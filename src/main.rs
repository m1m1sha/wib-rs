use once_cell::sync::Lazy;
use std::{ptr, sync::Mutex};
use windows::{
    core::PSTR,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetIpForwardTable, MIB_IPFORWARDTABLE, MIB_IPROUTE_TYPE_DIRECT,
        },
        Networking::WinSock::{
            bind, closesocket, setsockopt, WSACleanup, WSAGetLastError, WSAIoctl, WSARecv,
            WSASendTo, WSASocketA, WSAStartup, ADDRESS_FAMILY, AF_INET, FIONBIO, IPPROTO_IP,
            IPPROTO_UDP, IP_TTL, SOCKADDR, SOCKADDR_IN, SOCKET, SOL_SOCKET, SO_BROADCAST, WSABUF,
            WSADATA,
        },
    },
};

static WSA_VERSION: u16 = 0x0202; // 2.2
static LOOPBACK: u32 = 0x01_00_00_7F; // 127.0.0.1
static BROADCAST: u32 = 0xff_ff_ff_ff; // 255.255.255.255
static LISTEN_SOCKET: Lazy<Mutex<SOCKET>> = Lazy::new(|| Mutex::new(SOCKET::default()));
static FORWARD_TABLE: Lazy<Mutex<MIB_IPFORWARDTABLE>> =
    Lazy::new(|| Mutex::new(MIB_IPFORWARDTABLE::default()));

const DEFAULT_BUFFER_SIZE: usize = 4096;
const IP_HEADER_SIZE: usize = 20;
const IP_SRCADDR_POS: usize = 12;
const IP_DSTADDR_POS: usize = 16;
const IP_TTL_POS: usize = 8;

const UDP_HEADER_SIZE: usize = 8;
const UDP_CHECKSUM_POS: usize = 6;

fn main() -> Result<(), std::io::Error> {
    unsafe {
        let mut wsadata = WSADATA::default();
        if WSAStartup(WSA_VERSION, &mut wsadata) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WSAStartup failed",
            ));
        }
    }

    init_listen_socket()?;

    let mut buffer = [0u8; DEFAULT_BUFFER_SIZE];
    let mut src = 0;

    loop {
        let buffer_len = buffer.len().try_into().unwrap();
        let len = get_broadcast_packet(&mut buffer, buffer_len, &mut src)?;
        if buffer[IP_TTL_POS] <= 1 {
            continue;
        }

        let mut payload = [0u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE];
        payload[0..DEFAULT_BUFFER_SIZE].copy_from_slice(&buffer);

        println!("Received: {}", src);

        relay_broadcast(&mut payload, (len - IP_HEADER_SIZE as u32) as u16, src);
    }
}

fn init_listen_socket() -> Result<(), std::io::Error> {
    let socket = create_socket()?;
    *LISTEN_SOCKET.lock().unwrap() = socket;

    let mut addr = SOCKADDR_IN::default();
    addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
    addr.sin_port = 0;
    addr.sin_addr.S_un.S_addr = LOOPBACK; // INADDR_ANY
    let addr_ptr: *mut SOCKADDR = &mut addr as *mut SOCKADDR_IN as *mut SOCKADDR;
    let addr_len = std::mem::size_of_val(&addr) as i32;

    if unsafe { bind(socket, addr_ptr, addr_len) } == -1 {
        return handle_error("init bind failed");
    }

    Ok(())
}

fn create_socket() -> Result<SOCKET, std::io::Error> {
    unsafe {
        let socket = WSASocketA(AF_INET.0.into(), 3, IPPROTO_UDP.0, None, 0, 0)?;
        if socket.is_invalid() {
            closesocket(socket);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WSASocketA failed",
            ));
        }
        Ok(socket)
    }
}

fn handle_error(msg: &str) -> Result<(), std::io::Error> {
    let error = unsafe { WSAGetLastError() };
    unsafe { WSACleanup() };
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{} with error: {:?}", msg, error),
    ))
}

fn get_broadcast_packet(
    buffer: &mut [u8; DEFAULT_BUFFER_SIZE],
    size: u32,
    src: &mut u32,
) -> Result<u32, std::io::Error> {
    get_forward_table()?;

    let mut flags = 0;
    let mut len = 0;
    let wsa_buf = WSABUF {
        len: size,
        buf: PSTR::from_raw(buffer.as_mut_ptr()),
    };

    let socket = LISTEN_SOCKET.lock().unwrap().clone();

    unsafe {
        loop {
            if WSARecv(socket, &[wsa_buf], Some(&mut len), &mut flags, None, None) != 0 {
                handle_error("WSARecv failed")?;
            }

            if (len as usize) < IP_HEADER_SIZE + UDP_HEADER_SIZE
                || buffer[IP_DSTADDR_POS] as u32 != BROADCAST
            {
                continue;
            }

            *src = u32::from_ne_bytes([
                buffer[IP_SRCADDR_POS],
                buffer[IP_SRCADDR_POS + 1],
                buffer[IP_SRCADDR_POS + 2],
                buffer[IP_SRCADDR_POS + 3],
            ]);

            if find_addr_in_routes(*src) {
                continue;
            }

            break;
        }
    }
    Ok(len)
}

fn get_forward_table() -> Result<(), std::io::Error> {
    unsafe {
        let mut table_size: u32 = 0;

        // First call to get the required buffer size
        let result = GetIpForwardTable(None, &mut table_size, false);
        // todo!("ERROR_INSUFFICIENT_BUFFER");
        if result != ERROR_BUFFER_OVERFLOW.0 && result != ERROR_INSUFFICIENT_BUFFER.0 {
            return handle_error("GetIpForwardTable failed to get buffer size");
        }

        // Allocate the buffer with the required size
        let mut table_vec: Vec<u8> = vec![0; table_size as usize];

        // Second call to get the actual data
        let result = GetIpForwardTable(
            Some(&mut *(table_vec.as_mut_ptr() as *mut MIB_IPFORWARDTABLE)),
            &mut table_size,
            false,
        );
        if result != NO_ERROR.0 {
            return handle_error("GetIpForwardTable failed to get data");
        }

        *FORWARD_TABLE.lock().unwrap() = *(table_vec.as_ptr() as *const MIB_IPFORWARDTABLE);

        Ok(())
    }
}

fn find_addr_in_routes(src: u32) -> bool {
    let table = FORWARD_TABLE.lock().unwrap().clone();
    for i in 0..(table.dwNumEntries as usize) {
        let row = table.table[i];
        if row.dwForwardDest != BROADCAST
            || row.dwForwardMask != u32::MAX
            || unsafe { (row.Anonymous1.dwForwardType as i32) != MIB_IPROUTE_TYPE_DIRECT.0 }
        {
            continue;
        }

        return row.dwForwardNextHop == src;
    }
    false
}

fn relay_broadcast(payload: &mut [u8], size: u16, src: u32) {
    let table = FORWARD_TABLE.lock().unwrap().clone();
    for i in 0..(table.dwNumEntries as usize) {
        let row = table.table[i];
        if row.dwForwardDest != BROADCAST
            || row.dwForwardMask != u32::MAX
            || unsafe { (row.Anonymous1.dwForwardType as i32) != MIB_IPROUTE_TYPE_DIRECT.0 }
        {
            continue;
        }

        if row.dwForwardNextHop == LOOPBACK || row.dwForwardNextHop == src {
            continue;
        }

        if let Err(e) = send_broadcast(row.dwForwardNextHop, payload, size) {
            eprintln!("Failed to send broadcast: {:?}", e);
        }
    }
}

fn send_broadcast(src: u32, payload: &mut [u8], size: u16) -> Result<(), std::io::Error> {
    let socket = create_socket()?;

    // Set the socket to non-blocking mode
    unsafe {
        let mut len = 0u32;
        if WSAIoctl(
            socket,
            FIONBIO as u32,
            None,
            0,
            None,
            0,
            &mut len,
            None,
            None,
        ) != 0
        {
            return handle_error("WSAIoctl failed");
        }

        let mut addr = SOCKADDR_IN::default();
        addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
        addr.sin_port = 0;
        addr.sin_addr.S_un.S_addr = src;
        let addr_ptr: *mut SOCKADDR = &mut addr as *mut SOCKADDR_IN as *mut SOCKADDR;
        let addr_len = std::mem::size_of_val(&addr) as i32;

        if bind(socket, addr_ptr, addr_len) == -1 {
            return handle_error("send bind failed");
        }

        if setsockopt(socket, SOL_SOCKET, SO_BROADCAST, Some(&[true as u8])) == -1 {
            closesocket(socket);
            return handle_error("setsockopt(SO_BROADCAST) failed");
        }

        if setsockopt(socket, IPPROTO_IP.0, IP_TTL, Some(&[1])) == -1 {
            closesocket(socket);
            return handle_error("setsockopt(IP_TTL) failed");
        }

        let mut dst_addr = SOCKADDR_IN::default();
        dst_addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
        dst_addr.sin_port = 0;
        dst_addr.sin_addr.S_un.S_addr = BROADCAST;
        let dst_addr_ptr: *mut SOCKADDR = &mut dst_addr as *mut SOCKADDR_IN as *mut SOCKADDR;
        let dst_addr_len = std::mem::size_of_val(&dst_addr) as i32;

        compute_udp_checksum(payload, size, src, BROADCAST);

        let wsa_buf = WSABUF {
            len: size as u32,
            buf: PSTR::from_raw(payload.as_mut_ptr() as *mut u8),
        };

        if WSASendTo(
            socket,
            &[wsa_buf],
            Some(&mut len),
            0,
            Some(dst_addr_ptr),
            dst_addr_len,
            None,
            None,
        ) != 0
        {
            closesocket(socket);
            return handle_error("WSASendTo failed");
        }

        closesocket(socket);
    }

    Ok(())
}

fn compute_udp_checksum(payload: &mut [u8], size: u16, src: u32, dst: u32) {
    let mut buf = payload.as_ptr() as *const u16;
    let mut length = size;
    let src = src.to_be_bytes();
    let dst = dst.to_be_bytes();
    let mut checksum: u32 = 0;

    payload[UDP_CHECKSUM_POS] = 0;

    // Calculate the checksum
    while length > 1 {
        unsafe {
            checksum += ptr::read(buf) as u32;
            buf = buf.add(1);
        }
        if checksum & 0x80000000 != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }
        length -= 2;
    }

    if length & 1 != 0 {
        unsafe {
            checksum += *(buf as *const u8) as u32;
        }
    }

    checksum += u16::from_be_bytes([src[0], src[1]]) as u32;
    checksum += u16::from_be_bytes([src[2], src[3]]) as u32;
    checksum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    checksum += u16::from_be_bytes([dst[2], dst[3]]) as u32;

    checksum += (IPPROTO_UDP.0 as u32).to_be();
    checksum += (size as u32).to_be();

    while checksum >> 16 != 0 {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    let checksum = checksum.to_be_bytes();
    payload[UDP_CHECKSUM_POS] = checksum[0];
    payload[UDP_CHECKSUM_POS + 1] = checksum[1];
    payload[UDP_CHECKSUM_POS + 2] = checksum[2];
    payload[UDP_CHECKSUM_POS + 3] = checksum[3];
}
