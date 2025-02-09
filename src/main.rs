use once_cell::sync::Lazy;
use std::sync::Mutex;
use windows::{
    core::PSTR,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetIpForwardTable, MIB_IPFORWARDTABLE, MIB_IPROUTE_TYPE_DIRECT,
        },
        Networking::WinSock::{
            bind, closesocket, WSACleanup, WSAGetLastError, WSAIoctl, WSARecv, WSASocketA,
            WSAStartup, ADDRESS_FAMILY, AF_INET, FIONBIO, IPPROTO_UDP, SOCKADDR, SOCKADDR_IN,
            SOCKET, WSABUF, WSADATA,
        },
    },
};

static WSA_VERSION: u16 = 0x0202; // 2.2
static LOOPBACK: u32 = 0x7f_00_00_01; // 127.0.0.1
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

    loop {
        let (buffer, len, src) = get_broadcast_packet()?;
        if buffer[len as usize] <= 1 {
            continue;
        }

        let mut payload = [0u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE];
        payload[0..DEFAULT_BUFFER_SIZE].copy_from_slice(&buffer);
        println!("Received packet from: {}", src);
        relay_broadcast(payload, (len - IP_HEADER_SIZE as u32) as u16, src);
    }
}

fn init_listen_socket() -> Result<(), std::io::Error> {
    let socket = create_socket()?;
    *LISTEN_SOCKET.lock().unwrap() = socket;

    let mut addr = SOCKADDR_IN::default();
    addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
    addr.sin_port = 0;
    addr.sin_addr.S_un.S_addr = 0; // INADDR_ANY
    let addr_ptr: *mut SOCKADDR = &mut addr as *mut SOCKADDR_IN as *mut SOCKADDR;
    let addr_len = std::mem::size_of_val(&addr) as i32;

    if unsafe { bind(socket, addr_ptr, addr_len) } == -1 {
        return handle_error("bind failed");
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

fn get_broadcast_packet() -> Result<([u8; DEFAULT_BUFFER_SIZE], u32, u32), std::io::Error> {
    get_forward_table()?;
    let mut flags = 0;
    let mut len = 0;
    let mut buffer = [0u8; DEFAULT_BUFFER_SIZE];
    let wsa_buf = WSABUF {
        len: DEFAULT_BUFFER_SIZE as u32,
        buf: PSTR::from_raw(buffer.as_mut_ptr()),
    };

    let socket = LISTEN_SOCKET.lock().unwrap().clone();

    let mut src;

    unsafe {
        loop {
            if WSARecv(socket, &[wsa_buf], Some(&mut len), &mut flags, None, None) != 0 {
                if let Err(e) = handle_error("WSARecv failed") {
                    return Err(e);
                }
            }

            if (len as usize) < IP_HEADER_SIZE + UDP_HEADER_SIZE
                || buffer[IP_DSTADDR_POS] as u32 != BROADCAST
            {
                continue;
            }

            src = buffer[IP_SRCADDR_POS] as u32;
            if find_addr_in_routes(src) {
                continue;
            }

            break;
        }
    }
    Ok((buffer, len, src))
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

fn relay_broadcast(payload: [u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE], size: u16, src: u32) {
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

        if let Err(e) = send_broadcast(src, payload, size) {
            eprintln!("Failed to send broadcast: {:?}", e);
        }
    }
}

fn send_broadcast(
    src: u32,
    payload: [u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE],
    size: u16,
) -> Result<(), std::io::Error> {
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
    }

    let mut addr = SOCKADDR_IN::default();
    addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
    addr.sin_port = 0;
    addr.sin_addr.S_un.S_addr = src;
    let addr_ptr: *mut SOCKADDR = &mut addr as *mut SOCKADDR_IN as *mut SOCKADDR;
    let addr_len = std::mem::size_of_val(&addr) as i32;

    let wsa_buf = WSABUF {
        len: size as u32,
        buf: PSTR::from_raw(payload.as_ptr() as *mut u8),
    };

    unsafe {
        if WSARecv(socket, &[wsa_buf], Some(&mut 0u32), &mut 0, None, None) != 0 {
            return handle_error("WSARecv failed");
        }
    }

    Ok(())
}
