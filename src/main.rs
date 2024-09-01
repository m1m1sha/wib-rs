use once_cell::sync::Lazy;
use std::sync::Mutex;
use windows::{
    core::PSTR,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
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
        println!("WSAStartup succeeded");
    }

    init_listen_socket()?;

    loop {
        let (buffer, len, src) = get_broadcast_packet()?;
        if buffer[len as usize] <= 1 {
            continue;
        }

        let mut payload = [0u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE];
        payload[0..DEFAULT_BUFFER_SIZE].copy_from_slice(&buffer);

        relay_broadcast(payload, (len - IP_HEADER_SIZE as u32) as u16, src);
    }
}

fn init_listen_socket() -> Result<(), std::io::Error> {
    unsafe {
        if let Ok(socket) = WSASocketA(AF_INET.0.into(), 3, IPPROTO_UDP.0, None, 0, 0) {
            *LISTEN_SOCKET.lock().unwrap() = socket;
            println!("WSASocketA succeeded");
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WSASocketA failed",
            ));
        }

        let mut addr = SOCKADDR_IN::default();
        addr.sin_family = ADDRESS_FAMILY(AF_INET.0);
        addr.sin_port = 0;
        addr.sin_addr.S_un.S_addr = LOOPBACK;
        let addr_ptr: *mut SOCKADDR = &mut addr as *mut SOCKADDR_IN as *mut SOCKADDR;
        let addr_len = std::mem::size_of_val(&addr) as i32;
        let socket = LISTEN_SOCKET.lock().unwrap().clone();

        if bind(socket, addr_ptr, addr_len) == -1 {
            let error = WSAGetLastError();
            WSACleanup();
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("bind failed with error: {:?}", error),
            ));
        }

        Ok(())
    }
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
                let error = WSAGetLastError();
                WSACleanup();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("WSARecv failed with error: {:?}", error),
                ));
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

        loop {
            let result = GetIpForwardTable(
                Some(&mut *FORWARD_TABLE.lock().unwrap()),
                &mut table_size,
                false,
            );
            if result == NO_ERROR.0 {
                break;
            } else if result == ERROR_BUFFER_OVERFLOW.0 {
                let mut table_vec: Vec<u8> = Vec::with_capacity(table_size as usize);
                *FORWARD_TABLE.lock().unwrap() =
                    *(table_vec.as_mut_ptr() as *mut MIB_IPFORWARDTABLE);

                table_vec.set_len(table_size as usize / std::mem::size_of::<MIB_IPFORWARDTABLE>());
            } else {
                WSACleanup();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("GetIpForwardTable failed with code: {:?}", result),
                ));
            }
        }

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
    return false;
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

        send_broadcast(src, payload, size);
    }
}

fn send_broadcast(
    src: u32,
    payload: [u8; DEFAULT_BUFFER_SIZE + IP_HEADER_SIZE],
    size: u16,
) -> Result<(), std::io::Error> {
    // todo!();

    unsafe {
        println!("send broadcast");

        let socket = if let Ok(socket) = WSASocketA(AF_INET.0.into(), 3, IPPROTO_UDP.0, None, 0, 0)
        {
            if socket.is_invalid() {
                closesocket(socket);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "WSASocketA failed",
                ));
            }
            socket
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WSASocketA failed",
            ));
        };

        let mut len = 0u32;
        // WSAIoctl(socket, FIONBIO, None, 0, None, 0, &mut len, None, None);
        todo!("relay");
        Ok(())
    }
}
