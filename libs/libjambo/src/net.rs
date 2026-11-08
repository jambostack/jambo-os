//! Primitives de communication réseau et interface de sockets POSIX standard (`libjambo::net`)
//!
//! Fournit les structures, constantes et utilitaires conformes POSIX.1-2008 / RFC 793 / RFC 768
//! pour la gestion des sockets réseau en espace utilisateur (`#![no_std]`, zéro allocation) :
//! 1. Constantes de familles d'adresses (`AF_INET`, `AF_INET6`, `AF_UNSPEC`).
//! 2. Types de sockets (`SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_RAW`).
//! 3. Protocoles de transport (`IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_ICMP`).
//! 4. Structures standard C-ABI (`struct in_addr`, `struct sockaddr`, `struct sockaddr_in`).
//! 5. Conversions d'ordre d'octets réseau (`htons`, `ntohs`, `htonl`, `ntohl`).
//! 6. Routines de conversion et analyse d'adresses IPv4 (`inet_addr`, `inet_ntoa`).

use jambo_abi::SysError;

// ============================================================================
// CONSTANTES POSIX STANDARD POUR SOCKETS
// ============================================================================

// Familles d'adresses (Address Families)
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_LOCAL: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// Types de sockets
pub const SOCK_STREAM: i32 = 1; // Flux fiable ordonné bidirectionnel (TCP)
pub const SOCK_DGRAM: i32 = 2; // Datagrammes non fiables sans connexion (UDP)
pub const SOCK_RAW: i32 = 3; // Accès brut direct aux protocoles IP
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

// Protocoles de transport IP
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_RAW: i32 = 255;

// Niveaux et options de socket
pub const SOL_SOCKET: i32 = 1;
pub const SO_DEBUG: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_DONTROUTE: i32 = 5;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_RCVTIMEO: i32 = 20;
pub const SO_SNDTIMEO: i32 = 21;

// Drapeaux de fermeture (shutdown)
pub const SHUT_RD: i32 = 0; // Arrêt des réceptions
pub const SHUT_WR: i32 = 1; // Arrêt des émissions
pub const SHUT_RDWR: i32 = 2; // Arrêt complet émissions et réceptions

// Adresses IPv4 spéciales (ordre machine)
pub const INADDR_ANY: u32 = 0x0000_0000;
pub const INADDR_BROADCAST: u32 = 0xFFFF_FFFF;
pub const INADDR_LOOPBACK: u32 = 0x7F00_0001; // 127.0.0.1

// ============================================================================
// CONVERSIONS D'ORDRE D'OCTETS (NETWORK BYTE ORDER - BIG ENDIAN)
// ============================================================================

/// Convertit un entier 16 bits de l'ordre hôte vers l'ordre réseau (Big-Endian).
#[inline(always)]
pub const fn htons(host: u16) -> u16 {
    host.to_be()
}

/// Convertit un entier 16 bits de l'ordre réseau (Big-Endian) vers l'ordre hôte.
#[inline(always)]
pub const fn ntohs(net: u16) -> u16 {
    u16::from_be(net)
}

/// Convertit un entier 32 bits de l'ordre hôte vers l'ordre réseau (Big-Endian).
#[inline(always)]
pub const fn htonl(host: u32) -> u32 {
    host.to_be()
}

/// Convertit un entier 32 bits de l'ordre réseau (Big-Endian) vers l'ordre hôte.
#[inline(always)]
pub const fn ntohl(net: u32) -> u32 {
    u32::from_be(net)
}

// ============================================================================
// STRUCTURES C-ABI STANDARD
// ============================================================================

/// Structure d'adresse IPv4 conforme POSIX `struct in_addr` (4 octets).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InAddr {
    /// Adresse IPv4 en ordre réseau (big-endian)
    pub s_addr: u32,
}

const _: () = assert!(core::mem::size_of::<InAddr>() == 4);

impl InAddr {
    /// Construit une adresse `INADDR_ANY` (0.0.0.0).
    pub const fn any() -> Self {
        Self { s_addr: 0 }
    }

    /// Construit une adresse `INADDR_BROADCAST` (255.255.255.255).
    pub const fn broadcast() -> Self {
        Self {
            s_addr: 0xFFFF_FFFF,
        }
    }

    /// Construit l'adresse locale de boucle `INADDR_LOOPBACK` (127.0.0.1).
    pub const fn loopback() -> Self {
        Self {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]),
        }
    }

    /// Construit une adresse à partir d'un quadruplet d'octets [a, b, c, d].
    pub const fn from_octets(octets: [u8; 4]) -> Self {
        Self {
            s_addr: u32::from_be_bytes(octets),
        }
    }

    /// Extrait les 4 octets individuels de l'adresse IPv4.
    pub const fn octets(&self) -> [u8; 4] {
        self.s_addr.to_be_bytes()
    }

    /// Indique si l'adresse est l'adresse de bouclage locale (127.0.0.0/8).
    pub const fn is_loopback(&self) -> bool {
        self.octets()[0] == 127
    }

    /// Indique si l'adresse est non spécifiée (0.0.0.0).
    pub const fn is_unspecified(&self) -> bool {
        self.s_addr == 0
    }
}

/// Structure d'adresse de socket générique conforme POSIX `struct sockaddr` (16 octets).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

const _: () = assert!(core::mem::size_of::<SockAddr>() == 16);

impl Default for SockAddr {
    fn default() -> Self {
        Self {
            sa_family: AF_UNSPEC,
            sa_data: [0u8; 14],
        }
    }
}

/// Structure d'adresse de socket IPv4 conforme POSIX `struct sockaddr_in` (16 octets).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16, // Port en ordre réseau (big-endian)
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<SockAddrIn>() == 16);

impl Default for SockAddrIn {
    fn default() -> Self {
        Self {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: InAddr::any(),
            sin_zero: [0u8; 8],
        }
    }
}

impl SockAddrIn {
    /// Initialise une nouvelle adresse de socket IPv4 avec son port hôte et ses octets d'IP.
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: AF_INET,
            sin_port: htons(port),
            sin_addr: InAddr::from_octets(ip),
            sin_zero: [0u8; 8],
        }
    }

    /// Retourne le numéro de port en ordre hôte processeur.
    #[inline]
    pub const fn port(&self) -> u16 {
        ntohs(self.sin_port)
    }

    /// Retourne le quadruplet d'octets IPv4.
    #[inline]
    pub const fn ip_octets(&self) -> [u8; 4] {
        self.sin_addr.octets()
    }

    /// Convertit vers la structure d'adresse générique `SockAddr`.
    pub fn to_sockaddr(&self) -> SockAddr {
        let mut sa = SockAddr {
            sa_family: self.sin_family,
            sa_data: [0u8; 14],
        };
        unsafe {
            let src = (self as *const Self as *const u8).add(2); // Saute sin_family
            let dst = sa.sa_data.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src, dst, 14);
        }
        sa
    }

    /// Tente de reconstruire un `SockAddrIn` depuis un `SockAddr` générique.
    pub fn from_sockaddr(sa: &SockAddr) -> Result<Self, SysError> {
        if sa.sa_family != AF_INET {
            return Err(SysError::NotSupported);
        }
        let mut sin = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                sa as *const SockAddr as *const u8,
                &mut sin as *mut Self as *mut u8,
                16,
            );
        }
        Ok(sin)
    }
}

// ============================================================================
// ROUTINES D'ANALYSE ET FORMATAGE D'ADRESSES IPV4
// ============================================================================

/// Analyse une chaîne de caractères au format "a.b.c.d" et retourne le quadruplet d'octets.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut current_val: u16 = 0;
    let mut has_digit = false;

    for b in s.bytes() {
        if b == b'.' {
            if !has_digit || octet_idx >= 3 || current_val > 255 {
                return None;
            }
            octets[octet_idx] = current_val as u8;
            octet_idx += 1;
            current_val = 0;
            has_digit = false;
        } else if b.is_ascii_digit() {
            has_digit = true;
            current_val = current_val * 10 + (b - b'0') as u16;
            if current_val > 255 {
                return None;
            }
        } else {
            return None;
        }
    }

    if !has_digit || octet_idx != 3 || current_val > 255 {
        return None;
    }
    octets[3] = current_val as u8;
    Some(octets)
}

/// Formate un quadruplet IPv4 dans un tampon d'octets et retourne la longueur écrite.
pub fn format_ipv4(ip: &[u8; 4], buf: &mut [u8]) -> Option<usize> {
    if buf.len() < 16 {
        return None;
    }
    let mut cursor = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            buf[cursor] = b'.';
            cursor += 1;
        }
        if octet >= 100 {
            buf[cursor] = b'0' + (octet / 100);
            cursor += 1;
            buf[cursor] = b'0' + ((octet / 10) % 10);
            cursor += 1;
            buf[cursor] = b'0' + (octet % 10);
            cursor += 1;
        } else if octet >= 10 {
            buf[cursor] = b'0' + (octet / 10);
            cursor += 1;
            buf[cursor] = b'0' + (octet % 10);
            cursor += 1;
        } else {
            buf[cursor] = b'0' + octet;
            cursor += 1;
        }
    }
    Some(cursor)
}

// ============================================================================
// ÉTATS DE SOCKET & PROTOCOLE IPC INTERNE
// ============================================================================

/// État du cycle de vie d'une socket réseau
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketLifecycle {
    Closed,
    Created {
        domain: u16,
        type_: i32,
        protocol: i32,
    },
    Bound {
        port: u16,
        ip: [u8; 4],
    },
    Listening {
        port: u16,
        backlog: u32,
    },
    Connected {
        local_port: u16,
        remote_port: u16,
        remote_ip: [u8; 4],
    },
}

/// Opcodes du protocole IPC de socket Ring 3
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOpcode {
    Create = 1,
    Bind = 2,
    Connect = 3,
    Listen = 4,
    Accept = 5,
    Send = 6,
    Recv = 7,
    Close = 8,
    GetSockOpt = 9,
    SetSockOpt = 10,
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_byte_order_conversions() {
        assert_eq!(htons(0x1234).to_ne_bytes(), [0x12, 0x34]);
        assert_eq!(ntohs(htons(0x8080)), 0x8080);
        assert_eq!(htonl(0x11223344).to_ne_bytes(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(ntohl(htonl(0xDEADBEEF)), 0xDEADBEEF);
    }

    #[test]
    fn test_in_addr_and_sockaddr_in_layouts() {
        let loopback = InAddr::loopback();
        assert_eq!(loopback.octets(), [127, 0, 0, 1]);
        assert!(loopback.is_loopback());
        assert!(!loopback.is_unspecified());

        let any = InAddr::any();
        assert_eq!(any.octets(), [0, 0, 0, 0]);
        assert!(any.is_unspecified());

        let sin = SockAddrIn::new([192, 168, 1, 100], 8080);
        assert_eq!(sin.sin_family, AF_INET);
        assert_eq!(sin.port(), 8080);
        assert_eq!(sin.ip_octets(), [192, 168, 1, 100]);
        assert_eq!(core::mem::size_of::<SockAddrIn>(), 16);
    }

    #[test]
    fn test_sockaddr_conversion_roundtrip() {
        let sin = SockAddrIn::new([10, 0, 2, 15], 443);
        let sa = sin.to_sockaddr();
        assert_eq!(sa.sa_family, AF_INET);

        let sin_parsed = SockAddrIn::from_sockaddr(&sa).expect("Doit être parsé avec succès");
        assert_eq!(sin_parsed.sin_family, AF_INET);
        assert_eq!(sin_parsed.port(), 443);
        assert_eq!(sin_parsed.ip_octets(), [10, 0, 2, 15]);
    }

    #[test]
    fn test_ipv4_parsing_and_formatting() {
        assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4("127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("10.0.2"), None);
        assert_eq!(parse_ipv4("10.0.2.15.1"), None);
        assert_eq!(parse_ipv4("abc"), None);

        let mut buf = [0u8; 32];
        let len = format_ipv4(&[192, 168, 0, 1], &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..len]).unwrap(), "192.168.0.1");
    }

    #[test]
    fn test_socket_constants() {
        assert_eq!(AF_INET, 2);
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(IPPROTO_TCP, 6);
        assert_eq!(IPPROTO_UDP, 17);
        assert_eq!(SHUT_RDWR, 2);
    }
}
