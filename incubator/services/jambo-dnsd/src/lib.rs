//! Serveur et Résolveur DNS d'Autorité de Grappe (`jambo-dnsd`)
//!
//! Fournit la résolution de noms de domaine pour la grappe souveraine JamboOS (`.jambo`),
//! la gestion d'enregistrements DNS (A, AAAA, SRV, CNAME, TXT, PTR), l'encodage/décodage
//! de trames réseau wire-format RFC 1035, un cache DNS avec TTL, et la synchronisation
//! bidirectionnelle avec le registre de découverte de services `jambo-serviced`.
//! L'accès et les mutations sont strictement confinés par la capacité `DnsCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_DNS_RECORDS: usize = 64;
pub const MAX_CACHE_ENTRIES: usize = 32;
pub const MAX_DOMAIN_LEN: usize = 64;
pub const MAX_TXT_LEN: usize = 64;
pub const MAX_WIRE_PACKET_LEN: usize = 512;
pub const DEFAULT_CLUSTER_ZONE: &[u8] = b"jambo";
pub const DEFAULT_TTL: u32 = 300;

/// Droits de capacité pour le sous-système DNS.
pub mod dns_rights {
    pub const DNS_RESOLVE: u32 = 0x01;
    pub const DNS_REGISTER: u32 = 0x02;
    pub const DNS_ZONE_UPDATE: u32 = 0x04;
    pub const DNS_RECURSE: u32 = 0x08;
    pub const DNS_ADMIN: u32 = 0x80;
    pub const ALL: u32 = DNS_RESOLVE | DNS_REGISTER | DNS_ZONE_UPDATE | DNS_RECURSE | DNS_ADMIN;
}

/// Jeton de capacité pour le résolveur et serveur DNS de grappe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DnsCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

/// Types d'enregistrements DNS selon RFC 1035 et RFC 3596.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    TXT,
    AAAA,
    SRV,
    ANY,
    Unknown(u16),
}

impl DnsType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            12 => DnsType::PTR,
            16 => DnsType::TXT,
            28 => DnsType::AAAA,
            33 => DnsType::SRV,
            255 => DnsType::ANY,
            other => DnsType::Unknown(other),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            DnsType::A => 1,
            DnsType::NS => 2,
            DnsType::CNAME => 5,
            DnsType::SOA => 6,
            DnsType::PTR => 12,
            DnsType::TXT => 16,
            DnsType::AAAA => 28,
            DnsType::SRV => 33,
            DnsType::ANY => 255,
            DnsType::Unknown(val) => *val,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::NS => "NS",
            DnsType::CNAME => "CNAME",
            DnsType::SOA => "SOA",
            DnsType::PTR => "PTR",
            DnsType::TXT => "TXT",
            DnsType::AAAA => "AAAA",
            DnsType::SRV => "SRV",
            DnsType::ANY => "ANY",
            DnsType::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Codes de réponse DNS (RCODE RFC 1035).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl DnsRcode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormErr,
            2 => DnsRcode::ServFail,
            3 => DnsRcode::NXDomain,
            4 => DnsRcode::NotImp,
            _ => DnsRcode::Refused,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Données associées aux enregistrements DNS supportés.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordData {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME {
        target: [u8; MAX_DOMAIN_LEN],
        target_len: usize,
    },
    PTR {
        target: [u8; MAX_DOMAIN_LEN],
        target_len: usize,
    },
    TXT {
        text: [u8; MAX_TXT_LEN],
        text_len: usize,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: [u8; MAX_DOMAIN_LEN],
        target_len: usize,
    },
    SOA {
        mname: [u8; MAX_DOMAIN_LEN],
        mname_len: usize,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
}

/// Enregistrement DNS stocké dans une zone ou en cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: [u8; MAX_DOMAIN_LEN],
    pub name_len: usize,
    pub rtype: DnsType,
    pub ttl: u32,
    pub created_at: u64,
    pub data: DnsRecordData,
    pub allocated: bool,
}

impl DnsRecord {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_DOMAIN_LEN],
            name_len: 0,
            rtype: DnsType::A,
            ttl: DEFAULT_TTL,
            created_at: 0,
            data: DnsRecordData::A([0, 0, 0, 0]),
            allocated: false,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn is_valid(&self, now: u64) -> bool {
        self.allocated && now <= self.created_at.saturating_add(self.ttl as u64)
    }
}

/// Comparaison ASCII insensible à la casse.
pub fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

/// Normalise un nom de domaine en supprimant un point final éventuel.
pub fn normalize_domain(domain: &[u8]) -> &[u8] {
    if domain.ends_with(b".") && domain.len() > 1 {
        &domain[..domain.len() - 1]
    } else {
        domain
    }
}

/// Zone DNS d'autorité pour la grappe souveraine (ex: `.jambo`).
pub struct DnsZone {
    pub origin: [u8; 32],
    pub origin_len: usize,
    pub records: [DnsRecord; MAX_DNS_RECORDS],
    pub serial: u32,
}

impl DnsZone {
    pub fn new(origin_str: &str) -> Self {
        let mut origin = [0u8; 32];
        let bytes = origin_str.as_bytes();
        let len = bytes.len().min(32);
        origin[..len].copy_from_slice(&bytes[..len]);
        Self {
            origin,
            origin_len: len,
            records: [DnsRecord::empty(); MAX_DNS_RECORDS],
            serial: 1,
        }
    }

    pub fn origin_str(&self) -> &str {
        core::str::from_utf8(&self.origin[..self.origin_len]).unwrap_or("jambo")
    }

    /// Détermine si la zone fait autorité pour le nom demandé.
    pub fn is_authoritative_for(&self, domain: &str) -> bool {
        let norm = normalize_domain(domain.as_bytes());
        let orig = &self.origin[..self.origin_len];
        if ascii_eq_ignore_case(norm, orig) {
            return true;
        }
        if norm.len() > orig.len() + 1 {
            let suffix_start = norm.len() - orig.len();
            if norm[suffix_start - 1] == b'.' {
                return ascii_eq_ignore_case(&norm[suffix_start..], orig);
            }
        }
        false
    }

    /// Ajoute ou met à jour un enregistrement dans la zone d'autorité.
    pub fn add_record(
        &mut self,
        name: &str,
        rtype: DnsType,
        ttl: u32,
        data: DnsRecordData,
        now: u64,
    ) -> Result<(), SysError> {
        let name_bytes = normalize_domain(name.as_bytes());
        if name_bytes.is_empty() || name_bytes.len() > MAX_DOMAIN_LEN {
            return Err(SysError::InvalidArgument);
        }

        // 1. Mise à jour d'un enregistrement existant identique (même nom + même type)
        for rec in self.records.iter_mut() {
            if rec.allocated
                && rec.rtype == rtype
                && ascii_eq_ignore_case(&rec.name[..rec.name_len], name_bytes)
            {
                rec.ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
                rec.created_at = now;
                rec.data = data;
                self.serial = self.serial.wrapping_add(1);
                return Ok(());
            }
        }

        // 2. Allocation d'un nouvel emplacement
        for rec in self.records.iter_mut() {
            if !rec.allocated {
                rec.name[..name_bytes.len()].copy_from_slice(name_bytes);
                rec.name_len = name_bytes.len();
                rec.rtype = rtype;
                rec.ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
                rec.created_at = now;
                rec.data = data;
                rec.allocated = true;
                self.serial = self.serial.wrapping_add(1);
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Supprime un enregistrement par nom et type.
    pub fn remove_record(&mut self, name: &str, rtype: DnsType) -> bool {
        let name_bytes = normalize_domain(name.as_bytes());
        for rec in self.records.iter_mut() {
            if rec.allocated
                && rec.rtype == rtype
                && ascii_eq_ignore_case(&rec.name[..rec.name_len], name_bytes)
            {
                *rec = DnsRecord::empty();
                self.serial = self.serial.wrapping_add(1);
                return true;
            }
        }
        false
    }

    /// Recherche les enregistrements correspondant à un nom et type.
    pub fn find_records(
        &self,
        name: &str,
        rtype: DnsType,
        now: u64,
        out: &mut [DnsRecord; 8],
    ) -> usize {
        let name_bytes = normalize_domain(name.as_bytes());
        let mut count = 0;
        for rec in self.records.iter() {
            if rec.is_valid(now) && ascii_eq_ignore_case(&rec.name[..rec.name_len], name_bytes) {
                if rtype == DnsType::ANY || rec.rtype == rtype || rec.rtype == DnsType::CNAME {
                    if count < out.len() {
                        out[count] = *rec;
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Nombre total d'enregistrements alloués.
    pub fn active_records_count(&self) -> usize {
        self.records.iter().filter(|r| r.allocated).count()
    }
}

/// Cache DNS local avec expiration par TTL.
pub struct DnsCache {
    pub entries: [DnsRecord; MAX_CACHE_ENTRIES],
}

impl DnsCache {
    pub const fn new() -> Self {
        Self {
            entries: [DnsRecord::empty(); MAX_CACHE_ENTRIES],
        }
    }

    pub fn insert(&mut self, record: DnsRecord) {
        // Remplacement si existant
        for ent in self.entries.iter_mut() {
            if ent.allocated
                && ent.rtype == record.rtype
                && ascii_eq_ignore_case(&ent.name[..ent.name_len], &record.name[..record.name_len])
            {
                *ent = record;
                return;
            }
        }
        // Premier emplacement libre
        for ent in self.entries.iter_mut() {
            if !ent.allocated {
                *ent = record;
                return;
            }
        }
        // Sinon éviction FIFO / première entrée
        self.entries[0] = record;
    }

    pub fn lookup(&self, name: &str, rtype: DnsType, now: u64) -> Option<DnsRecordData> {
        let name_bytes = normalize_domain(name.as_bytes());
        for ent in self.entries.iter() {
            if ent.is_valid(now)
                && (ent.rtype == rtype || rtype == DnsType::ANY)
                && ascii_eq_ignore_case(&ent.name[..ent.name_len], name_bytes)
            {
                return Some(ent.data);
            }
        }
        None
    }

    pub fn evict_expired(&mut self, now: u64) -> usize {
        let mut evicted = 0;
        for ent in self.entries.iter_mut() {
            if ent.allocated && !ent.is_valid(now) {
                *ent = DnsRecord::empty();
                evicted += 1;
            }
        }
        evicted
    }
}

/// Question DNS extraite d'une trame wire-format RFC 1035.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedQuestion {
    pub qname: [u8; MAX_DOMAIN_LEN],
    pub qname_len: usize,
    pub qtype: DnsType,
    pub qclass: u16,
    pub wire_len: usize,
}

impl ParsedQuestion {
    pub const fn empty() -> Self {
        Self {
            qname: [0u8; MAX_DOMAIN_LEN],
            qname_len: 0,
            qtype: DnsType::A,
            qclass: 1,
            wire_len: 0,
        }
    }

    pub fn qname_str(&self) -> &str {
        core::str::from_utf8(&self.qname[..self.qname_len]).unwrap_or("")
    }
}

/// Requête DNS analysée depuis une trame RFC 1035.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedWireQuery {
    pub id: u16,
    pub flags: u16,
    pub rd: bool,
    pub question: ParsedQuestion,
}

/// Analyse une trame binaire RFC 1035 wire-format.
pub fn parse_wire_query(buf: &[u8]) -> Result<ParsedWireQuery, SysError> {
    if buf.len() < 12 {
        return Err(SysError::InvalidArgument);
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    // QR doit être 0 (query), QDCOUNT >= 1
    let is_query = (flags & 0x8000) == 0;
    if !is_query || qdcount == 0 {
        return Err(SysError::InvalidArgument);
    }
    let rd = (flags & 0x0100) != 0;

    let mut pos = 12;
    let mut qname = [0u8; MAX_DOMAIN_LEN];
    let mut qname_len = 0;
    let mut jumped = false;
    let mut jump_offset = 0;
    let mut jumps_count = 0;
    let mut bytes_consumed = 0;

    while pos < buf.len() {
        let len = buf[pos];
        if len == 0 {
            if !jumped {
                bytes_consumed += 1;
            }
            break;
        }

        // Pointeur de compression DNS (0xC0XX)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(SysError::InvalidArgument);
            }
            let offset = (((len & 0x3F) as usize) << 8) | (buf[pos + 1] as usize);
            if offset >= buf.len() || jumps_count > 5 {
                return Err(SysError::InvalidArgument);
            }
            if !jumped {
                jump_offset = pos + 2;
                jumped = true;
            }
            pos = offset;
            jumps_count += 1;
            continue;
        }

        // Label normal
        let label_len = len as usize;
        pos += 1;
        if !jumped {
            bytes_consumed += 1;
        }
        if pos + label_len > buf.len() {
            return Err(SysError::InvalidArgument);
        }

        if qname_len > 0 && qname_len < MAX_DOMAIN_LEN {
            qname[qname_len] = b'.';
            qname_len += 1;
        }

        let copy_len = label_len.min(MAX_DOMAIN_LEN.saturating_sub(qname_len));
        qname[qname_len..qname_len + copy_len].copy_from_slice(&buf[pos..pos + copy_len]);
        qname_len += copy_len;

        pos += label_len;
        if !jumped {
            bytes_consumed += label_len;
        }
    }

    let wire_qname_len = if jumped {
        jump_offset - 12
    } else {
        bytes_consumed
    };
    let question_end = 12 + wire_qname_len + 4;
    if question_end > buf.len() {
        return Err(SysError::InvalidArgument);
    }

    let qtype_raw = u16::from_be_bytes([buf[12 + wire_qname_len], buf[12 + wire_qname_len + 1]]);
    let qclass = u16::from_be_bytes([buf[12 + wire_qname_len + 2], buf[12 + wire_qname_len + 3]]);

    Ok(ParsedWireQuery {
        id,
        flags,
        rd,
        question: ParsedQuestion {
            qname,
            qname_len,
            qtype: DnsType::from_u16(qtype_raw),
            qclass,
            wire_len: wire_qname_len + 4,
        },
    })
}

/// Encode un nom de domaine en format labels wire RFC 1035 (ex: "api.jambo" -> "\x03api\x05jambo\x00").
pub fn encode_domain_labels(domain: &[u8], out: &mut [u8]) -> Result<usize, SysError> {
    let norm = normalize_domain(domain);
    let mut out_pos = 0;
    let mut start = 0;

    for i in 0..=norm.len() {
        if i == norm.len() || norm[i] == b'.' {
            let label_len = i - start;
            if label_len > 63 || out_pos + 1 + label_len >= out.len() {
                return Err(SysError::InvalidArgument);
            }
            out[out_pos] = label_len as u8;
            out_pos += 1;
            out[out_pos..out_pos + label_len].copy_from_slice(&norm[start..i]);
            out_pos += label_len;
            start = i + 1;
        }
    }

    if out_pos >= out.len() {
        return Err(SysError::OutOfMemory);
    }
    out[out_pos] = 0; // Terminateur de labels
    out_pos += 1;
    Ok(out_pos)
}

/// Construit une réponse binaire RFC 1035 wire-format.
pub fn build_wire_response(
    query: &ParsedWireQuery,
    query_raw: &[u8],
    answers: &[DnsRecord],
    is_authoritative: bool,
    rcode: DnsRcode,
    out: &mut [u8],
) -> Result<usize, SysError> {
    if out.len() < 12 + query.question.wire_len {
        return Err(SysError::OutOfMemory);
    }

    // 1. En-tête DNS (12 octets)
    out[0..2].copy_from_slice(&query.id.to_be_bytes());

    let mut flags: u16 = 0x8000; // QR = 1 (réponse)
    if is_authoritative {
        flags |= 0x0400; // AA = 1
    }
    if query.rd {
        flags |= 0x0100; // RD = 1
    }
    flags |= 0x0080; // RA = 1 (Recursion Available)
    flags |= (rcode.as_u8() as u16) & 0x000F; // RCODE
    out[2..4].copy_from_slice(&flags.to_be_bytes());

    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // 2. Section Question (recopie textuelle depuis la requête brute)
    let q_len = query.question.wire_len;
    if 12 + q_len > query_raw.len() || 12 + q_len > out.len() {
        return Err(SysError::InvalidArgument);
    }
    out[12..12 + q_len].copy_from_slice(&query_raw[12..12 + q_len]);
    let mut pos = 12 + q_len;

    // 3. Section Réponses (Answers)
    for ans in answers {
        // Compression de nom : pointeur 0xC00C vers le QNAME de la question
        if pos + 12 > out.len() {
            return Err(SysError::OutOfMemory);
        }
        out[pos] = 0xC0;
        out[pos + 1] = 0x0C;
        pos += 2;

        // TYPE
        out[pos..pos + 2].copy_from_slice(&ans.rtype.as_u16().to_be_bytes());
        pos += 2;

        // CLASS = IN (1)
        out[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
        pos += 2;

        // TTL
        out[pos..pos + 4].copy_from_slice(&ans.ttl.to_be_bytes());
        pos += 4;

        // Réserve 2 octets pour RDLENGTH
        let rdlength_pos = pos;
        pos += 2;

        // RDATA
        let rdata_start = pos;
        match ans.data {
            DnsRecordData::A(ip) => {
                if pos + 4 > out.len() {
                    return Err(SysError::OutOfMemory);
                }
                out[pos..pos + 4].copy_from_slice(&ip);
                pos += 4;
            }
            DnsRecordData::AAAA(ip6) => {
                if pos + 16 > out.len() {
                    return Err(SysError::OutOfMemory);
                }
                out[pos..pos + 16].copy_from_slice(&ip6);
                pos += 16;
            }
            DnsRecordData::CNAME { target, target_len }
            | DnsRecordData::PTR { target, target_len } => {
                let written = encode_domain_labels(&target[..target_len], &mut out[pos..])?;
                pos += written;
            }
            DnsRecordData::TXT { text, text_len } => {
                if pos + 1 + text_len > out.len() {
                    return Err(SysError::OutOfMemory);
                }
                out[pos] = text_len as u8;
                pos += 1;
                out[pos..pos + text_len].copy_from_slice(&text[..text_len]);
                pos += text_len;
            }
            DnsRecordData::SRV {
                priority,
                weight,
                port,
                target,
                target_len,
            } => {
                if pos + 6 > out.len() {
                    return Err(SysError::OutOfMemory);
                }
                out[pos..pos + 2].copy_from_slice(&priority.to_be_bytes());
                pos += 2;
                out[pos..pos + 2].copy_from_slice(&weight.to_be_bytes());
                pos += 2;
                out[pos..pos + 2].copy_from_slice(&port.to_be_bytes());
                pos += 2;
                let written = encode_domain_labels(&target[..target_len], &mut out[pos..])?;
                pos += written;
            }
            DnsRecordData::SOA { .. } => {
                // Support minimal SOA si requis
                if pos + 4 > out.len() {
                    return Err(SysError::OutOfMemory);
                }
                out[pos..pos + 4].copy_from_slice(&ans.ttl.to_be_bytes());
                pos += 4;
            }
        }

        let rdlength = (pos - rdata_start) as u16;
        out[rdlength_pos..rdlength_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
    }

    Ok(pos)
}

/// Démon serveur et résolveur DNS de grappe (`JamboDnsDaemon`).
pub struct JamboDnsDaemon {
    pub zone: DnsZone,
    pub cache: DnsCache,
    pub cap: DnsCap,
    pub queries_total: u64,
    pub queries_resolved: u64,
    pub nxdomain_total: u64,
    pub refused_total: u64,
}

impl JamboDnsDaemon {
    pub fn new(cap: DnsCap) -> Self {
        let mut zone = DnsZone::new("jambo");
        // Enregistrements de base par défaut du cluster
        let _ = zone.add_record(
            "cluster.jambo",
            DnsType::A,
            3600,
            DnsRecordData::A([127, 0, 0, 1]),
            0,
        );
        let _ = zone.add_record(
            "gateway.jambo",
            DnsType::A,
            3600,
            DnsRecordData::A([10, 0, 0, 1]),
            0,
        );
        let _ = zone.add_record(
            "dns.jambo",
            DnsType::A,
            3600,
            DnsRecordData::A([10, 0, 0, 53]),
            0,
        );

        Self {
            zone,
            cache: DnsCache::new(),
            cap,
            queries_total: 0,
            queries_resolved: 0,
            nxdomain_total: 0,
            refused_total: 0,
        }
    }

    /// Ajoute un enregistrement sous contrôle capabilaire (`DNS_REGISTER` ou `DNS_ZONE_UPDATE`).
    pub fn add_record(
        &mut self,
        cap: &DnsCap,
        name: &str,
        rtype: DnsType,
        ttl: u32,
        data: DnsRecordData,
        now: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(dns_rights::DNS_REGISTER) && !cap.has_right(dns_rights::DNS_ZONE_UPDATE) {
            return Err(SysError::PermissionDenied);
        }
        self.zone.add_record(name, rtype, ttl, data, now)
    }

    /// Supprime un enregistrement sous contrôle capabilaire (`DNS_ZONE_UPDATE` ou `DNS_ADMIN`).
    pub fn remove_record(
        &mut self,
        cap: &DnsCap,
        name: &str,
        rtype: DnsType,
    ) -> Result<bool, SysError> {
        if !cap.has_right(dns_rights::DNS_ZONE_UPDATE) && !cap.has_right(dns_rights::DNS_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.zone.remove_record(name, rtype))
    }

    /// Résout un nom de domaine et type DNS (recherche zone puis cache local).
    pub fn resolve(
        &mut self,
        cap: &DnsCap,
        name: &str,
        rtype: DnsType,
        now: u64,
    ) -> Result<Option<DnsRecordData>, SysError> {
        if !cap.has_right(dns_rights::DNS_RESOLVE) {
            self.refused_total += 1;
            return Err(SysError::PermissionDenied);
        }
        self.queries_total += 1;

        // 1. Recherche dans la zone d'autorité
        let mut matches = [DnsRecord::empty(); 8];
        let found = self.zone.find_records(name, rtype, now, &mut matches);
        if found > 0 {
            self.queries_resolved += 1;
            return Ok(Some(matches[0].data));
        }

        // 2. Recherche dans le cache local
        if let Some(cached) = self.cache.lookup(name, rtype, now) {
            self.queries_resolved += 1;
            return Ok(Some(cached));
        }

        self.nxdomain_total += 1;
        Ok(None)
    }

    /// Raccourci pour résoudre un enregistrement IPv4 (A).
    pub fn resolve_a(
        &mut self,
        cap: &DnsCap,
        name: &str,
        now: u64,
    ) -> Result<Option<[u8; 4]>, SysError> {
        match self.resolve(cap, name, DnsType::A, now)? {
            Some(DnsRecordData::A(ip)) => Ok(Some(ip)),
            _ => Ok(None),
        }
    }

    /// Raccourci pour résoudre un enregistrement SRV.
    pub fn resolve_srv(
        &mut self,
        cap: &DnsCap,
        name: &str,
        now: u64,
    ) -> Result<Option<(u16, u16, u16, [u8; MAX_DOMAIN_LEN], usize)>, SysError> {
        match self.resolve(cap, name, DnsType::SRV, now)? {
            Some(DnsRecordData::SRV {
                priority,
                weight,
                port,
                target,
                target_len,
            }) => Ok(Some((priority, weight, port, target, target_len))),
            _ => Ok(None),
        }
    }

    /// Synchronise les services actifs depuis le registre `jambo-serviced`.
    /// Chaque service sain génère un enregistrement A (`<nom>.jambo`) et SRV (`_<nom>._tcp.jambo`).
    pub fn sync_from_service_registry(
        &mut self,
        cap: &DnsCap,
        registry: &jambo_serviced::ServiceRegistry,
        now: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dns_rights::DNS_REGISTER) {
            return Err(SysError::PermissionDenied);
        }

        let mut synced = 0;
        for svc in registry.services.iter() {
            if !svc.allocated {
                continue;
            }

            // Trouver la première instance saine
            for inst in svc.instances.iter() {
                if inst.is_alive(now) {
                    // Extraire le nom de base du service (ex: "api", "kvd.service")
                    let svc_name_raw = &svc.name;
                    let len = svc_name_raw
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(svc_name_raw.len());
                    let svc_str = core::str::from_utf8(&svc_name_raw[..len]).unwrap_or("");
                    if svc_str.is_empty() {
                        continue;
                    }

                    // Nettoyer suffixe ".service" si présent
                    let base_name = if let Some(stripped) = svc_str.strip_suffix(".service") {
                        stripped
                    } else {
                        svc_str
                    };

                    // 1. Enregistrement A : "<base_name>.jambo"
                    let mut a_name = [0u8; MAX_DOMAIN_LEN];
                    let mut a_len = 0;
                    for b in base_name.bytes() {
                        if a_len < MAX_DOMAIN_LEN {
                            a_name[a_len] = b;
                            a_len += 1;
                        }
                    }
                    for b in b".jambo".iter() {
                        if a_len < MAX_DOMAIN_LEN {
                            a_name[a_len] = *b;
                            a_len += 1;
                        }
                    }
                    let a_domain = core::str::from_utf8(&a_name[..a_len]).unwrap_or("");
                    self.zone.add_record(
                        a_domain,
                        DnsType::A,
                        inst.ttl_seconds,
                        DnsRecordData::A(inst.ip),
                        now,
                    )?;
                    synced += 1;

                    // 2. Enregistrement SRV : "_<base_name>._tcp.jambo"
                    let mut srv_name = [0u8; MAX_DOMAIN_LEN];
                    let mut srv_len = 0;
                    if srv_len < MAX_DOMAIN_LEN {
                        srv_name[srv_len] = b'_';
                        srv_len += 1;
                    }
                    for b in base_name.bytes() {
                        if srv_len < MAX_DOMAIN_LEN {
                            srv_name[srv_len] = b;
                            srv_len += 1;
                        }
                    }
                    for b in b"._tcp.jambo".iter() {
                        if srv_len < MAX_DOMAIN_LEN {
                            srv_name[srv_len] = *b;
                            srv_len += 1;
                        }
                    }
                    let srv_domain = core::str::from_utf8(&srv_name[..srv_len]).unwrap_or("");
                    let mut target = [0u8; MAX_DOMAIN_LEN];
                    target[..a_len].copy_from_slice(&a_name[..a_len]);

                    self.zone.add_record(
                        srv_domain,
                        DnsType::SRV,
                        inst.ttl_seconds,
                        DnsRecordData::SRV {
                            priority: 10,
                            weight: 10,
                            port: inst.port,
                            target,
                            target_len: a_len,
                        },
                        now,
                    )?;
                    synced += 1;
                    break;
                }
            }
        }
        Ok(synced)
    }

    /// Traite un paquet DNS wire-format RFC 1035 et génère la trame de réponse correspondante.
    pub fn handle_wire_query(
        &mut self,
        cap: &DnsCap,
        query_packet: &[u8],
        response_buf: &mut [u8],
        now: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dns_rights::DNS_RESOLVE) {
            self.refused_total += 1;
            // Essayer de renvoyer un REFUSED si possible
            if query_packet.len() >= 12 {
                if let Ok(query) = parse_wire_query(query_packet) {
                    return build_wire_response(
                        &query,
                        query_packet,
                        &[],
                        false,
                        DnsRcode::Refused,
                        response_buf,
                    );
                }
            }
            return Err(SysError::PermissionDenied);
        }
        self.queries_total += 1;

        let query = match parse_wire_query(query_packet) {
            Ok(q) => q,
            Err(_) => {
                return Err(SysError::InvalidArgument);
            }
        };

        let qname_str = query.question.qname_str();
        let is_auth = self.zone.is_authoritative_for(qname_str);

        let mut answers = [DnsRecord::empty(); 8];
        let mut answers_count = 0;

        if is_auth {
            answers_count =
                self.zone
                    .find_records(qname_str, query.question.qtype, now, &mut answers);
        } else if let Some(cached_data) = self.cache.lookup(qname_str, query.question.qtype, now) {
            let mut rec = DnsRecord::empty();
            let name_bytes = query.question.qname;
            rec.name[..query.question.qname_len]
                .copy_from_slice(&name_bytes[..query.question.qname_len]);
            rec.name_len = query.question.qname_len;
            rec.rtype = query.question.qtype;
            rec.ttl = 60;
            rec.created_at = now;
            rec.data = cached_data;
            rec.allocated = true;
            answers[0] = rec;
            answers_count = 1;
        }

        let rcode = if answers_count > 0 {
            self.queries_resolved += 1;
            DnsRcode::NoError
        } else if is_auth {
            self.nxdomain_total += 1;
            DnsRcode::NXDomain
        } else {
            self.refused_total += 1;
            DnsRcode::Refused
        };

        build_wire_response(
            &query,
            query_packet,
            &answers[..answers_count],
            is_auth,
            rcode,
            response_buf,
        )
    }

    /// Nettoie les entrées expirées du cache.
    pub fn evict_expired(&mut self, now: u64) -> usize {
        self.cache.evict_expired(now)
    }

    /// Statistiques de télémétrie du serveur DNS.
    pub fn stats(&self) -> (u64, u64, u64, u64, usize) {
        (
            self.queries_total,
            self.queries_resolved,
            self.nxdomain_total,
            self.refused_total,
            self.zone.active_records_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cap_attenuation() {
        let root_cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
        assert!(root_cap.has_right(dns_rights::DNS_RESOLVE));
        assert!(root_cap.has_right(dns_rights::DNS_REGISTER));
        assert!(root_cap.has_right(dns_rights::DNS_ZONE_UPDATE));
        assert!(root_cap.has_right(dns_rights::DNS_ADMIN));

        let ro_cap = root_cap
            .attenuate(dns_rights::DNS_RESOLVE)
            .expect("Atténuation en lecture seule");
        assert!(ro_cap.has_right(dns_rights::DNS_RESOLVE));
        assert!(!ro_cap.has_right(dns_rights::DNS_REGISTER));

        // Interdiction d'escalade
        assert_eq!(
            ro_cap.attenuate(dns_rights::DNS_REGISTER),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_zone_add_and_resolve_records() {
        let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
        let mut daemon = JamboDnsDaemon::new(cap);

        // Ajout d'enregistrements A et AAAA
        daemon
            .add_record(
                &cap,
                "api.jambo",
                DnsType::A,
                300,
                DnsRecordData::A([192, 168, 1, 100]),
                100,
            )
            .expect("add A record");

        daemon
            .add_record(
                &cap,
                "api.jambo",
                DnsType::AAAA,
                300,
                DnsRecordData::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                100,
            )
            .expect("add AAAA record");

        // Résolution
        let res_a = daemon.resolve_a(&cap, "api.jambo", 150).expect("resolve A");
        assert_eq!(res_a, Some([192, 168, 1, 100]));

        let res_aaaa = daemon
            .resolve(&cap, "api.jambo", DnsType::AAAA, 150)
            .expect("resolve AAAA");
        assert_eq!(
            res_aaaa,
            Some(DnsRecordData::AAAA([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))
        );

        // Non trouvé
        let res_nx = daemon
            .resolve_a(&cap, "unknown.jambo", 150)
            .expect("resolve NX");
        assert_eq!(res_nx, None);
    }

    #[test]
    fn test_srv_and_cname_resolution() {
        let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
        let mut daemon = JamboDnsDaemon::new(cap);

        let mut target = [0u8; MAX_DOMAIN_LEN];
        let t_bytes = b"kvd.jambo";
        target[..t_bytes.len()].copy_from_slice(t_bytes);

        daemon
            .add_record(
                &cap,
                "_kvd._tcp.jambo",
                DnsType::SRV,
                300,
                DnsRecordData::SRV {
                    priority: 5,
                    weight: 20,
                    port: 6379,
                    target,
                    target_len: t_bytes.len(),
                },
                200,
            )
            .expect("add SRV");

        let srv = daemon
            .resolve_srv(&cap, "_kvd._tcp.jambo", 250)
            .expect("resolve SRV")
            .expect("SRV exists");
        assert_eq!(srv.0, 5); // priority
        assert_eq!(srv.1, 20); // weight
        assert_eq!(srv.2, 6379); // port
        assert_eq!(&srv.3[..srv.4], b"kvd.jambo");
    }

    #[test]
    fn test_wire_format_parse_and_response() {
        let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
        let mut daemon = JamboDnsDaemon::new(cap);

        daemon
            .add_record(
                &cap,
                "web.jambo",
                DnsType::A,
                300,
                DnsRecordData::A([10, 0, 0, 42]),
                10,
            )
            .expect("add A record");

        // Paquet requête DNS standard RFC 1035 pour "web.jambo" (Type A, Class IN)
        // Header: ID=0x1234, Flags=0x0100 (RD=1), QD=1, AN=0, NS=0, AR=0
        // Question: \x03web\x05jambo\x00, Type=0x0001 (A), Class=0x0001 (IN)
        let query_wire: [u8; 27] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'e', b'b', 0x05, b'j', b'a', b'm', b'b', b'o', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let mut response_buf = [0u8; 512];
        let res_len = daemon
            .handle_wire_query(&cap, &query_wire, &mut response_buf, 20)
            .expect("handle wire query");

        assert!(res_len >= 27);
        // Vérifier header réponse
        assert_eq!(response_buf[0..2], [0x12, 0x34]); // ID
        let flags = u16::from_be_bytes([response_buf[2], response_buf[3]]);
        assert!((flags & 0x8000) != 0); // QR = 1
        assert!((flags & 0x0400) != 0); // AA = 1 (authoritative)
        assert_eq!(flags & 0x000F, 0); // RCODE = NoError
        assert_eq!(u16::from_be_bytes([response_buf[6], response_buf[7]]), 1); // ANCOUNT = 1

        // Vérifier IP 10.0.0.42 dans le RDATA de l'Answer (derniers 4 octets)
        assert_eq!(&response_buf[res_len - 4..res_len], &[10, 0, 0, 42]);
    }

    #[test]
    fn test_sync_from_service_registry() {
        let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
        let mut daemon = JamboDnsDaemon::new(cap);

        let mut registry = jambo_serviced::ServiceRegistry::new();
        let disc_cap = jambo_serviced::DiscoveryCap::new(
            Handle::new(68, 1),
            jambo_serviced::discovery_rights::ALL,
        );

        registry
            .register_instance(&disc_cap, b"vault", 1, [10, 0, 1, 99], 8200, 1, 60, 50)
            .expect("register instance in service discovery");

        let synced = daemon
            .sync_from_service_registry(&cap, &registry, 55)
            .expect("sync from registry");
        assert_eq!(synced, 2); // 1 A record + 1 SRV record

        let ip = daemon
            .resolve_a(&cap, "vault.jambo", 55)
            .expect("resolve synced A")
            .expect("IP found");
        assert_eq!(ip, [10, 0, 1, 99]);

        let srv = daemon
            .resolve_srv(&cap, "_vault._tcp.jambo", 55)
            .expect("resolve synced SRV")
            .expect("SRV found");
        assert_eq!(srv.2, 8200); // Port 8200
    }

    #[test]
    fn test_unauthorized_dns_operations() {
        let ro_cap = DnsCap::new(Handle::new(74, 2), dns_rights::DNS_RESOLVE);
        let mut daemon = JamboDnsDaemon::new(ro_cap);

        // Tentative d'enregistrement sans DNS_REGISTER
        assert_eq!(
            daemon.add_record(
                &ro_cap,
                "bad.jambo",
                DnsType::A,
                300,
                DnsRecordData::A([1, 2, 3, 4]),
                10
            ),
            Err(SysError::PermissionDenied)
        );

        // Tentative de suppression sans DNS_ZONE_UPDATE
        assert_eq!(
            daemon.remove_record(&ro_cap, "dns.jambo", DnsType::A),
            Err(SysError::PermissionDenied)
        );
    }
}
