//! Sous-système de partitionnement GPT (GUID Partition Table) conforme UEFI 2.10.
//!
//! Ce module implémente la sérialisation, la validation et l'analyse des tables de
//! partitionnement GPT et des MBR protecteurs en environnement `#![no_std]`.

use core::fmt;

/// Taille standard d'un secteur logique en octets.
pub const SECTOR_SIZE: usize = 512;

/// Nombre standard d'entrées de partition GPT dans la table primaire.
pub const DEFAULT_PARTITION_ENTRIES: u32 = 128;

/// Taille standard en octets d'une entrée de partition GPT.
pub const PARTITION_ENTRY_SIZE: u32 = 128;

/// Signature magique de l'en-tête GPT ("EFI PART").
pub const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645;

/// Révision standard UEFI 1.0 (0x00010000).
pub const GPT_REVISION_1_0: u32 = 0x0001_0000;

/// Taille officielle de l'en-tête GPT en octets.
pub const GPT_HEADER_SIZE: u32 = 92;

/// GUID représentant un identifiant unique universel de 128 bits (16 octets).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// GUID nul (tous zéros).
    pub const ZERO: Guid = Guid([0u8; 16]);

    /// GUID standard de partition système EFI (ESP).
    /// Format textuel : `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`
    pub const EFI_SYSTEM_PARTITION: Guid = Guid([
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ]);

    /// GUID standard de partition racine JamboOS Root (JamboFS).
    /// Format textuel : `6A616D62-6F6F-7300-726F-6F7400000001`
    pub const JAMBOOS_ROOT: Guid = Guid([
        0x6A, 0x61, 0x6D, 0x62, 0x6F, 0x6F, 0x73, 0x00, 0x72, 0x6F, 0x6F, 0x74, 0x00, 0x00, 0x00,
        0x01,
    ]);

    /// GUID pour partition de données Linux / POSIX générique.
    /// Format textuel : `0FC63DAF-8483-4772-8E79-3D69D8477DE4`
    pub const LINUX_DATA: Guid = Guid([
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ]);

    /// Crée un GUID à partir d'un tableau brut de 16 octets.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Guid(bytes)
    }

    /// Retourne les octets bruts du GUID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Vérifie si le GUID est nul.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Affichage en notation hexadécimale standard
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Calcul CRC32 standard IEEE 802.3 sans table précalculée (adapté `#![no_std]`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Entrée de partition MBR classique (16 octets).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionEntry {
    pub boot_indicator: u8,
    pub starting_chs: [u8; 3],
    pub os_type: u8,
    pub ending_chs: [u8; 3],
    pub starting_lba: u32,
    pub size_in_lba: u32,
}

/// MBR Protecteur situé à LBA 0 pour protéger le disque contre les outils MBR legacy.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ProtectiveMbr {
    pub boot_code: [u8; 446],
    pub partition_record: [MbrPartitionEntry; 4],
    pub signature: [u8; 2], // 0x55, 0xAA
}

impl ProtectiveMbr {
    /// Construit un MBR protecteur valide couvrant la taille du disque.
    pub fn new(disk_sectors: u64) -> Self {
        let size = disk_sectors.saturating_sub(1).min(u32::MAX as u64) as u32;

        let protective_entry = MbrPartitionEntry {
            boot_indicator: 0x00,
            starting_chs: [0x00, 0x02, 0x00],
            os_type: 0xEE, // Type EFI Protective MBR
            ending_chs: [0xFF, 0xFF, 0xFF],
            starting_lba: 1,
            size_in_lba: size,
        };

        let empty_entry = MbrPartitionEntry {
            boot_indicator: 0,
            starting_chs: [0; 3],
            os_type: 0,
            ending_chs: [0; 3],
            starting_lba: 0,
            size_in_lba: 0,
        };

        Self {
            boot_code: [0u8; 446],
            partition_record: [protective_entry, empty_entry, empty_entry, empty_entry],
            signature: [0x55, 0xAA],
        }
    }

    /// Écrit le MBR protecteur dans un tampon d'au moins 512 octets.
    pub fn write_to_slice(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= SECTOR_SIZE);
        buffer[..SECTOR_SIZE].fill(0);

        unsafe {
            let ptr = self as *const Self as *const u8;
            core::ptr::copy_nonoverlapping(ptr, buffer.as_mut_ptr(), core::mem::size_of::<Self>());
        }
    }
}

/// En-tête de partitionnement GPT officiel (LBA 1 pour le primaire).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Guid,
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}

/// Entrée individuelle de la table de partitions GPT (128 octets).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartitionEntry {
    pub partition_type_guid: Guid,
    pub unique_partition_guid: Guid,
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub partition_name: [u16; 36], // Nom en UTF-16LE
}

impl GptPartitionEntry {
    /// Crée une entrée vide / inactive.
    pub const fn empty() -> Self {
        Self {
            partition_type_guid: Guid::ZERO,
            unique_partition_guid: Guid::ZERO,
            starting_lba: 0,
            ending_lba: 0,
            attributes: 0,
            partition_name: [0u16; 36],
        }
    }

    /// Vérifie si l'entrée est active (Type GUID non nul).
    pub fn is_used(&self) -> bool {
        !self.partition_type_guid.is_zero()
    }

    /// Retourne la taille en secteurs (inclusif).
    pub fn size_sectors(&self) -> u64 {
        if self.ending_lba >= self.starting_lba && self.is_used() {
            (self.ending_lba - self.starting_lba) + 1
        } else {
            0
        }
    }

    /// Initialise le nom de partition en convertissant de l'ASCII vers UTF-16LE.
    pub fn set_name_ascii(&mut self, name: &str) {
        self.partition_name = [0u16; 36];
        for (i, b) in name.bytes().take(35).enumerate() {
            self.partition_name[i] = b as u16;
        }
    }

    /// Extrait le nom en chaîne ASCII si possible.
    pub fn get_name_ascii(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        for (i, &u) in self.partition_name.iter().enumerate() {
            if u == 0 || u > 127 {
                break;
            }
            buf[i] = u as u8;
        }
        buf
    }
}

/// Demande de création de partition logique.
#[derive(Debug, Clone, Copy)]
pub struct PartitionRequest<'a> {
    pub name: &'a str,
    pub type_guid: Guid,
    pub size_sectors: u64,
}

/// Erreurs possibles lors des opérations GPT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    BufferTooSmall,
    InvalidMbrSignature,
    InvalidGptSignature,
    InvalidHeaderSize,
    HeaderCrcMismatch,
    PartitionArrayCrcMismatch,
    DiskTooSmall,
    TooManyPartitions,
}

/// Informations extraites d'une table de partitions GPT analysée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptDiskInfo {
    pub disk_guid: Guid,
    pub total_sectors: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub partition_count: usize,
    pub partitions: [GptPartitionEntry; 4],
}

/// Formate un tampon disque en écrivant le MBR protecteur, l'en-tête GPT et les entrées.
///
/// Le tampon fourni doit faire au moins 34 secteurs (17 408 octets) représentant
/// LBA 0 (MBR), LBA 1 (GPT Header) et LBA 2..33 (Table de 128 entrées).
pub fn format_gpt_disk(
    buffer: &mut [u8],
    total_disk_sectors: u64,
    disk_guid: Guid,
    requests: &[PartitionRequest],
) -> Result<(), GptError> {
    const MIN_REQUIRED_BYTES: usize = 34 * SECTOR_SIZE;
    if buffer.len() < MIN_REQUIRED_BYTES {
        return Err(GptError::BufferTooSmall);
    }
    if total_disk_sectors < 68 {
        return Err(GptError::DiskTooSmall);
    }
    if requests.len() > 128 {
        return Err(GptError::TooManyPartitions);
    }

    buffer[..MIN_REQUIRED_BYTES].fill(0);

    // 1. Écriture du MBR Protecteur à LBA 0 (offset 0..512)
    let mbr = ProtectiveMbr::new(total_disk_sectors);
    mbr.write_to_slice(&mut buffer[0..SECTOR_SIZE]);

    // 2. Construction du tableau d'entrées de partition à LBA 2..33 (offset 1024..17408)
    let mut current_lba: u64 = 34; // Premier LBA utilisable après les structures GPT primaires
    let last_usable_lba = total_disk_sectors.saturating_sub(34);

    let entries_offset = 2 * SECTOR_SIZE;
    let entries_len = 128 * PARTITION_ENTRY_SIZE as usize;
    let entries_slice = &mut buffer[entries_offset..entries_offset + entries_len];

    for (idx, req) in requests.iter().enumerate() {
        if current_lba + req.size_sectors > last_usable_lba {
            return Err(GptError::DiskTooSmall);
        }

        let start_lba = current_lba;
        let end_lba = start_lba + req.size_sectors - 1;
        current_lba = end_lba + 1;

        // Génération d'un GUID unique simple dérivé du disque et de l'index
        let mut unique_bytes = disk_guid.0;
        unique_bytes[15] = unique_bytes[15].wrapping_add((idx + 1) as u8);
        let unique_guid = Guid(unique_bytes);

        let mut entry = GptPartitionEntry::empty();
        entry.partition_type_guid = req.type_guid;
        entry.unique_partition_guid = unique_guid;
        entry.starting_lba = start_lba;
        entry.ending_lba = end_lba;
        entry.attributes = 0;
        entry.set_name_ascii(req.name);

        let entry_bytes: [u8; 128] = unsafe { core::mem::transmute(entry) };
        let offset = idx * 128;
        entries_slice[offset..offset + 128].copy_from_slice(&entry_bytes);
    }

    // 3. Calcul du CRC32 du tableau d'entrées de partition
    let entries_crc = crc32(entries_slice);

    // 4. Construction de l'en-tête GPT à LBA 1 (offset 512..1024)
    let mut header = GptHeader {
        signature: GPT_SIGNATURE,
        revision: GPT_REVISION_1_0,
        header_size: GPT_HEADER_SIZE,
        header_crc32: 0, // Mis à zéro pour le calcul
        reserved: 0,
        my_lba: 1,
        alternate_lba: total_disk_sectors - 1,
        first_usable_lba: 34,
        last_usable_lba,
        disk_guid,
        partition_entry_lba: 2,
        num_partition_entries: DEFAULT_PARTITION_ENTRIES,
        size_of_partition_entry: PARTITION_ENTRY_SIZE,
        partition_entry_array_crc32: entries_crc,
    };

    // Calcul du CRC32 de l'en-tête GPT (sur 92 octets avec crc=0)
    let header_bytes: [u8; 92] = unsafe {
        let ptr = &header as *const GptHeader as *const [u8; 92];
        *ptr
    };
    header.header_crc32 = crc32(&header_bytes);

    let final_header_bytes: [u8; 92] = unsafe {
        let ptr = &header as *const GptHeader as *const [u8; 92];
        *ptr
    };

    let header_offset = SECTOR_SIZE;
    buffer[header_offset..header_offset + 92].copy_from_slice(&final_header_bytes);

    Ok(())
}

/// Analyse un tampon contenant au moins 34 secteurs et vérifie l'intégrité de la table GPT.
pub fn parse_gpt_disk(buffer: &[u8]) -> Result<GptDiskInfo, GptError> {
    const MIN_REQUIRED_BYTES: usize = 34 * SECTOR_SIZE;
    if buffer.len() < MIN_REQUIRED_BYTES {
        return Err(GptError::BufferTooSmall);
    }

    // 1. Vérification du MBR Protecteur
    if buffer[510] != 0x55 || buffer[511] != 0xAA {
        return Err(GptError::InvalidMbrSignature);
    }

    // 2. Vérification de l'En-tête GPT à LBA 1 (offset 512..1024)
    let header_slice = &buffer[SECTOR_SIZE..SECTOR_SIZE + GPT_HEADER_SIZE as usize];
    let header: GptHeader = unsafe {
        let ptr = header_slice.as_ptr() as *const GptHeader;
        core::ptr::read_unaligned(ptr)
    };

    if header.signature != GPT_SIGNATURE {
        return Err(GptError::InvalidGptSignature);
    }
    if header.header_size != GPT_HEADER_SIZE {
        return Err(GptError::InvalidHeaderSize);
    }

    // Vérification du CRC32 de l'en-tête
    let mut check_header = header;
    check_header.header_crc32 = 0;
    let check_bytes: [u8; 92] = unsafe {
        let ptr = &check_header as *const GptHeader as *const [u8; 92];
        *ptr
    };
    let calculated_header_crc = crc32(&check_bytes);
    if calculated_header_crc != header.header_crc32 {
        return Err(GptError::HeaderCrcMismatch);
    }

    // 3. Vérification du tableau de partitions à LBA 2..33
    let entries_offset = (header.partition_entry_lba as usize) * SECTOR_SIZE;
    let entries_len =
        (header.num_partition_entries as usize) * (header.size_of_partition_entry as usize);

    if buffer.len() < entries_offset + entries_len {
        return Err(GptError::BufferTooSmall);
    }

    let entries_slice = &buffer[entries_offset..entries_offset + entries_len];
    let calculated_entries_crc = crc32(entries_slice);
    if calculated_entries_crc != header.partition_entry_array_crc32 {
        return Err(GptError::PartitionArrayCrcMismatch);
    }

    // 4. Extraction des partitions actives
    let mut partitions = [GptPartitionEntry::empty(); 4];
    let mut count = 0;

    for i in 0..header.num_partition_entries as usize {
        let offset = entries_offset + i * (header.size_of_partition_entry as usize);
        let entry: GptPartitionEntry = unsafe {
            let ptr = buffer[offset..offset + 128].as_ptr() as *const GptPartitionEntry;
            core::ptr::read_unaligned(ptr)
        };

        if entry.is_used() {
            if count < 4 {
                partitions[count] = entry;
            }
            count += 1;
        }
    }

    Ok(GptDiskInfo {
        disk_guid: header.disk_guid,
        total_sectors: header.alternate_lba + 1,
        first_usable_lba: header.first_usable_lba,
        last_usable_lba: header.last_usable_lba,
        partition_count: count,
        partitions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_values() {
        // "123456789" a pour CRC32 standard IEEE 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_protective_mbr_creation() {
        let mbr = ProtectiveMbr::new(65536);
        let mut buf = [0u8; 512];
        mbr.write_to_slice(&mut buf);

        assert_eq!(buf[510], 0x55);
        assert_eq!(buf[511], 0xAA);
        // Entrée 1 : os_type = 0xEE (offset 446 + 4)
        assert_eq!(buf[446 + 4], 0xEE);
    }

    #[test]
    fn test_format_and_parse_gpt() {
        let mut disk_buf = [0u8; 34 * 512];
        let disk_guid = Guid([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let requests = [
            PartitionRequest {
                name: "EFI System Partition",
                type_guid: Guid::EFI_SYSTEM_PARTITION,
                size_sectors: 2048, // 1 Mio
            },
            PartitionRequest {
                name: "JamboOS Root",
                type_guid: Guid::JAMBOOS_ROOT,
                size_sectors: 16384, // 8 Mio
            },
        ];

        let total_sectors = 65536; // 32 Mio
        let format_res = format_gpt_disk(&mut disk_buf, total_sectors, disk_guid, &requests);
        assert!(format_res.is_ok());

        let parse_res = parse_gpt_disk(&disk_buf);
        assert!(parse_res.is_ok());

        let info = parse_res.unwrap();
        assert_eq!(info.disk_guid, disk_guid);
        assert_eq!(info.partition_count, 2);
        assert_eq!(info.total_sectors, total_sectors);

        // Partition 1 : ESP
        let p1 = &info.partitions[0];
        assert_eq!(p1.partition_type_guid, Guid::EFI_SYSTEM_PARTITION);
        assert_eq!(p1.starting_lba, 34);
        assert_eq!(p1.ending_lba, 34 + 2048 - 1);
        assert_eq!(p1.size_sectors(), 2048);
        assert_eq!(&p1.get_name_ascii()[0..20], b"EFI System Partition");

        // Partition 2 : JamboOS Root
        let p2 = &info.partitions[1];
        assert_eq!(p2.partition_type_guid, Guid::JAMBOOS_ROOT);
        assert_eq!(p2.starting_lba, 34 + 2048);
        assert_eq!(p2.ending_lba, 34 + 2048 + 16384 - 1);
        assert_eq!(p2.size_sectors(), 16384);
        assert_eq!(&p2.get_name_ascii()[0..12], b"JamboOS Root");
    }

    #[test]
    fn test_corrupt_gpt_crc_detection() {
        let mut disk_buf = [0u8; 34 * 512];
        let disk_guid = Guid::JAMBOOS_ROOT;
        let requests = [PartitionRequest {
            name: "TestPart",
            type_guid: Guid::LINUX_DATA,
            size_sectors: 100,
        }];

        format_gpt_disk(&mut disk_buf, 1000, disk_guid, &requests).unwrap();

        // Corrompre 1 octet dans l'en-tête GPT
        disk_buf[512 + 40] ^= 0xFF;
        let err = parse_gpt_disk(&disk_buf);
        assert_eq!(err, Err(GptError::HeaderCrcMismatch));
    }
}
