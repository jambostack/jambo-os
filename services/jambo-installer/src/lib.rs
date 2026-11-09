//! Bibliothèque logique de l'utilitaire d'installation JamboOS (Ring 3).
//!
//! Fournit les structures et calculs de géométrie pour le partitionnement GPT,
//! l'alignement des secteurs et l'ordonnancement du déploiement UEFI sur disque cible.

#![no_std]

#[cfg(test)]
extern crate std;

use libjambo::gpt::{
    format_backup_gpt_disk, format_gpt_disk, parse_gpt_disk, GptDiskInfo, Guid, PartitionRequest,
    SECTOR_SIZE,
};

use jambo_fs::{
    compute_merkle_leaf_hash, BlockClient, Uberblock, BLOCK_SIZE, JAMBOFS_MAGIC, JAMBOFS_VERSION,
};

/// Configuration et plan de déploiement d'une installation JamboOS sur support de stockage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallationPlan {
    /// Nombre total de secteurs logiques (LBA) adressables sur le disque.
    pub total_sectors: u64,
    /// Taille d'un secteur en octets (512 par défaut sous UEFI).
    pub sector_size: usize,
    /// Nombre de secteurs alloués pour l'EFI System Partition (ESP).
    pub esp_sectors: u64,
    /// Nombre de secteurs alloués pour la partition racine JamboFS.
    pub root_sectors: u64,
    /// LBA de début de la partition ESP.
    pub esp_start_lba: u64,
    /// LBA de début de la partition racine.
    pub root_start_lba: u64,
}

impl InstallationPlan {
    /// Calcule un plan de partitionnement conforme UEFI 2.10 à partir du nombre de secteurs.
    ///
    /// Retourne `None` si la capacité est insuffisante pour loger l'ESP, la table GPT et la racine.
    pub fn calculate(total_sectors: u64) -> Option<Self> {
        // Exige au minimum 4096 secteurs (2 Mio) pour un système minimal fonctionnel
        if total_sectors < 4096 {
            return None;
        }

        let sector_size = SECTOR_SIZE;
        let gpt_reserved = 34u64; // LBA 0 (Protective MBR) + LBA 1 (Header) + LBA 2..33 (Partitions)
        let usable_sectors = total_sectors.saturating_sub(gpt_reserved * 2); // Primaire + Secondaire

        // ESP : au moins 2048 secteurs (1 Mio), plafonné à 65536 secteurs (32 Mio)
        let esp_sectors = (usable_sectors / 8).clamp(2048, 65536);
        let root_sectors = usable_sectors.saturating_sub(esp_sectors);

        if root_sectors < 1024 {
            return None;
        }

        let esp_start_lba = 34u64;
        let root_start_lba = esp_start_lba + esp_sectors;

        Some(Self {
            total_sectors,
            sector_size,
            esp_sectors,
            root_sectors,
            esp_start_lba,
            root_start_lba,
        })
    }

    /// Calcule un plan de partitionnement conforme UEFI 2.10 en tenant compte de la géométrie de secteur (512e ou 4Kn).
    pub fn calculate_with_geometry(
        total_sectors: u64,
        geometry: libjambo::gpt::SectorGeometry,
    ) -> Option<Self> {
        let sector_size = geometry.sector_size();
        let gpt_reserved = geometry.gpt_reserved_sectors();
        let min_sectors = gpt_reserved * 2 + 512;
        if total_sectors < min_sectors {
            return None;
        }

        let usable_sectors = total_sectors.saturating_sub(gpt_reserved * 2);
        let min_esp_sectors = match geometry {
            libjambo::gpt::SectorGeometry::Sector512e => 2048,
            libjambo::gpt::SectorGeometry::Sector4Kn => 256,
        };
        let max_esp_sectors = min_esp_sectors * 32;
        let esp_sectors = (usable_sectors / 8).clamp(min_esp_sectors, max_esp_sectors);
        let root_sectors = usable_sectors.saturating_sub(esp_sectors);

        if root_sectors < 128 {
            return None;
        }

        let esp_start_lba = geometry.first_usable_lba();
        let root_start_lba = esp_start_lba + esp_sectors;

        Some(Self {
            total_sectors,
            sector_size,
            esp_sectors,
            root_sectors,
            esp_start_lba,
            root_start_lba,
        })
    }

    /// Génère la table de partitions GPT (LBA 0..33) dans le tampon de destination fourni.
    pub fn generate_gpt(&self, out: &mut [u8], disk_guid: Guid) -> Result<(), &'static str> {
        if out.len() < 34 * SECTOR_SIZE {
            return Err("Tampon insuffisant pour accueillir la table GPT");
        }

        let requests = [
            PartitionRequest {
                name: "EFI System Partition",
                type_guid: Guid::EFI_SYSTEM_PARTITION,
                size_sectors: self.esp_sectors,
            },
            PartitionRequest {
                name: "JamboOS Root",
                type_guid: Guid::JAMBOOS_ROOT,
                size_sectors: self.root_sectors,
            },
        ];

        format_gpt_disk(out, self.total_sectors, disk_guid, &requests)
            .map_err(|_| "Échec lors de la génération de la table GPT")
    }

    /// Valide l'intégrité de la table de partitions GPT présente dans le tampon.
    pub fn verify_gpt(&self, disk_buf: &[u8]) -> Result<GptDiskInfo, &'static str> {
        parse_gpt_disk(disk_buf).map_err(|_| "Table GPT corrompue ou non conforme")
    }

    /// Génère la table de partitions GPT secondaire de secours (Backup GPT conforme UEFI 2.10).
    pub fn generate_backup_gpt(&self, out: &mut [u8], disk_guid: Guid) -> Result<(), &'static str> {
        if out.len() < 33 * SECTOR_SIZE {
            return Err("Tampon insuffisant pour accueillir la table GPT secondaire");
        }

        let requests = [
            PartitionRequest {
                name: "EFI System Partition",
                type_guid: Guid::EFI_SYSTEM_PARTITION,
                size_sectors: self.esp_sectors,
            },
            PartitionRequest {
                name: "JamboOS Root",
                type_guid: Guid::JAMBOOS_ROOT,
                size_sectors: self.root_sectors,
            },
        ];

        format_backup_gpt_disk(out, self.total_sectors, disk_guid, &requests)
            .map_err(|_| "Échec lors de la génération de la table GPT secondaire")
    }

    /// Déploie le partitionnement GPT et la racine JamboFS sur un périphérique de bloc physique
    pub fn deploy_to_block_device(
        &self,
        client: &BlockClient,
        disk_guid: Guid,
    ) -> Result<(), &'static str> {
        // 1. Écriture des 34 secteurs GPT primaires (MBR + Header + Entries) par blocs de 4 Kio
        let mut primary_gpt_buf = [0u8; 34 * SECTOR_SIZE];
        self.generate_gpt(&mut primary_gpt_buf, disk_guid)?;

        let num_primary_blocks = primary_gpt_buf.len().div_ceil(BLOCK_SIZE);
        for b in 0..num_primary_blocks {
            let start = b * BLOCK_SIZE;
            let end = (start + BLOCK_SIZE).min(primary_gpt_buf.len());
            let mut block = [0u8; BLOCK_SIZE];
            block[..end - start].copy_from_slice(&primary_gpt_buf[start..end]);
            let lba = (b * 8) as u64;
            client
                .write_block(lba, &block)
                .map_err(|_| "Erreur d'écriture GPT primaire sur support de stockage")?;
        }

        // 2. Écriture des 33 secteurs GPT secondaires (Backup GPT)
        let mut backup_gpt_buf = [0u8; 33 * SECTOR_SIZE];
        self.generate_backup_gpt(&mut backup_gpt_buf, disk_guid)?;

        let backup_start_lba = self.total_sectors.saturating_sub(33);
        let num_backup_blocks = backup_gpt_buf.len().div_ceil(BLOCK_SIZE);
        for b in 0..num_backup_blocks {
            let start = b * BLOCK_SIZE;
            let end = (start + BLOCK_SIZE).min(backup_gpt_buf.len());
            let mut block = [0u8; BLOCK_SIZE];
            block[..end - start].copy_from_slice(&backup_gpt_buf[start..end]);
            let lba = backup_start_lba + (b * 8) as u64;
            client
                .write_block(lba, &block)
                .map_err(|_| "Erreur d'écriture GPT secondaire sur support de stockage")?;
        }

        // 3. Initialisation du système de fichiers JamboFS transactionnel à root_start_lba
        let banner_content = b"Bienvenue sur JamboOS v0.3.42\n";
        let banner_lba = self.root_start_lba + 24;
        let mut banner_block = [0u8; BLOCK_SIZE];
        banner_block[..banner_content.len()].copy_from_slice(banner_content);
        client
            .write_block(banner_lba, &banner_block)
            .map_err(|_| "Erreur d'écriture de la bannière système")?;

        // Calcul du condensat d'intégrité Merkle BLAKE3 pour la génération initiale 1
        let merkle_root_checksum = compute_merkle_leaf_hash(banner_content, 1);

        // Inode racine scellé à root_start_lba + 16
        let mut inode_buf = [0u8; BLOCK_SIZE];
        let ino = 1u64 + 24;
        let size = banner_content.len() as u64;
        inode_buf[0..8].copy_from_slice(&ino.to_le_bytes());
        inode_buf[8..16].copy_from_slice(&size.to_le_bytes());
        inode_buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // generation = 1
        inode_buf[24..28].copy_from_slice(&0u32.to_le_bytes());
        inode_buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // block_count = 1
        inode_buf[32..40].copy_from_slice(&24u64.to_le_bytes()); // direct_block = 24
        inode_buf[40..72].copy_from_slice(&merkle_root_checksum);
        let name_bytes = b"banner.txt";
        inode_buf[72..72 + name_bytes.len()].copy_from_slice(name_bytes);

        let inode_lba = self.root_start_lba + 16;
        client
            .write_block(inode_lba, &inode_buf)
            .map_err(|_| "Erreur d'écriture de l'inode racine JamboFS")?;

        // Uberblock initial scellé
        let uberblock = Uberblock {
            magic: JAMBOFS_MAGIC,
            version: JAMBOFS_VERSION,
            block_size: BLOCK_SIZE as u32,
            generation: 1,
            root_tree_offset: BLOCK_SIZE as u64,
            root_checksum: merkle_root_checksum,
            flags: 0,
            timestamp: 1,
        };

        let mut ub_buf = [0u8; BLOCK_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &uberblock as *const Uberblock as *const u8,
                ub_buf.as_mut_ptr(),
                core::mem::size_of::<Uberblock>(),
            );
        }

        // Écriture de l'Uberblock Slot A (LBA base racine)
        client
            .write_block(self.root_start_lba, &ub_buf)
            .map_err(|_| "Erreur d'écriture de l'Uberblock A")?;

        // Écriture de l'Uberblock Slot B (LBA base racine + 8) pour résilience CoW immédiate
        client
            .write_block(self.root_start_lba + 8, &ub_buf)
            .map_err(|_| "Erreur d'écriture de l'Uberblock B")?;

        // 4. Barrière de synchronisation matérielle NVMe / VirtIO
        client
            .flush()
            .map_err(|_| "Erreur lors du flush de synchronisation matérielle de stockage")?;

        Ok(())
    }
}

/// Extrait les arguments de la pile au format System V ABI AMD64.
///
/// # Safety
///
/// L'appelant doit garantir que `sp` pointe vers le sommet de la pile initialisé
/// par le noyau ou le dynamic loader (`*sp == argc`).
pub unsafe fn parse_stack_args<'a>(
    sp: *const usize,
    storage: &'a mut [&'a str; 16],
) -> (&'a str, &'a [&'a str]) {
    if sp.is_null() {
        return ("", &[]);
    }
    let argc = *sp;
    let mut count = 0;
    let argv_ptr = sp.add(1) as *const *const u8;

    while count < argc && count < 16 {
        let arg_ptr = *argv_ptr.add(count);
        if arg_ptr.is_null() {
            break;
        }

        let mut len = 0;
        while *arg_ptr.add(len) != 0 && len < 256 {
            len += 1;
        }

        let slice = core::slice::from_raw_parts(arg_ptr, len);
        if let Ok(s) = core::str::from_utf8(slice) {
            storage[count] = s;
            count += 1;
        } else {
            break;
        }
    }

    let prog = if count > 0 { storage[0] } else { "" };
    let args = if count > 1 {
        &storage[1..count]
    } else {
        &storage[..0]
    };
    (prog, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_nominal_32mb() {
        // 65 536 secteurs * 512 = 32 Mio
        let plan = InstallationPlan::calculate(65536).expect("Plan calculable");
        assert_eq!(plan.total_sectors, 65536);
        assert_eq!(plan.sector_size, 512);
        assert_eq!(plan.esp_start_lba, 34);
        assert!(plan.esp_sectors >= 2048);
        assert_eq!(plan.root_start_lba, 34 + plan.esp_sectors);
        assert!(plan.root_sectors > 0);
    }

    #[test]
    fn test_plan_large_disk() {
        // Disque de 1 000 000 secteurs (~500 Mio)
        let plan = InstallationPlan::calculate(1_000_000).expect("Plan calculable");
        assert_eq!(plan.esp_sectors, 65536); // Plafonné à 32 Mio ESP
        assert_eq!(plan.esp_start_lba, 34);
        assert_eq!(plan.root_start_lba, 34 + 65536);
        assert_eq!(plan.root_sectors, 1_000_000 - 68 - 65536);
    }

    #[test]
    fn test_plan_too_small() {
        assert_eq!(InstallationPlan::calculate(100), None);
        assert_eq!(InstallationPlan::calculate(2000), None);
    }

    #[test]
    fn test_gpt_generation_and_verification() {
        let plan = InstallationPlan::calculate(65536).unwrap();
        let mut buffer = [0u8; 34 * SECTOR_SIZE];
        let disk_guid = Guid([
            0x4A, 0x41, 0x4D, 0x42, 0x4F, 0x2D, 0x44, 0x49, 0x53, 0x4B, 0x2D, 0x47, 0x55, 0x49,
            0x44, 0x01,
        ]);

        assert!(plan.generate_gpt(&mut buffer, disk_guid).is_ok());

        let info = plan.verify_gpt(&buffer).expect("Table GPT valide");
        assert_eq!(info.disk_guid, disk_guid);
        assert_eq!(info.partition_count, 2);
    }

    #[test]
    fn test_backup_gpt_generation() {
        let plan = InstallationPlan::calculate(65536).unwrap();
        let mut buffer = [0u8; 33 * SECTOR_SIZE];
        let disk_guid = Guid::JAMBOOS_ROOT;

        assert!(plan.generate_backup_gpt(&mut buffer, disk_guid).is_ok());

        // L'en-tête de secours est à l'offset 32 * SECTOR_SIZE
        let sig = u64::from_le_bytes(buffer[32 * 512..32 * 512 + 8].try_into().unwrap());
        assert_eq!(sig, libjambo::gpt::GPT_SIGNATURE);
    }

    #[test]
    fn test_deploy_to_block_device_lifecycle() {
        let plan = InstallationPlan::calculate(65536).unwrap();
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let disk_guid = Guid::JAMBOOS_ROOT;

        let deploy_res = plan.deploy_to_block_device(&dummy_client, disk_guid);
        assert!(deploy_res.is_ok());

        // Après déploiement, le montage JamboFS sur la racine doit détecter l'Uberblock A scellé
        let fs =
            jambo_fs::JamboFs::mount(&dummy_client).expect("Montage persistant après installation");
        assert_eq!(fs.active_uberblock.magic, JAMBOFS_MAGIC);
        assert_eq!(fs.active_uberblock.version, JAMBOFS_VERSION);
        assert_eq!(fs.active_uberblock.generation, 1);
        assert_ne!(fs.active_uberblock.root_checksum, [0u8; 32]);

        // Vérification de la lecture du fichier déployé
        let mut read_buf = [0u8; 64];
        let len = fs
            .read_file("/banner.txt", &mut read_buf)
            .expect("Lecture banner déployé");
        assert!(len > 0);
        let s = core::str::from_utf8(&read_buf[..len]).unwrap();
        assert!(s.contains("JamboOS"));
    }

    #[test]
    fn test_parse_stack_args_mock() {
        let prog = b"installer\0";
        let arg1 = b"install\0";
        let stack: [usize; 3] = [2, prog.as_ptr() as usize, arg1.as_ptr() as usize];

        let mut storage = [""; 16];
        let (p, args) = unsafe { parse_stack_args(stack.as_ptr(), &mut storage) };
        assert_eq!(p, "installer");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0], "install");
    }
}
