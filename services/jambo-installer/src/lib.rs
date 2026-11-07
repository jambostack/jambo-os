//! Bibliothèque logique de l'utilitaire d'installation JamboOS (Ring 3).
//!
//! Fournit les structures et calculs de géométrie pour le partitionnement GPT,
//! l'alignement des secteurs et l'ordonnancement du déploiement UEFI sur disque cible.

#![no_std]

#[cfg(test)]
extern crate std;

use libjambo::gpt::{
    format_gpt_disk, parse_gpt_disk, GptDiskInfo, Guid, PartitionRequest, SECTOR_SIZE,
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
