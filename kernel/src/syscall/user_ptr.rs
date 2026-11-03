//! Primitives sécurisées de validation et de copie mémoire espace utilisateur
//! Empêche les déréférencements directs en Ring 0 et protège contre C-02.

use crate::mm::AddressSpace;
use jambo_abi::SysError;

/// Limite supérieure stricte de l'espace d'adressage virtuel utilisateur x86_64 canonique
/// Toute adresse au-delà appartient à la zone non-canonique ou au noyau (HHDM à 0xffff800000000000).
pub const USER_ADDR_LIMIT: u64 = 0x0000_7fff_ffff_0000;

/// Valide qu'une plage virtuelle [vaddr, vaddr + len) est strictement cantonnée à l'espace utilisateur
/// et qu'elle est mappée avec les permissions requises dans l'espace d'adressage spécifié.
pub fn validate_user_range(
    aspace: &AddressSpace,
    vaddr: u64,
    len: usize,
    write: bool,
) -> Result<(), SysError> {
    if len == 0 {
        return Ok(());
    }

    // 1. Rejet formel du pointeur nul
    if vaddr == 0 {
        return Err(SysError::BadAddress);
    }

    // 2. Détection de débordement arithmétique 64 bits
    let end = vaddr.checked_add(len as u64).ok_or(SysError::BadAddress)?;

    // 3. Confinement dans l'espace utilisateur canonique
    if end > USER_ADDR_LIMIT {
        return Err(SysError::BadAddress);
    }

    // 4. Vérification de la présence des mappings et des permissions dans AddressSpace
    aspace.validate_range(vaddr as usize, len, write)
}

/// Copie une valeur typée `T` depuis l'espace noyau vers l'espace virtuel utilisateur
pub fn copy_to_user<T: Copy>(
    aspace: &AddressSpace,
    dst_vaddr: u64,
    val: &T,
) -> Result<(), SysError> {
    let size = core::mem::size_of::<T>();
    validate_user_range(aspace, dst_vaddr, size, true)?;
    let slice = unsafe { core::slice::from_raw_parts(val as *const T as *const u8, size) };
    aspace.write_bytes(dst_vaddr as usize, slice)
}

/// Copie optionnelle : si `dst_vaddr == 0`, l'écriture est ignorée sans erreur (paramètre de sortie omis)
pub fn copy_to_user_opt<T: Copy>(
    aspace: &AddressSpace,
    dst_vaddr: u64,
    val: &T,
) -> Result<(), SysError> {
    if dst_vaddr == 0 {
        return Ok(());
    }
    copy_to_user(aspace, dst_vaddr, val)
}

/// Lit une valeur typée `T` depuis l'espace virtuel utilisateur vers l'espace noyau
pub fn copy_from_user<T: Copy>(aspace: &AddressSpace, src_vaddr: u64) -> Result<T, SysError> {
    let size = core::mem::size_of::<T>();
    validate_user_range(aspace, src_vaddr, size, false)?;
    let mut val = core::mem::MaybeUninit::<T>::uninit();
    let slice = unsafe { core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, size) };
    aspace.read_bytes(src_vaddr as usize, slice)?;
    Ok(unsafe { val.assume_init() })
}

/// Copie un tampon d'octets depuis l'espace noyau vers l'espace virtuel utilisateur
pub fn copy_to_user_slice(
    aspace: &AddressSpace,
    dst_vaddr: u64,
    src: &[u8],
) -> Result<(), SysError> {
    if src.is_empty() {
        return Ok(());
    }
    validate_user_range(aspace, dst_vaddr, src.len(), true)?;
    aspace.write_bytes(dst_vaddr as usize, src)
}

/// Lit un tampon d'octets depuis l'espace virtuel utilisateur vers l'espace noyau
pub fn copy_from_user_slice(
    aspace: &AddressSpace,
    src_vaddr: u64,
    dst: &mut [u8],
) -> Result<(), SysError> {
    if dst.is_empty() {
        return Ok(());
    }
    validate_user_range(aspace, src_vaddr, dst.len(), false)?;
    aspace.read_bytes(src_vaddr as usize, dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::Vmo;
    use alloc::sync::Arc;

    #[test]
    fn test_null_pointer_rejected() {
        let aspace = AddressSpace::new().unwrap();
        assert_eq!(
            validate_user_range(&aspace, 0, 8, false),
            Err(SysError::BadAddress)
        );
        assert_eq!(
            validate_user_range(&aspace, 0, 8, true),
            Err(SysError::BadAddress)
        );
    }

    #[test]
    fn test_overflow_pointer_rejected() {
        let aspace = AddressSpace::new().unwrap();
        assert_eq!(
            validate_user_range(&aspace, u64::MAX - 4, 10, false),
            Err(SysError::BadAddress)
        );
    }

    #[test]
    fn test_kernel_space_pointer_rejected() {
        let aspace = AddressSpace::new().unwrap();
        // HHDM mapping address
        let kernel_addr = 0xffff_8000_0000_0000u64;
        assert_eq!(
            validate_user_range(&aspace, kernel_addr, 8, false),
            Err(SysError::BadAddress)
        );
    }

    #[test]
    fn test_unmapped_user_address_rejected() {
        let aspace = AddressSpace::new().unwrap();
        let unmapped_user_addr = 0x0000_0000_0040_0000u64;
        assert_eq!(
            validate_user_range(&aspace, unmapped_user_addr, 8, false),
            Err(SysError::BadAddress)
        );
    }

    #[test]
    fn test_mapped_user_copy_roundtrip() {
        let aspace = AddressSpace::new().unwrap();
        let vaddr = 0x0000_0000_0050_0000usize;
        let vmo = Vmo::create(4096);
        aspace
            .map_vmo(vaddr, vmo, vmo_prot::READ | vmo_prot::WRITE)
            .unwrap();

        let val_to_write: u64 = 0x1122334455667788;
        assert_eq!(copy_to_user(&aspace, vaddr as u64, &val_to_write), Ok(()));

        let read_val: u64 = copy_from_user(&aspace, vaddr as u64).unwrap();
        assert_eq!(read_val, val_to_write);
    }

    #[test]
    fn test_permission_denied_on_readonly() {
        let aspace = AddressSpace::new().unwrap();
        let vaddr = 0x0000_0000_0060_0000usize;
        let vmo = Vmo::create(4096);
        aspace.map_vmo(vaddr, vmo, vmo_prot::READ).unwrap();

        let val: u64 = 42;
        assert_eq!(
            copy_to_user(&aspace, vaddr as u64, &val),
            Err(SysError::PermissionDenied)
        );
    }
}
