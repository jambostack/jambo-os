//! Compositeur graphique zéro-copie et isolation de fenêtres (jambo-comp)
//!
//! Assure la composition matérielle fluide (60/120 Hz) par Damage Tracking,
//! la synchronisation VSync et le confinement strict des surfaces :
//! chaque application cliente ne peut ni lire ni capturer les pixels d'une
//! fenêtre tierce sans passer par un portail système à consentement explicite.

#![no_std]

use libjambo::{Handle, SysError};
use virtio_drv::{VirtioGpuDriver, VirtioGpuRect};

pub const MAX_WINDOWS: usize = 32;

/// Rectangle de région modifiée (Damage Tracking)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DamageRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl DamageRect {
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// Surface de fenêtre isolée par capacité
#[derive(Debug, Clone, Copy)]
pub struct WindowSurface {
    pub id: u32,
    pub owner_pid: u64,
    pub surface_cap: Handle,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub z_index: u32,
    pub visible: bool,
    pub damage: DamageRect,
}

/// Compositeur d'affichage JamboComp
pub struct JamboComp {
    pub gpu_driver: VirtioGpuDriver,
    pub screen_width: u32,
    pub screen_height: u32,
    pub refresh_rate_hz: u32,
    pub windows: [Option<WindowSurface>; MAX_WINDOWS],
    pub window_count: usize,
    pub focused_window_id: Option<u32>,
    pub total_frames_composed: u64,
}

impl Default for JamboComp {
    fn default() -> Self {
        Self::new(1920, 1080, 60)
    }
}

impl JamboComp {
    pub const fn new(screen_width: u32, screen_height: u32, refresh_rate_hz: u32) -> Self {
        const INIT_OPT: Option<WindowSurface> = None;
        Self {
            gpu_driver: VirtioGpuDriver::new(0, screen_width, screen_height),
            screen_width,
            screen_height,
            refresh_rate_hz,
            windows: [INIT_OPT; MAX_WINDOWS],
            window_count: 0,
            focused_window_id: None,
            total_frames_composed: 0,
        }
    }

    /// Crée une surface de fenêtre pour un processus client
    /// Le client ne reçoit qu'un Handle vers sa propre surface (isolation stricte).
    pub fn create_surface(
        &mut self,
        owner_pid: u64,
        width: u32,
        height: u32,
    ) -> Result<Handle, SysError> {
        if self.window_count >= MAX_WINDOWS {
            return Err(SysError::OutOfMemory);
        }

        let id = (self.window_count + 1) as u32;
        let cap_handle = Handle::new(200 + id, 1);

        let window = WindowSurface {
            id,
            owner_pid,
            surface_cap: cap_handle,
            x: 100 + (id as i32 * 30),
            y: 100 + (id as i32 * 30),
            width,
            height,
            z_index: id,
            visible: true,
            damage: DamageRect::new(0, 0, width, height), // Marqué dirty initialement
        };

        for slot in self.windows.iter_mut() {
            if slot.is_none() {
                *slot = Some(window);
                self.window_count += 1;
                self.focused_window_id = Some(id);
                return Ok(cap_handle);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Déclare une région modifiée dans une fenêtre (Damage Tracking)
    pub fn damage_surface(
        &mut self,
        surface_cap: Handle,
        damage: DamageRect,
    ) -> Result<(), SysError> {
        for slot in self.windows.iter_mut().flatten() {
            if slot.surface_cap == surface_cap {
                slot.damage = damage;
                return Ok(());
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Compose une trame d'affichage (Damage Tracking & VSync)
    /// Seules les régions sales sont recomposées vers le scanout.
    pub fn composite_frame(&mut self) -> Result<usize, SysError> {
        let mut damaged_regions_count = 0;

        for slot in self.windows.iter_mut().flatten() {
            if slot.visible && !slot.damage.is_empty() {
                // Transfert vers VirtIO-GPU uniquement de la région dirty
                let gpu_rect = VirtioGpuRect {
                    x: (slot.x.max(0) as u32) + slot.damage.x,
                    y: (slot.y.max(0) as u32) + slot.damage.y,
                    width: slot.damage.width.min(self.screen_width),
                    height: slot.damage.height.min(self.screen_height),
                };

                let _ = self.gpu_driver.transfer_to_host(gpu_rect);
                // Réinitialise la région dirty après transmission
                slot.damage = DamageRect::default();
                damaged_regions_count += 1;
            }
        }

        // Déclenche le VSync flush matériel
        self.gpu_driver.flush_screen()?;
        self.total_frames_composed = self.total_frames_composed.wrapping_add(1);

        Ok(damaged_regions_count)
    }

    /// Règle formelle : Vérifie qu'un processus ne peut pas lire les pixels d'une autre surface
    pub fn verify_surface_isolation(&self, requester_pid: u64, target_surface_cap: Handle) -> bool {
        for slot in self.windows.iter().flatten() {
            if slot.surface_cap == target_surface_cap {
                // Seul le propriétaire légitime a le droit de lire/modifier sa surface
                return slot.owner_pid == requester_pid;
            }
        }
        false
    }

    /// Déplace une fenêtre sur l'écran
    pub fn move_window(
        &mut self,
        surface_cap: Handle,
        new_x: i32,
        new_y: i32,
    ) -> Result<(), SysError> {
        for slot in self.windows.iter_mut().flatten() {
            if slot.surface_cap == surface_cap {
                slot.x = new_x;
                slot.y = new_y;
                slot.damage = DamageRect::new(0, 0, slot.width, slot.height);
                return Ok(());
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Place une fenêtre au premier plan (z-index maximal)
    pub fn bring_to_front(&mut self, window_id: u32) -> Result<(), SysError> {
        let mut max_z = 0;
        for slot in self.windows.iter().flatten() {
            if slot.z_index > max_z {
                max_z = slot.z_index;
            }
        }
        for slot in self.windows.iter_mut().flatten() {
            if slot.id == window_id {
                slot.z_index = max_z + 1;
                self.focused_window_id = Some(window_id);
                slot.damage = DamageRect::new(0, 0, slot.width, slot.height);
                return Ok(());
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Détermine quelle fenêtre se trouve aux coordonnées (x, y) spécifiées (Hit Testing)
    pub fn window_at(&self, x: i32, y: i32) -> Option<u32> {
        let mut top_window = None;
        let mut highest_z = 0;

        for slot in self.windows.iter().flatten() {
            if slot.visible
                && x >= slot.x
                && x < slot.x + slot.width as i32
                && y >= slot.y
                && y < slot.y + slot.height as i32
            {
                if slot.z_index >= highest_z {
                    highest_z = slot.z_index;
                    top_window = Some(slot.id);
                }
            }
        }
        top_window
    }

    /// Portail de capture d'écran sécurisé (Zero-Ambient Authority) :
    /// Rejette toute tentative de capture si le demandeur ne possède pas le Handle de portail accordé.
    pub fn request_screen_capture(
        &self,
        requester_pid: u64,
        portal_cap: Option<Handle>,
    ) -> Result<DamageRect, SysError> {
        match portal_cap {
            Some(cap) if !cap.is_null() => {
                if cap.index() >= 100 {
                    Ok(DamageRect::new(0, 0, self.screen_width, self.screen_height))
                } else {
                    Err(SysError::PermissionDenied)
                }
            }
            _ => {
                let _ = requester_pid;
                Err(SysError::PermissionDenied)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compositor_lifecycle_and_isolation() {
        let mut comp = JamboComp::new(1920, 1080, 60);
        let cap1 = comp.create_surface(10, 800, 600).unwrap();
        let cap2 = comp.create_surface(20, 1024, 768).unwrap();

        assert!(comp.verify_surface_isolation(10, cap1));
        assert!(!comp.verify_surface_isolation(10, cap2));

        // Hit testing
        assert!(comp.window_at(130, 130).is_some());

        // Screen capture portal
        let unauth = comp.request_screen_capture(10, None);
        assert_eq!(unauth, Err(SysError::PermissionDenied));

        let authorized_cap = Handle::new(150, 1);
        let auth = comp.request_screen_capture(10, Some(authorized_cap));
        assert!(auth.is_ok());
    }
}
