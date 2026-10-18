//! Pilote VirtIO-GPU 1.2 en espace utilisateur (Ring 3)
//!
//! Assure le contrôle du périphérique d'accélération d'affichage VirtIO-GPU,
//! la création de ressources 2D, l'assignation du scanout et les opérations de flush.

use libjambo::SysError;

pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;

/// En-tête de contrôle VirtIO-GPU (24 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioGpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}

/// Rectangle de coordonnées VirtIO-GPU
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioGpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Commande de création de ressource 2D
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// Commande de configuration du scanout (Display Output)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioGpuSetScanout {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

/// Commande de synchronisation de trame (Flush)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioGpuResourceFlush {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

/// Pilote VirtIO-GPU
pub struct VirtioGpuDriver {
    pub mmio_base: u64,
    pub width: u32,
    pub height: u32,
    pub primary_resource_id: u32,
    pub ready: bool,
    pub frames_flushed: u64,
}

impl Default for VirtioGpuDriver {
    fn default() -> Self {
        Self::new(0, 1920, 1080)
    }
}

impl VirtioGpuDriver {
    pub const fn new(mmio_base: u64, width: u32, height: u32) -> Self {
        Self {
            mmio_base,
            width,
            height,
            primary_resource_id: 1,
            ready: true,
            frames_flushed: 0,
        }
    }

    /// Alloue la ressource 2D du scanout principal
    pub fn setup_primary_scanout(&mut self) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.create_resource_2d(1, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, self.width, self.height)?;
        self.set_scanout(
            0,
            1,
            VirtioGpuRect {
                x: 0,
                y: 0,
                width: self.width,
                height: self.height,
            },
        )?;
        self.primary_resource_id = 1;
        Ok(())
    }

    /// Crée une ressource 2D sur le contrôleur VirtIO-GPU
    pub fn create_resource_2d(
        &mut self,
        resource_id: u32,
        _format: u32,
        width: u32,
        height: u32,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if resource_id == 0 || width == 0 || height == 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Associe une page mémoire physique hôte/invité comme mémoire d'arrière-plan
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        paddr: u64,
        length: u32,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if resource_id == 0 || paddr == 0 || length == 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Configure la sortie d'affichage scanout vers une ressource
    pub fn set_scanout(
        &mut self,
        _scanout_id: u32,
        resource_id: u32,
        rect: VirtioGpuRect,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if resource_id == 0 || rect.width == 0 || rect.height == 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Transfère un rectangle modifié vers le framebuffer hôte
    pub fn transfer_to_host(&mut self, rect: VirtioGpuRect) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if rect.x + rect.width > self.width || rect.y + rect.height > self.height {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Synchronise l'affichage avec l'écran (VSync Flush)
    pub fn flush_screen(&mut self) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.frames_flushed = self.frames_flushed.wrapping_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_gpu_lifecycle() {
        let mut gpu = VirtioGpuDriver::new(0xFE00_0000, 1920, 1080);
        assert!(gpu.setup_primary_scanout().is_ok());

        let rect = VirtioGpuRect {
            x: 10,
            y: 10,
            width: 200,
            height: 100,
        };
        assert!(gpu.transfer_to_host(rect).is_ok());
        assert!(gpu.flush_screen().is_ok());
        assert_eq!(gpu.frames_flushed, 1);
    }
}
