//! Pilote VirtIO-GPU 1.2 en espace utilisateur (Ring 3) et Console Native 2D
//!
//! Assure le contrôle du périphérique d'accélération d'affichage VirtIO-GPU,
//! la création de ressources 2D, l'assignation du scanout, les transferts mémoire hôte/invité,
//! les opérations de synchronisation de trame (VSync Flush) et une console d'affichage native
//! Ring 3 bitmap 2D avec défilement matériel/logiciel.

use libjambo::SysError;

// Commandes de contrôle VirtIO-GPU OASIS 1.2
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const VIRTIO_GPU_CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const VIRTIO_GPU_CMD_MOVE_CURSOR: u32 = 0x0301;
pub const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x0108;

// Réponses de statut VirtIO-GPU OASIS 1.2
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1102;
pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

// Formats de pixels standard OASIS VirtIO-GPU 1.2
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 68;

// Dimensions de la fonte bitmap ASCII de la console
pub const FONT_WIDTH: usize = 8;
pub const FONT_HEIGHT: usize = 16;
pub const MAX_CONSOLE_COLS: usize = 128;
pub const MAX_CONSOLE_ROWS: usize = 48;
pub const CONSOLE_BUFFER_SIZE: usize = MAX_CONSOLE_COLS * MAX_CONSOLE_ROWS;

/// En-tête de contrôle VirtIO-GPU (24 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}

/// Rectangle de coordonnées VirtIO-GPU (16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Commande de création de ressource 2D
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// Commande de configuration du scanout (Display Output)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuSetScanout {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

/// Commande de synchronisation de trame (Flush)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuResourceFlush {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

/// Commande de transfert 2D vers l'hôte
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuTransferToHost2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

/// Entrée mémoire pour attachement de backing store
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuMemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

/// Position du curseur VirtIO-GPU (16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuCursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub padding: u32,
}

/// Commande de mise à jour du curseur VirtIO-GPU 1.2 (56 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuUpdateCursor {
    pub hdr: VirtioGpuCtrlHdr,
    pub pos: VirtioGpuCursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub padding: u32,
}

/// Commande de récupération des métadonnées EDID du moniteur connecté (24 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioGpuGetEdid {
    pub hdr: VirtioGpuCtrlHdr,
    pub scanout: u32,
    pub padding: u32,
}

/// Réponse contenant le bloc EDID binaire (jusqu'à 1024 octets selon OASIS VirtIO-GPU 1.2)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioGpuRespEdid {
    pub hdr: VirtioGpuCtrlHdr,
    pub size: u32,
    pub padding: u32,
    pub edid: [u8; 1024],
}

impl Default for VirtioGpuRespEdid {
    fn default() -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::default(),
            size: 0,
            padding: 0,
            edid: [0u8; 1024],
        }
    }
}

/// Métadonnées d'affichage décodées à partir du bloc binaire VESA EDID 1.3 / 1.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdidInfo {
    pub valid: bool,
    pub manufacturer_id: [u8; 3],
    pub product_code: u16,
    pub serial_number: u32,
    pub version: u8,
    pub revision: u8,
    pub preferred_width: u32,
    pub preferred_height: u32,
    pub pixel_clock_khz: u32,
    pub h_active: u32,
    pub v_active: u32,
    pub refresh_rate_hz: u32,
}

impl Default for EdidInfo {
    fn default() -> Self {
        Self {
            valid: false,
            manufacturer_id: *b"JMB",
            product_code: 0x0001,
            serial_number: 1,
            version: 1,
            revision: 4,
            preferred_width: 1920,
            preferred_height: 1080,
            pixel_clock_khz: 148_500,
            h_active: 1920,
            v_active: 1080,
            refresh_rate_hz: 60,
        }
    }
}

/// Mode vidéo d'affichage haute résolution et cadencement de rafraîchissement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoMode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u32,
    pub format: u32,
    pub pitch: u32,
}

impl Default for VideoMode {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            refresh_hz: 60,
            format: VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            pitch: 1920 * 4,
        }
    }
}

/// Convertit un tampon de trame de pixels entre les formats RGBA et BGRA
///
/// Assure l'échange sécurisé des composantes rouge et bleue par mot de 32 bits
/// pour garantir la conformité avec le contrôleur d'affichage matériel sans copie superflue.
pub fn convert_pixel_format(
    src_format: u32,
    dst_format: u32,
    src: &[u8],
    dst: &mut [u8],
) -> Result<usize, SysError> {
    if src.len() > dst.len() || (src.len() % 4) != 0 {
        return Err(SysError::InvalidArgument);
    }

    let pixels_count = src.len() / 4;

    if src_format == dst_format {
        dst[..src.len()].copy_from_slice(src);
        return Ok(src.len());
    }

    let need_rb_swap = (src_format == VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
        && (dst_format == VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
            || dst_format == VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM))
        || (src_format == VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
            && (dst_format == VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
                || dst_format == VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM))
        || (src_format == VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
            && (dst_format == VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
                || dst_format == VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM))
        || (src_format == VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM
            && (dst_format == VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
                || dst_format == VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM));

    if need_rb_swap {
        for i in 0..pixels_count {
            let offset = i * 4;
            let b0 = src[offset];
            let g = src[offset + 1];
            let b2 = src[offset + 2];
            let a = src[offset + 3];
            dst[offset] = b2;
            dst[offset + 1] = g;
            dst[offset + 2] = b0;
            dst[offset + 3] = a;
        }
        Ok(src.len())
    } else {
        dst[..src.len()].copy_from_slice(src);
        Ok(src.len())
    }
}

/// Gestionnaire d'agrégation et de coalescence des régions modifiées de l'écran (Dirty Rectangles)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirtyRectTracker {
    pub min_x: u32,
    pub min_y: u32,
    pub max_x: u32,
    pub max_y: u32,
    pub has_dirty: bool,
    pub screen_width: u32,
    pub screen_height: u32,
}

impl DirtyRectTracker {
    pub const fn new(screen_width: u32, screen_height: u32) -> Self {
        Self {
            min_x: 0,
            min_y: 0,
            max_x: 0,
            max_y: 0,
            has_dirty: false,
            screen_width,
            screen_height,
        }
    }

    /// Marque un rectangle d'écran comme modifié
    pub fn mark_rect(&mut self, rect: VirtioGpuRect) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        let rx1 = rect.x.min(self.screen_width);
        let ry1 = rect.y.min(self.screen_height);
        let rx2 = (rect.x.saturating_add(rect.width)).min(self.screen_width);
        let ry2 = (rect.y.saturating_add(rect.height)).min(self.screen_height);

        if !self.has_dirty {
            self.min_x = rx1;
            self.min_y = ry1;
            self.max_x = rx2;
            self.max_y = ry2;
            self.has_dirty = true;
        } else {
            self.min_x = self.min_x.min(rx1);
            self.min_y = self.min_y.min(ry1);
            self.max_x = self.max_x.max(rx2);
            self.max_y = self.max_y.max(ry2);
        }
    }

    /// Marque un point ou pixel individuel
    pub fn mark_point(&mut self, x: u32, y: u32) {
        self.mark_rect(VirtioGpuRect {
            x,
            y,
            width: 1,
            height: 1,
        });
    }

    /// Extrait le rectangle englobant modifié et réinitialise le suivi
    pub fn take_dirty_rect(&mut self) -> Option<VirtioGpuRect> {
        if !self.has_dirty {
            return None;
        }
        let rect = VirtioGpuRect {
            x: self.min_x,
            y: self.min_y,
            width: self.max_x.saturating_sub(self.min_x),
            height: self.max_y.saturating_sub(self.min_y),
        };
        self.has_dirty = false;
        self.min_x = 0;
        self.min_y = 0;
        self.max_x = 0;
        self.max_y = 0;
        Some(rect)
    }

    /// Surface totale modifiée en pixels
    pub const fn dirty_area(&self) -> u64 {
        if !self.has_dirty {
            0
        } else {
            ((self.max_x - self.min_x) as u64) * ((self.max_y - self.min_y) as u64)
        }
    }
}

/// Pilote VirtIO-GPU
pub struct VirtioGpuDriver {
    pub mmio_base: u64,
    pub width: u32,
    pub height: u32,
    pub pixel_format: u32,
    pub active_mode: VideoMode,
    pub edid_info: Option<EdidInfo>,
    pub primary_resource_id: u32,
    pub active_scanout_id: u32,
    pub cursor_resource_id: u32,
    pub cursor_x: u32,
    pub cursor_y: u32,
    pub cursor_visible: bool,
    pub dirty_tracker: DirtyRectTracker,
    pub ready: bool,
    pub frames_flushed: u64,
    pub bytes_transferred: u64,
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
            pixel_format: VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            active_mode: VideoMode {
                width,
                height,
                refresh_hz: 60,
                format: VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
                pitch: width * 4,
            },
            edid_info: None,
            primary_resource_id: 1,
            active_scanout_id: 0,
            cursor_resource_id: 0,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            dirty_tracker: DirtyRectTracker::new(width, height),
            ready: true,
            frames_flushed: 0,
            bytes_transferred: 0,
        }
    }

    /// Construit la commande de création d'une ressource 2D
    pub fn build_create_2d_cmd(
        &self,
        resource_id: u32,
        format: u32,
        width: u32,
        height: u32,
    ) -> VirtioGpuResourceCreate2d {
        VirtioGpuResourceCreate2d {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            resource_id,
            format,
            width,
            height,
        }
    }

    /// Construit la commande de configuration du scanout
    pub fn build_set_scanout_cmd(
        &self,
        scanout_id: u32,
        resource_id: u32,
        rect: VirtioGpuRect,
    ) -> VirtioGpuSetScanout {
        VirtioGpuSetScanout {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_SET_SCANOUT,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            rect,
            scanout_id,
            resource_id,
        }
    }

    /// Construit la commande de transfert vers l'hôte
    pub fn build_transfer_to_host_cmd(
        &self,
        resource_id: u32,
        rect: VirtioGpuRect,
        offset: u64,
    ) -> VirtioGpuTransferToHost2d {
        VirtioGpuTransferToHost2d {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            rect,
            offset,
            resource_id,
            padding: 0,
        }
    }

    /// Construit la commande de flush de ressource
    pub fn build_flush_cmd(&self, resource_id: u32, rect: VirtioGpuRect) -> VirtioGpuResourceFlush {
        VirtioGpuResourceFlush {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_RESOURCE_FLUSH,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            rect,
            resource_id,
            padding: 0,
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
        self.active_scanout_id = 0;
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
        scanout_id: u32,
        resource_id: u32,
        rect: VirtioGpuRect,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if resource_id == 0 || rect.width == 0 || rect.height == 0 {
            return Err(SysError::InvalidArgument);
        }
        self.active_scanout_id = scanout_id;
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
        let bytes = (rect.width as u64) * (rect.height as u64) * 4;
        self.bytes_transferred = self.bytes_transferred.saturating_add(bytes);
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

    /// Construit la commande de mise à jour du curseur
    pub fn build_update_cursor_cmd(
        &self,
        resource_id: u32,
        scanout_id: u32,
        x: u32,
        y: u32,
        hot_x: u32,
        hot_y: u32,
    ) -> VirtioGpuUpdateCursor {
        VirtioGpuUpdateCursor {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_UPDATE_CURSOR,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            pos: VirtioGpuCursorPos {
                scanout_id,
                x,
                y,
                padding: 0,
            },
            resource_id,
            hot_x,
            hot_y,
            padding: 0,
        }
    }

    /// Construit la commande de déplacement du curseur
    pub fn build_move_cursor_cmd(&self, scanout_id: u32, x: u32, y: u32) -> VirtioGpuUpdateCursor {
        VirtioGpuUpdateCursor {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_MOVE_CURSOR,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            pos: VirtioGpuCursorPos {
                scanout_id,
                x,
                y,
                padding: 0,
            },
            resource_id: self.cursor_resource_id,
            hot_x: 0,
            hot_y: 0,
            padding: 0,
        }
    }

    /// Met à jour la position et la forme du curseur matériel
    pub fn update_cursor(
        &mut self,
        resource_id: u32,
        x: u32,
        y: u32,
        hot_x: u32,
        hot_y: u32,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cursor_resource_id = resource_id;
        self.cursor_x = x.min(self.width);
        self.cursor_y = y.min(self.height);
        self.cursor_visible = resource_id > 0;
        let _ = (hot_x, hot_y);
        Ok(())
    }

    /// Déplace le curseur matériel à des coordonnées absolues
    pub fn move_cursor(&mut self, x: u32, y: u32) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cursor_x = x.min(self.width);
        self.cursor_y = y.min(self.height);
        Ok(())
    }

    /// Masque le curseur matériel
    pub fn hide_cursor(&mut self) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cursor_visible = false;
        Ok(())
    }

    /// Transfère et synchronise les zones modifiées agrégées (Dirty Rectangles)
    pub fn flush_dirty_regions(&mut self) -> Result<Option<VirtioGpuRect>, SysError> {
        if let Some(dirty_rect) = self.dirty_tracker.take_dirty_rect() {
            self.transfer_to_host(dirty_rect)?;
            self.flush_screen()?;
            Ok(Some(dirty_rect))
        } else {
            Ok(None)
        }
    }

    /// Construit la commande pour interroger les métadonnées EDID d'un scanout
    pub fn build_get_edid_cmd(&self, scanout: u32) -> VirtioGpuGetEdid {
        VirtioGpuGetEdid {
            hdr: VirtioGpuCtrlHdr {
                cmd_type: VIRTIO_GPU_CMD_GET_EDID,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                ring_idx: 0,
                padding: [0; 3],
            },
            scanout,
            padding: 0,
        }
    }

    /// Décode et valide un bloc binaire EDID VESA 1.3 / 1.4 de 128 octets
    pub fn parse_edid_block(&self, raw: &[u8]) -> Result<EdidInfo, SysError> {
        if raw.len() < 128 {
            return Err(SysError::BufferTooSmall);
        }

        // 1. Validation de l'en-tête magique VESA standard (0x00, 0xFF * 6, 0x00)
        let expected_hdr: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        if raw[..8] != expected_hdr {
            return Err(SysError::InvalidArgument);
        }

        // 2. Validation de la somme de contrôle (checksum modulo 256 == 0)
        let mut sum: u8 = 0;
        for &b in &raw[..128] {
            sum = sum.wrapping_add(b);
        }
        if sum != 0 {
            return Err(SysError::InvalidArgument);
        }

        // 3. Décodage de l'identifiant fabricant (3 lettres ASCII encodées sur 5 bits)
        let mfg_code = u16::from_be_bytes([raw[8], raw[9]]);
        let c1 = b'@' + (((mfg_code >> 10) & 0x1F) as u8);
        let c2 = b'@' + (((mfg_code >> 5) & 0x1F) as u8);
        let c3 = b'@' + ((mfg_code & 0x1F) as u8);

        // 4. Code produit et numéro de série
        let product_code = u16::from_le_bytes([raw[10], raw[11]]);
        let serial_number = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let version = raw[18];
        let revision = raw[19];

        // 5. Décodage du premier Detailed Timing Descriptor (offset 54..72)
        let pixel_clock_khz = (u16::from_le_bytes([raw[54], raw[55]]) as u32) * 10;
        let h_active = (raw[56] as u32) | (((raw[58] >> 4) as u32) << 8);
        let h_blank = (raw[57] as u32) | (((raw[58] & 0x0F) as u32) << 8);
        let v_active = (raw[59] as u32) | (((raw[61] >> 4) as u32) << 8);
        let v_blank = (raw[60] as u32) | (((raw[61] & 0x0F) as u32) << 8);

        let h_total = h_active + h_blank;
        let v_total = v_active + v_blank;
        let refresh_rate_hz = if h_total > 0 && v_total > 0 && pixel_clock_khz > 0 {
            ((pixel_clock_khz as u64 * 1000) / (h_total as u64 * v_total as u64)) as u32
        } else {
            60
        };

        let pref_w = if h_active > 0 { h_active } else { 1920 };
        let pref_h = if v_active > 0 { v_active } else { 1080 };

        Ok(EdidInfo {
            valid: true,
            manufacturer_id: [c1, c2, c3],
            product_code,
            serial_number,
            version,
            revision,
            preferred_width: pref_w,
            preferred_height: pref_h,
            pixel_clock_khz,
            h_active,
            v_active,
            refresh_rate_hz,
        })
    }

    /// Interroge les métadonnées EDID de la sortie d'affichage désignée
    pub fn query_edid(&mut self, scanout_id: u32) -> Result<EdidInfo, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let _cmd = self.build_get_edid_cmd(scanout_id);

        // Données EDID virtuelles par défaut pour VirtIO-GPU en l'absence de retour matériel
        let mut mock_edid = [0u8; 128];
        mock_edid[..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        // Manufacturer "JMB" (0x29, 0xA2)
        mock_edid[8] = 0x29;
        mock_edid[9] = 0xA2;
        // Product code 0x0001
        mock_edid[10] = 0x01;
        mock_edid[11] = 0x00;
        mock_edid[18] = 1; // VESA 1.4
        mock_edid[19] = 4;
        // Detailed Timing Descriptor 1920x1080 @ 60 Hz (pixel clock 148.50 MHz = 14850 * 10 kHz -> 0x3A02)
        mock_edid[54] = 0x02;
        mock_edid[55] = 0x3A;
        // H-active 1920 (0x780), H-blank 280 (0x118) -> 56=0x80, 57=0x18, 58=0x71
        mock_edid[56] = 0x80;
        mock_edid[57] = 0x18;
        mock_edid[58] = 0x71;
        // V-active 1080 (0x438), V-blank 45 (0x02D) -> 59=0x38, 60=0x2D, 61=0x40
        mock_edid[59] = 0x38;
        mock_edid[60] = 0x2D;
        mock_edid[61] = 0x40;

        // Calcul du checksum
        let mut sum: u8 = 0;
        for &b in &mock_edid[..127] {
            sum = sum.wrapping_add(b);
        }
        mock_edid[127] = (!sum).wrapping_add(1);

        let info = self.parse_edid_block(&mock_edid)?;
        self.edid_info = Some(info);
        Ok(info)
    }

    /// Applique un nouveau mode vidéo d'affichage haute résolution
    pub fn set_video_mode(&mut self, mode: VideoMode) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if mode.width == 0 || mode.width > 3840 || mode.height == 0 || mode.height > 2160 {
            return Err(SysError::InvalidArgument);
        }

        self.width = mode.width;
        self.height = mode.height;
        self.pixel_format = mode.format;
        self.active_mode = mode;
        self.dirty_tracker = DirtyRectTracker::new(mode.width, mode.height);
        self.dirty_tracker.mark_rect(VirtioGpuRect {
            x: 0,
            y: 0,
            width: mode.width,
            height: mode.height,
        });

        Ok(())
    }
}

/// Console d'affichage native 2D Ring 3 opérant sur VirtIO-GPU
#[derive(Debug, Clone)]
pub struct VirtioGpuConsole {
    pub cols: usize,
    pub rows: usize,
    pub cursor_col: usize,
    pub cursor_row: usize,
    pub fg_color: u32,
    pub bg_color: u32,
    pub char_buffer: [u8; CONSOLE_BUFFER_SIZE],
    pub color_buffer: [u32; CONSOLE_BUFFER_SIZE],
    // Zone modifiée à synchroniser (bounding box dirty)
    pub dirty_min_col: usize,
    pub dirty_min_row: usize,
    pub dirty_max_col: usize,
    pub dirty_max_row: usize,
    pub has_dirty: bool,
}

impl VirtioGpuConsole {
    /// Crée une nouvelle console texte 2D adaptée à la résolution d'écran
    pub fn new(screen_width: u32, screen_height: u32) -> Self {
        let max_cols = (screen_width as usize / FONT_WIDTH).min(MAX_CONSOLE_COLS);
        let max_rows = (screen_height as usize / FONT_HEIGHT).min(MAX_CONSOLE_ROWS);
        let cols = if max_cols > 0 { max_cols } else { 80 };
        let rows = if max_rows > 0 { max_rows } else { 25 };

        let mut console = Self {
            cols,
            rows,
            cursor_col: 0,
            cursor_row: 0,
            fg_color: 0x00F0_F0F0, // Blanc cassé lisible
            bg_color: 0x000F_172A, // Bleu ardoise profond JamboOS
            char_buffer: [b' '; CONSOLE_BUFFER_SIZE],
            color_buffer: [0x00F0_F0F0; CONSOLE_BUFFER_SIZE],
            dirty_min_col: 0,
            dirty_min_row: 0,
            dirty_max_col: 0,
            dirty_max_row: 0,
            has_dirty: false,
        };
        console.clear();
        console
    }

    /// Efface l'écran et réinitialise le curseur en haut à gauche
    pub fn clear(&mut self) {
        for idx in 0..CONSOLE_BUFFER_SIZE {
            self.char_buffer[idx] = b' ';
            self.color_buffer[idx] = self.fg_color;
        }
        self.cursor_col = 0;
        self.cursor_row = 0;
        self.mark_dirty(
            0,
            0,
            self.cols.saturating_sub(1),
            self.rows.saturating_sub(1),
        );
    }

    /// Configure les couleurs d'avant-plan et d'arrière-plan
    pub fn set_colors(&mut self, fg: u32, bg: u32) {
        self.fg_color = fg;
        self.bg_color = bg;
    }

    /// Marque une zone rectangulaire de cellules comme modifiée
    pub fn mark_dirty(&mut self, min_col: usize, min_row: usize, max_col: usize, max_row: usize) {
        if !self.has_dirty {
            self.dirty_min_col = min_col;
            self.dirty_min_row = min_row;
            self.dirty_max_col = max_col;
            self.dirty_max_row = max_row;
            self.has_dirty = true;
        } else {
            self.dirty_min_col = self.dirty_min_col.min(min_col);
            self.dirty_min_row = self.dirty_min_row.min(min_row);
            self.dirty_max_col = self.dirty_max_col.max(max_col);
            self.dirty_max_row = self.dirty_max_row.max(max_row);
        }
    }

    /// Défilement vertical d'une ligne vers le haut
    pub fn scroll_up(&mut self) {
        if self.rows <= 1 {
            return;
        }

        // Remonter toutes les lignes d'un cran
        for r in 1..self.rows {
            let src_start = r * self.cols;
            let dst_start = (r - 1) * self.cols;
            for c in 0..self.cols {
                self.char_buffer[dst_start + c] = self.char_buffer[src_start + c];
                self.color_buffer[dst_start + c] = self.color_buffer[src_start + c];
            }
        }

        // Effacer la dernière ligne
        let last_start = (self.rows - 1) * self.cols;
        for c in 0..self.cols {
            self.char_buffer[last_start + c] = b' ';
            self.color_buffer[last_start + c] = self.fg_color;
        }

        if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }

        self.mark_dirty(
            0,
            0,
            self.cols.saturating_sub(1),
            self.rows.saturating_sub(1),
        );
    }

    /// Écrit un octet ASCII sur la console avec interprétation des séquences de contrôle
    pub fn put_char(&mut self, b: u8) {
        match b {
            b'\n' => {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= self.rows {
                    self.scroll_up();
                }
            }
            b'\r' => {
                self.cursor_col = 0;
            }
            b'\t' => {
                let next_col = (self.cursor_col + 8) & !7;
                while self.cursor_col < next_col && self.cursor_col < self.cols {
                    let idx = self.cursor_row * self.cols + self.cursor_col;
                    self.char_buffer[idx] = b' ';
                    self.color_buffer[idx] = self.fg_color;
                    self.mark_dirty(
                        self.cursor_col,
                        self.cursor_row,
                        self.cursor_col,
                        self.cursor_row,
                    );
                    self.cursor_col += 1;
                }
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.rows {
                        self.scroll_up();
                    }
                }
            }
            b'\x08' => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    let idx = self.cursor_row * self.cols + self.cursor_col;
                    self.char_buffer[idx] = b' ';
                    self.mark_dirty(
                        self.cursor_col,
                        self.cursor_row,
                        self.cursor_col,
                        self.cursor_row,
                    );
                }
            }
            c => {
                let col = self.cursor_col;
                let row = self.cursor_row;
                let idx = row * self.cols + col;
                self.char_buffer[idx] = c;
                self.color_buffer[idx] = self.fg_color;
                self.mark_dirty(col, row, col, row);

                self.cursor_col += 1;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.rows {
                        self.scroll_up();
                    }
                }
            }
        }
    }

    /// Écrit une chaîne UTF-8 / ASCII sur la console
    pub fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_char(b);
        }
    }

    /// Obtient le caractère stocké à une coordonnée donnée
    pub fn get_char_at(&self, col: usize, row: usize) -> Option<u8> {
        if col < self.cols && row < self.rows {
            Some(self.char_buffer[row * self.cols + col])
        } else {
            None
        }
    }

    /// Calcule le rectangle de pixels VirtIO-GPU correspondant à la zone modifiée
    pub fn dirty_rect(&self) -> Option<VirtioGpuRect> {
        if !self.has_dirty {
            return None;
        }

        let x = (self.dirty_min_col * FONT_WIDTH) as u32;
        let y = (self.dirty_min_row * FONT_HEIGHT) as u32;
        let width = ((self.dirty_max_col - self.dirty_min_col + 1) * FONT_WIDTH) as u32;
        let height = ((self.dirty_max_row - self.dirty_min_row + 1) * FONT_HEIGHT) as u32;

        Some(VirtioGpuRect {
            x,
            y,
            width,
            height,
        })
    }

    /// Synchronise les modifications vers le pilote VirtIO-GPU hôte
    pub fn flush(&mut self, driver: &mut VirtioGpuDriver) -> Result<bool, SysError> {
        if let Some(rect) = self.dirty_rect() {
            driver.transfer_to_host(rect)?;
            driver.flush_screen()?;
            self.has_dirty = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_gpu_driver_lifecycle() {
        let mut gpu = VirtioGpuDriver::new(0xFE00_0000, 1920, 1080);
        assert!(gpu.setup_primary_scanout().is_ok());

        let rect = VirtioGpuRect {
            x: 10,
            y: 10,
            width: 200,
            height: 100,
        };
        assert!(gpu.transfer_to_host(rect).is_ok());
        assert_eq!(gpu.bytes_transferred, 200 * 100 * 4);
        assert!(gpu.flush_screen().is_ok());
        assert_eq!(gpu.frames_flushed, 1);
    }

    #[test]
    fn test_virtio_gpu_console_output_and_scrolling() {
        let mut console = VirtioGpuConsole::new(640, 480);
        assert_eq!(console.cols, 80);
        assert_eq!(console.rows, 30);

        console.write_str("Hello, JamboOS!\n");
        assert_eq!(console.get_char_at(0, 0), Some(b'H'));
        assert_eq!(console.get_char_at(1, 0), Some(b'e'));
        assert_eq!(console.get_char_at(0, 1), Some(b' '));
        assert_eq!(console.cursor_col, 0);
        assert_eq!(console.cursor_row, 1);
        assert!(console.has_dirty);

        let mut gpu = VirtioGpuDriver::new(0, 640, 480);
        let flushed = console.flush(&mut gpu).expect("flush ok");
        assert!(flushed);
        assert!(!console.has_dirty);
        assert_eq!(gpu.frames_flushed, 1);

        // Test défilement
        for i in 0..35 {
            let mut line = [0u8; 16];
            line[0] = b'L';
            line[1] = b'0' + (i % 10) as u8;
            line[2] = b'\n';
            console.write_str(core::str::from_utf8(&line[..3]).unwrap());
        }
        assert_eq!(console.cursor_row, console.rows - 1);
    }

    #[test]
    fn test_virtio_gpu_hardware_cursor_and_dirty_rect_coalescing() {
        let mut gpu = VirtioGpuDriver::new(0, 1920, 1080);
        assert!(!gpu.cursor_visible);

        // 1. Initialisation et configuration du curseur
        assert!(gpu.update_cursor(10, 100, 200, 0, 0).is_ok());
        assert!(gpu.cursor_visible);
        assert_eq!(gpu.cursor_x, 100);
        assert_eq!(gpu.cursor_y, 200);

        // 2. Déplacement du curseur
        assert!(gpu.move_cursor(300, 400).is_ok());
        assert_eq!(gpu.cursor_x, 300);
        assert_eq!(gpu.cursor_y, 400);

        // 3. Masquage du curseur
        assert!(gpu.hide_cursor().is_ok());
        assert!(!gpu.cursor_visible);

        // 4. Test des commandes brutes VirtIO-GPU
        let cmd_up = gpu.build_update_cursor_cmd(10, 0, 50, 60, 2, 2);
        assert_eq!(cmd_up.hdr.cmd_type, VIRTIO_GPU_CMD_UPDATE_CURSOR);
        assert_eq!(cmd_up.pos.x, 50);
        assert_eq!(cmd_up.pos.y, 60);

        let cmd_mv = gpu.build_move_cursor_cmd(0, 80, 90);
        assert_eq!(cmd_mv.hdr.cmd_type, VIRTIO_GPU_CMD_MOVE_CURSOR);
        assert_eq!(cmd_mv.pos.x, 80);
        assert_eq!(cmd_mv.pos.y, 90);

        // 5. Test de DirtyRectTracker
        let mut tracker = DirtyRectTracker::new(1920, 1080);
        assert!(!tracker.has_dirty);
        assert_eq!(tracker.take_dirty_rect(), None);

        // Marquer deux rectangles disjoints
        tracker.mark_rect(VirtioGpuRect {
            x: 10,
            y: 20,
            width: 30,
            height: 40,
        });
        tracker.mark_rect(VirtioGpuRect {
            x: 100,
            y: 150,
            width: 50,
            height: 60,
        });

        assert!(tracker.has_dirty);
        let union_rect = tracker.take_dirty_rect().expect("dirty rect présent");
        assert_eq!(union_rect.x, 10);
        assert_eq!(union_rect.y, 20);
        assert_eq!(union_rect.width, (100 + 50) - 10); // 140
        assert_eq!(union_rect.height, (150 + 60) - 20); // 190
        assert!(!tracker.has_dirty);

        // 6. Flush des zones modifiées sur le driver
        gpu.dirty_tracker.mark_rect(VirtioGpuRect {
            x: 0,
            y: 0,
            width: 64,
            height: 64,
        });
        let res = gpu.flush_dirty_regions().expect("flush dirty ok");
        assert!(res.is_some());
        assert_eq!(gpu.frames_flushed, 1);
        assert_eq!(gpu.bytes_transferred, 64 * 64 * 4);
    }

    #[test]
    fn test_virtio_gpu_edid_negotiation_and_pixel_conversion() {
        let mut gpu = VirtioGpuDriver::new(0, 1920, 1080);

        // 1. Test commande get_edid
        let cmd = gpu.build_get_edid_cmd(0);
        assert_eq!(cmd.hdr.cmd_type, VIRTIO_GPU_CMD_GET_EDID);
        assert_eq!(cmd.scanout, 0);

        // 2. Requête et parsing EDID
        let info = gpu.query_edid(0).expect("requête EDID réussie");
        assert!(info.valid);
        assert_eq!(&info.manufacturer_id, b"JMB");
        assert_eq!(info.product_code, 0x0001);
        assert_eq!(info.preferred_width, 1920);
        assert_eq!(info.preferred_height, 1080);
        assert_eq!(info.refresh_rate_hz, 60);

        // 3. Rejet d'un bloc EDID corrompu (en-tête invalide)
        let bad_edid = [0u8; 128];
        assert_eq!(
            gpu.parse_edid_block(&bad_edid),
            Err(SysError::InvalidArgument)
        );

        // 4. Rejet d'un bloc avec checksum corrompu
        let mut corrupted_chk = [0u8; 128];
        corrupted_chk[..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(
            gpu.parse_edid_block(&corrupted_chk),
            Err(SysError::InvalidArgument)
        );

        // 5. Test de changement de mode vidéo haute résolution
        let new_mode = VideoMode {
            width: 2560,
            height: 1440,
            refresh_hz: 60,
            format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
            pitch: 2560 * 4,
        };
        assert!(gpu.set_video_mode(new_mode).is_ok());
        assert_eq!(gpu.width, 2560);
        assert_eq!(gpu.height, 1440);
        assert_eq!(gpu.pixel_format, VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM);
        assert!(gpu.dirty_tracker.has_dirty);
        assert_eq!(gpu.dirty_tracker.dirty_area(), 2560 * 1440);

        // 6. Test de conversion de format de pixels (RGBA <-> BGRA)
        let src_rgba = [
            0x11, 0x22, 0x33, 0xFF, // Pixel 0: R=0x11, G=0x22, B=0x33, A=0xFF
            0xAA, 0xBB, 0xCC, 0x80, // Pixel 1: R=0xAA, G=0xBB, B=0xCC, A=0x80
        ];
        let mut dst_bgra = [0u8; 8];

        let converted = convert_pixel_format(
            VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            &src_rgba,
            &mut dst_bgra,
        )
        .expect("conversion de pixel ok");

        assert_eq!(converted, 8);
        // Doit inverser R et B en gardant G et A intacts
        assert_eq!(
            dst_bgra,
            [
                0x33, 0x22, 0x11, 0xFF, // B=0x33, G=0x22, R=0x11, A=0xFF
                0xCC, 0xBB, 0xAA, 0x80, // B=0xCC, G=0xBB, R=0xAA, A=0x80
            ]
        );

        // 7. Reconversion symétrique
        let mut restored_rgba = [0u8; 8];
        let _ = convert_pixel_format(
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
            VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
            &dst_bgra,
            &mut restored_rgba,
        );
        assert_eq!(restored_rgba, src_rgba);
    }
}
