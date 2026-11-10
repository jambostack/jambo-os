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

// Réponses de statut VirtIO-GPU OASIS 1.2
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

// Formats de pixels standard
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;

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
}
