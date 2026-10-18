use super::font::{BASIC_FONT, FONT_HEIGHT, FONT_WIDTH};
use core::fmt;
use spin::Mutex;

pub struct FramebufferConsole {
    base: *mut u8,
    width: usize,
    height: usize,
    pitch: usize,
    bpp: usize,
    cursor_x: usize,
    cursor_y: usize,
    fg_color: u32,
    bg_color: u32,
}

// SAFETY: La mémoire du Framebuffer GOP mappée par le bootloader est
// accessible en exclusivité via le verrou FramebufferConsole.
unsafe impl Send for FramebufferConsole {}
unsafe impl Sync for FramebufferConsole {}

impl FramebufferConsole {
    pub unsafe fn new(base: *mut u8, width: usize, height: usize, pitch: usize, bpp: u8) -> Self {
        let mut console = Self {
            base,
            width,
            height,
            pitch,
            bpp: (bpp as usize) / 8,
            cursor_x: 0,
            cursor_y: 0,
            fg_color: 0x00F0F0F0, // Blanc cassé
            bg_color: 0x000F172A, // Bleu nuit profond / ardoise
        };
        console.clear();
        console
    }

    #[inline]
    pub fn put_pixel(&mut self, x: usize, y: usize, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = y * self.pitch + x * self.bpp;
        // SAFETY: Offset validé par les bornes x < width et y < height.
        unsafe {
            let pixel_ptr = self.base.add(offset) as *mut u32;
            *pixel_ptr = color;
        }
    }

    pub fn clear(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.put_pixel(x, y, self.bg_color);
            }
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    pub fn scroll(&mut self) {
        let line_height = FONT_HEIGHT;
        let bytes_per_line = line_height * self.pitch;
        let total_bytes = self.height * self.pitch;

        if total_bytes > bytes_per_line {
            // SAFETY: Déplacement de blocs mémoire valides dans les limites du framebuffer.
            unsafe {
                core::ptr::copy(
                    self.base.add(bytes_per_line),
                    self.base,
                    total_bytes - bytes_per_line,
                );
            }
        }

        // Effacer la dernière ligne
        let start_y = self.height.saturating_sub(line_height);
        for y in start_y..self.height {
            for x in 0..self.width {
                self.put_pixel(x, y, self.bg_color);
            }
        }

        if self.cursor_y >= line_height {
            self.cursor_y -= line_height;
        }
    }

    pub fn draw_char(&mut self, x: usize, y: usize, c: char, fg: u32, bg: u32) {
        let ascii = c as usize;
        let glyph = if (32..128).contains(&ascii) {
            &BASIC_FONT[ascii - 32]
        } else {
            &BASIC_FONT[63 - 32] // '?'
        };

        for (row, byte) in glyph.iter().enumerate() {
            for col in 0..FONT_WIDTH {
                let color = if (byte & (0x80 >> col)) != 0 { fg } else { bg };
                self.put_pixel(x + col, y + row, color);
            }
        }
    }

    pub fn write_char(&mut self, c: char) {
        match c {
            '\n' => {
                self.cursor_x = 0;
                self.cursor_y += FONT_HEIGHT;
                if self.cursor_y + FONT_HEIGHT > self.height {
                    self.scroll();
                }
            }
            '\r' => {
                self.cursor_x = 0;
            }
            '\t' => {
                let next_tab = (self.cursor_x / (FONT_WIDTH * 4) + 1) * (FONT_WIDTH * 4);
                self.cursor_x = next_tab;
                if self.cursor_x + FONT_WIDTH > self.width {
                    self.write_char('\n');
                }
            }
            ch => {
                if self.cursor_x + FONT_WIDTH > self.width {
                    self.write_char('\n');
                }
                self.draw_char(
                    self.cursor_x,
                    self.cursor_y,
                    ch,
                    self.fg_color,
                    self.bg_color,
                );
                self.cursor_x += FONT_WIDTH;
            }
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }
}

impl fmt::Write for FramebufferConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

pub static FRAMEBUFFER: Mutex<Option<FramebufferConsole>> = Mutex::new(None);

pub fn init_framebuffer(base: *mut u8, width: usize, height: usize, pitch: usize, bpp: u8) {
    // SAFETY: Paramètres fournis par le chargeur UEFI Limine vérifiés.
    let console = unsafe { FramebufferConsole::new(base, width, height, pitch, bpp) };
    *FRAMEBUFFER.lock() = Some(console);
}
