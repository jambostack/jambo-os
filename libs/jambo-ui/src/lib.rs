//! Framework d'interface graphique déclarative (JamboUI) et Terminal (JamboTerm)
//!
//! Intègre un arbre d'accessibilité obligatoire pour tous les composants
//! interactifs, le rendu vectoriel 2D et le terminal graphique accéléré.

#![no_std]

/// Couleur RGBA 32 bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);
    pub const ACCENT: Self = Self::rgb(0, 168, 150);
}

/// Rôle d'un nœud dans l'arbre d'accessibilité
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibilityRole {
    Window,
    Button,
    Label,
    Terminal,
    Container,
}

/// Nœud d'accessibilité obligatoire pour les lecteurs d'écran et l'assistance
#[derive(Debug, Clone, Copy)]
pub struct AccessibilityNode {
    pub id: u32,
    pub role: AccessibilityRole,
    pub label: &'static str,
    pub focusable: bool,
    pub focused: bool,
}

/// Bouton déclaratif JamboUI
#[derive(Debug, Clone, Copy)]
pub struct Button {
    pub text: &'static str,
    pub width: u32,
    pub height: u32,
    pub background: Color,
    pub accessibility: AccessibilityNode,
}

impl Button {
    pub const fn new(id: u32, text: &'static str, width: u32, height: u32) -> Self {
        Self {
            text,
            width,
            height,
            background: Color::ACCENT,
            accessibility: AccessibilityNode {
                id,
                role: AccessibilityRole::Button,
                label: text,
                focusable: true,
                focused: false,
            },
        }
    }
}

/// Terminal graphique interactif JamboTerm
pub struct JamboTerm {
    pub cols: usize,
    pub rows: usize,
    pub cursor_col: usize,
    pub cursor_row: usize,
    pub grid: [[char; 80]; 25],
    pub accessibility: AccessibilityNode,
}

impl Default for JamboTerm {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboTerm {
    pub const fn new() -> Self {
        Self {
            cols: 80,
            rows: 25,
            cursor_col: 0,
            cursor_row: 0,
            grid: [[' '; 80]; 25],
            accessibility: AccessibilityNode {
                id: 1,
                role: AccessibilityRole::Terminal,
                label: "Terminal Interactif JamboTerm",
                focusable: true,
                focused: true,
            },
        }
    }

    /// Écrit une chaîne de caractères dans le terminal graphique
    pub fn write_str(&mut self, text: &str) {
        for c in text.chars() {
            if c == '\n' {
                self.cursor_col = 0;
                self.cursor_row = (self.cursor_row + 1).min(self.rows - 1);
            } else if self.cursor_col < self.cols && self.cursor_row < self.rows {
                self.grid[self.cursor_row][self.cursor_col] = c;
                self.cursor_col += 1;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row = (self.cursor_row + 1).min(self.rows - 1);
                }
            }
        }
    }

    /// Vérifie la présence obligatoire de l'arbre d'accessibilité
    pub fn accessibility_node(&self) -> &AccessibilityNode {
        &self.accessibility
    }
}
