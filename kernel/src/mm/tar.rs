//! Décodeur d'archive TAR / UStar zéro-allocation en `#![no_std]`
//!
//! Permet au micro-noyau d'extraire les fichiers et exécutables ELF
//! depuis l'archive d'amorçage Initrd passée en module par Limine.

/// Entrée de fichier dans l'archive TAR
#[derive(Debug, Clone, Copy)]
pub struct TarEntry<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

/// Archive TAR en mémoire
pub struct TarArchive<'a> {
    bytes: &'a [u8],
}

impl<'a> TarArchive<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Recherche un fichier par nom ou suffixe de nom (ex: "init" ou "bin/init")
    pub fn find(&self, filename: &str) -> Option<&'a [u8]> {
        for entry in self.entries() {
            if entry.name == filename || entry.name.ends_with(filename) {
                return Some(entry.data);
            }
        }
        None
    }

    /// Itérateur sur toutes les entrées de l'archive
    pub fn entries(&self) -> TarIterator<'a> {
        TarIterator {
            bytes: self.bytes,
            offset: 0,
        }
    }
}

/// Itérateur d'entrées TAR
pub struct TarIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for TarIterator<'a> {
    type Item = TarEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset + 512 <= self.bytes.len() {
            let header = &self.bytes[self.offset..self.offset + 512];
            // Deux blocs de zéros consécutifs ou premier octet nul indiquent la fin
            if header[0] == 0 {
                return None;
            }

            // Nom du fichier (100 octets max, terminé par nul)
            let name_end = header[0..100].iter().position(|&b| b == 0).unwrap_or(100);
            let name = core::str::from_utf8(&header[0..name_end]).unwrap_or("");

            // Taille du fichier (octal ASCII, 12 octets à l'offset 124)
            let size_slice = &header[124..136];
            let mut size: usize = 0;
            for &b in size_slice {
                if b >= b'0' && b <= b'7' {
                    size = size * 8 + (b - b'0') as usize;
                } else if b == 0 || b == b' ' {
                    // Fin du champ octal
                    break;
                }
            }

            self.offset += 512;
            if self.offset + size > self.bytes.len() {
                return None;
            }

            let data = &self.bytes[self.offset..self.offset + size];
            // Les fichiers sont alignés sur un multiple de 512 octets
            self.offset += (size + 511) & !511;

            if !name.is_empty() {
                return Some(TarEntry { name, data });
            }
        }
        None
    }
}
