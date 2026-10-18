# Spécification de la Carte d'Adressage Virtuel 64 bits (x86-64)

La mémoire virtuelle de JamboOS sous pagination à 4 niveaux (PML4) est organisée de manière canonique stricte :

| Plage Virtuelle (Hex) | Taille | Description et Permissions |
|---|---|---|
| `0x0000_0000_0000_0000` - `0x0000_0000_003F_FFFF` | 4 Mio | **Zone de garde NULL** (Non mappée — trappe tout déréférencement NULL) |
| `0x0000_0000_0040_0000` - `0x0000_7FFF_FFFF_FFFF` | ~128 Tio | **Espace Utilisateur** (Code R-X, Données RW-, VMO, Piles avec Guard Pages) |
| *0x0000_8000_0000_0000* - *0xFFFF_7FFF_FFFF_FFFF* | ~16 Eio | **Trou Canonique (Non-Canonical Address Hole)** |
| `0xFFFF_8000_0000_0000` - `0xFFFF_BFFF_FFFF_FFFF` | 64 Tio | **Higher-Half Direct Map (HHDM)** — RAM physique projetée (RW-, NX, Global) |
| `0xFFFF_C000_0000_0000` - `0xFFFF_DFFF_FFFF_FFFF` | 32 Tio | **Tas Noyau** (SLUB Caches & Objets Noyau — RW-, NX) |
| `0xFFFF_E000_0000_0000` - `0xFFFF_EFFF_FFFF_FFFF` | 16 Tio | **Piles Noyau** (16 Kio + Guard Page 4 Kio par thread — RW-, NX) |
| `0xFFFF_F000_0000_0000` - `0xFFFF_FF7F_FFFF_FFFF` | ~15.5 Tio | **Projections MMIO Noyau** (APIC, IOMMU, Timers — RW-, NX, Uncached) |
| `0xFFFF_FFFF_8000_0000` - `0xFFFF_FFFF_FFFF_FFFF` | 2 Gio | **Image du Noyau JamboKernel** (`.text` R-X, `.rodata` R--, `.data`/`.bss` RW-) |
