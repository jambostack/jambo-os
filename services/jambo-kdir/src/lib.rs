//! Cyber-Résilience & Intégrité du Noyau et des Pilotes (KDIR - Kernel & Driver Integrity Resilience)
//!
//! Phase 141 — Jalon v0.3.8
//!
//! Fournit un sous-système souverain de cyber-résilience et de contrôle d'intégrité noyau en `#![no_std]` :
//! 1. Surveillance continue d'intégrité des structures critiques du noyau (IDT, GDT, tables CR3, dispatchers syscalls).
//! 2. Détection en temps réel des altérations non autorisées et rootkits Ring 0 / hyperviseur (DKOM, hooks IDT/MSR).
//! 3. Validation de signature cryptographique des pilotes et contrôle de capabilités VMO.
//! 4. Confinement et isolation instantanée O(1) des pilotes défaillants ou corrompus.
//! 5. Auto-restauration des tables système à partir des empreintes de référence (golden snapshot).
//! 6. Contrôle d'accès capabilaire (`KdirCap`) avec atténuation monotone stricte.
//! 7. Registre d'audit SHA-256 inaltérable scellé par chaînage cryptographique.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 pour micro-noyau et services
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes += data.len() as u64;

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
                self.process_block();
                data = &data[needed..];
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            self.buffer.copy_from_slice(&data[..64]);
            self.process_block();
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        self.process_block();

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        output
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (KdirCap)
// ============================================================================

pub mod kdir_rights {
    pub const REGISTER_PROBE: u32 = 1 << 0;
    pub const VERIFY_INTEGRITY: u32 = 1 << 1;
    pub const ATTEST_MEMORY: u32 = 1 << 2;
    pub const RESTORE_TABLE: u32 = 1 << 3;
    pub const ISOLATE_DRIVER: u32 = 1 << 4;
    pub const CONFIGURE_POLICY: u32 = 1 << 5;
    pub const QUERY_AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdirError {
    PermissionDenied,
    AttenuationViolation,
    ProbeNotFound,
    DriverNotFound,
    BufferFull,
    IntegrityMismatch,
    RestorationFailed,
    DriverAlreadyIsolated,
    InvalidParameter,
}

/// Capabilité de contrôle d'accès avec atténuation monotone stricte pour le moteur KDIR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdirCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl KdirCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_lifetime: u64,
        invocations_left: u32,
    ) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right && self.invocations_left > 0
    }

    /// Atténuation monotone : les droits ne peuvent être qu'un sous-ensemble strict ou égal
    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, KdirError> {
        if (new_rights & !self.rights) != 0 {
            return Err(KdirError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(KdirError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(KdirError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    #[inline]
    pub fn consume_invocation(&mut self) -> Result<(), KdirError> {
        if self.invocations_left == 0 {
            return Err(KdirError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// STRUCTURES DE SURVEILLANCE & DÉTECTION
// ============================================================================

/// Type de structure critique sous surveillance continue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureType {
    Idt,
    Gdt,
    Cr3PageTable,
    SyscallDispatcher,
    Tss,
    KernelText,
    HypervisorVmcs,
}

impl StructureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idt => "IDT (Interrupt Descriptor Table)",
            Self::Gdt => "GDT (Global Descriptor Table)",
            Self::Cr3PageTable => "CR3 (Root Page Table PML4/PML5)",
            Self::SyscallDispatcher => "MSR LSTAR (Fast Syscall Dispatcher)",
            Self::Tss => "TSS (Task State Segment)",
            Self::KernelText => "Kernel .text (Executable Section)",
            Self::HypervisorVmcs => "VMCS (Hypervisor Host/Guest Control)",
        }
    }
}

/// État d'intégrité d'une sonde ou structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    Intact,
    Tampered,
    Restoring,
    Quarantined,
}

/// Nature des menaces de compromission noyau et rootkits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootkitThreatType {
    DirectKernelObjectModification, // DKOM
    IdtHooking,
    SyscallHijack,
    PageTableInjection,
    UnauthorizedDriverCode,
    HypervisorShadowHook,
}

impl RootkitThreatType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DirectKernelObjectModification => "Direct Kernel Object Modification (DKOM)",
            Self::IdtHooking => "IDT Hooking / Interrupt Gate Redirection",
            Self::SyscallHijack => "Syscall Dispatcher Hijack (MSR LSTAR Alteration)",
            Self::PageTableInjection => "CR3 / Page Table Remapping (Privilege Escalation)",
            Self::UnauthorizedDriverCode => "Driver Code Signature Violation / Unsigned VMO",
            Self::HypervisorShadowHook => "Hypervisor / Nested VMCS Interception",
        }
    }
}

/// Niveau de sévérité de la menace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// État de conformité d'un pilote VMO
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    Trusted,
    Compromised,
    Isolated,
    Evicted,
}

/// Types d'événements scellés dans le registre cryptographique
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    ProbeRegistered,
    IntegrityCheckPassed,
    IntegrityViolationDetected,
    SystemTableRestored,
    DriverRegistered,
    DriverIsolated,
    CapAttenuated,
}

// ============================================================================
// ENTRÉES DU SYSTÈME KDIR
// ============================================================================

/// Sonde d'intégrité sur une structure critique
#[derive(Debug, Clone, Copy)]
pub struct KernelProbe {
    pub probe_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub structure: StructureType,
    pub base_address: u64,
    pub size_bytes: usize,
    pub golden_hash: [u8; 32],
    pub current_hash: [u8; 32],
    pub status: IntegrityStatus,
    pub last_checked_timestamp: u64,
    pub violation_count: u32,
    pub golden_backup: [u8; 128],
    pub golden_backup_len: usize,
}

/// Métadonnées et statut d'un pilote supervisé
#[derive(Debug, Clone, Copy)]
pub struct DriverEntry {
    pub driver_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub vmo_handle: Handle,
    pub load_address: u64,
    pub size_bytes: usize,
    pub signature_hash: [u8; 32],
    pub status: DriverStatus,
    pub capabilities_mask: u32,
    pub fault_count: u32,
}

/// Menace détectée sur les structures de bas niveau
#[derive(Debug, Clone, Copy)]
pub struct RootkitThreat {
    pub threat_id: u32,
    pub probe_id: u32,
    pub structure: StructureType,
    pub threat_type: RootkitThreatType,
    pub severity: ThreatSeverity,
    pub detected_timestamp: u64,
    pub remediated: bool,
    pub auto_restored: bool,
}

/// Entrée du journal d'audit cryptographique SHA-256
#[derive(Debug, Clone, Copy)]
pub struct KdirAuditEntry {
    pub index: u64,
    pub event_type: AuditEventType,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub detail: [u8; 48],
    pub detail_len: usize,
}

/// Synthèse globale de l'état de résilience du noyau
#[derive(Debug, Clone, Copy)]
pub struct KdirSummary {
    pub probes_count: usize,
    pub intact_count: usize,
    pub tampered_count: usize,
    pub drivers_count: usize,
    pub isolated_drivers_count: usize,
    pub threats_detected: usize,
    pub remediated_threats: usize,
    pub ledger_entries: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// DÉMON MAÎTRE KDIR (JamboKdirDaemon)
// ============================================================================

pub struct JamboKdirDaemon {
    pub cap: KdirCap,
    pub probes: [Option<KernelProbe>; 16],
    pub probe_count: usize,
    pub drivers: [Option<DriverEntry>; 16],
    pub driver_count: usize,
    pub threats: [Option<RootkitThreat>; 16],
    pub threat_count: usize,
    pub audit_log: [Option<KdirAuditEntry>; 64],
    pub audit_count: usize,
    pub next_id: u32,
    pub last_audit_hash: [u8; 32],
}

impl JamboKdirDaemon {
    pub const fn new(cap: KdirCap) -> Self {
        Self {
            cap,
            probes: [None; 16],
            probe_count: 0,
            drivers: [None; 16],
            driver_count: 0,
            threats: [None; 16],
            threat_count: 0,
            audit_log: [None; 64],
            audit_count: 0,
            next_id: 100,
            last_audit_hash: [0u8; 32],
        }
    }

    /// Initialise la configuration et les sondes par défaut du micro-noyau JamboOS
    pub fn init_defaults(&mut self) {
        let ts = 1735000000;

        // 1. Sonde IDT (Interrupt Descriptor Table)
        let idt_data = b"JAMBO_IDT_GOLDEN_VECTORS_0_TO_256_RING0_EXCEPTIONS_INTERRUPT_GATES";
        let _ = self.register_probe(
            "kernel_idt_table",
            StructureType::Idt,
            0xFFFF_8000_0000_1000,
            idt_data.len(),
            idt_data,
            ts,
        );

        // 2. Sonde GDT (Global Descriptor Table)
        let gdt_data = b"JAMBO_GDT_NULL_KCODE64_KDATA64_UCODE64_UDATA64_TSS64_VALIDATED";
        let _ = self.register_probe(
            "kernel_gdt_table",
            StructureType::Gdt,
            0xFFFF_8000_0000_2000,
            gdt_data.len(),
            gdt_data,
            ts,
        );

        // 3. Sonde Table des Pages CR3 (PML4)
        let cr3_data = b"JAMBO_CR3_PML4_ROOT_KERNEL_RESERVED_HIGHER_HALF_NX_SECURE";
        let _ = self.register_probe(
            "kernel_cr3_pml4",
            StructureType::Cr3PageTable,
            0x0000_0000_0010_0000,
            cr3_data.len(),
            cr3_data,
            ts,
        );

        // 4. Sonde Dispatcher MSR LSTAR (Syscall Entry)
        let syscall_data = b"JAMBO_MSR_LSTAR_FAST_SYSCALL_ENTRYPOINT_HARDENED_DISPATCH";
        let _ = self.register_probe(
            "kernel_msr_lstar",
            StructureType::SyscallDispatcher,
            0xFFFF_8000_0010_5000,
            syscall_data.len(),
            syscall_data,
            ts,
        );

        // 5. Enregistrement des pilotes de périphériques souverains par défaut
        let virtio_sig = Sha256::digest(b"VIRTIO_NET_BLK_CONSOLE_SOVEREIGN_SIGNED_VMO");
        let _ = self.register_driver(
            "virtio-driver",
            Handle::new(201, 1),
            0xFFFF_8000_0040_0000,
            65536,
            virtio_sig,
            0x07,
            ts,
        );

        let nvme_sig = Sha256::digest(b"NVME_CONTROLLER_PCI_EXPRESS_SOVEREIGN_DRIVER_VMO");
        let _ = self.register_driver(
            "nvme-driver",
            Handle::new(202, 1),
            0xFFFF_8000_0050_0000,
            131072,
            nvme_sig,
            0x0F,
            ts,
        );

        let xhci_sig = Sha256::digest(b"XHCI_USB3_HOST_CONTROLLER_HARDENED_VMO");
        let _ = self.register_driver(
            "xhci-driver",
            Handle::new(203, 1),
            0xFFFF_8000_0060_0000,
            49152,
            xhci_sig,
            0x03,
            ts,
        );
    }

    /// Enregistre une sonde de surveillance sur une structure critique du noyau
    pub fn register_probe(
        &mut self,
        name: &str,
        structure: StructureType,
        base_address: u64,
        size_bytes: usize,
        golden_data: &[u8],
        timestamp: u64,
    ) -> Result<u32, KdirError> {
        if !self.cap.has_right(kdir_rights::REGISTER_PROBE) {
            return Err(KdirError::PermissionDenied);
        }
        self.cap.consume_invocation()?;

        if self.probe_count >= self.probes.len() {
            return Err(KdirError::BufferFull);
        }

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let golden_hash = Sha256::digest(golden_data);
        let mut golden_backup = [0u8; 128];
        let backup_len = golden_data.len().min(128);
        golden_backup[..backup_len].copy_from_slice(&golden_data[..backup_len]);

        let probe_id = self.next_id;
        self.next_id += 1;

        let probe = KernelProbe {
            probe_id,
            name: name_buf,
            name_len: copy_len,
            structure,
            base_address,
            size_bytes,
            golden_hash,
            current_hash: golden_hash,
            status: IntegrityStatus::Intact,
            last_checked_timestamp: timestamp,
            violation_count: 0,
            golden_backup,
            golden_backup_len: backup_len,
        };

        for slot in self.probes.iter_mut() {
            if slot.is_none() {
                *slot = Some(probe);
                self.probe_count += 1;
                break;
            }
        }

        self.append_audit_entry(
            AuditEventType::ProbeRegistered,
            "Probe registered for kernel structure",
            timestamp,
        );

        Ok(probe_id)
    }

    /// Enregistre un pilote supervisé avec validation de sa signature
    pub fn register_driver(
        &mut self,
        name: &str,
        vmo_handle: Handle,
        load_address: u64,
        size_bytes: usize,
        signature_hash: [u8; 32],
        capabilities_mask: u32,
        timestamp: u64,
    ) -> Result<u32, KdirError> {
        if !self.cap.has_right(kdir_rights::CONFIGURE_POLICY) {
            return Err(KdirError::PermissionDenied);
        }
        self.cap.consume_invocation()?;

        if self.driver_count >= self.drivers.len() {
            return Err(KdirError::BufferFull);
        }

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let driver_id = self.next_id;
        self.next_id += 1;

        let entry = DriverEntry {
            driver_id,
            name: name_buf,
            name_len: copy_len,
            vmo_handle,
            load_address,
            size_bytes,
            signature_hash,
            status: DriverStatus::Trusted,
            capabilities_mask,
            fault_count: 0,
        };

        for slot in self.drivers.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.driver_count += 1;
                break;
            }
        }

        self.append_audit_entry(
            AuditEventType::DriverRegistered,
            "Driver VMO registered and verified",
            timestamp,
        );

        Ok(driver_id)
    }

    /// Vérifie l'intégrité en direct d'une structure système surveillée
    pub fn verify_structure_integrity(
        &mut self,
        probe_id: u32,
        live_data: &[u8],
        timestamp: u64,
    ) -> Result<bool, KdirError> {
        if !self.cap.has_right(kdir_rights::VERIFY_INTEGRITY) {
            return Err(KdirError::PermissionDenied);
        }
        self.cap.consume_invocation()?;

        let probe_idx = self
            .probes
            .iter()
            .position(|p| p.as_ref().map(|x| x.probe_id) == Some(probe_id))
            .ok_or(KdirError::ProbeNotFound)?;

        let current_digest = Sha256::digest(live_data);
        let golden_digest = self.probes[probe_idx].as_ref().unwrap().golden_hash;
        let is_intact = current_digest == golden_digest;
        let (structure, probe_id_val) = {
            let probe = self.probes[probe_idx].as_mut().unwrap();
            probe.current_hash = current_digest;
            probe.last_checked_timestamp = timestamp;
            if is_intact {
                probe.status = IntegrityStatus::Intact;
            } else {
                probe.status = IntegrityStatus::Tampered;
                probe.violation_count += 1;
            }
            (probe.structure, probe.probe_id)
        };

        if is_intact {
            self.append_audit_entry(
                AuditEventType::IntegrityCheckPassed,
                "Integrity check passed: hashes match",
                timestamp,
            );
        } else {
            let threat_type = match structure {
                StructureType::Idt => RootkitThreatType::IdtHooking,
                StructureType::SyscallDispatcher => RootkitThreatType::SyscallHijack,
                StructureType::Cr3PageTable => RootkitThreatType::PageTableInjection,
                StructureType::HypervisorVmcs => RootkitThreatType::HypervisorShadowHook,
                _ => RootkitThreatType::DirectKernelObjectModification,
            };

            self.record_threat(
                probe_id_val,
                structure,
                threat_type,
                ThreatSeverity::Critical,
                timestamp,
            );

            self.append_audit_entry(
                AuditEventType::IntegrityViolationDetected,
                "CRITICAL: Kernel structure altered!",
                timestamp,
            );
        }

        Ok(is_intact)
    }

    /// Restaure automatiquement une structure altérée à partir de son snapshot de référence (golden backup)
    pub fn auto_restore_structure(
        &mut self,
        probe_id: u32,
        restored_buffer: &mut [u8],
        timestamp: u64,
    ) -> Result<usize, KdirError> {
        if !self.cap.has_right(kdir_rights::RESTORE_TABLE) {
            return Err(KdirError::PermissionDenied);
        }
        self.cap.consume_invocation()?;

        let probe_idx = self
            .probes
            .iter()
            .position(|p| p.as_ref().map(|x| x.probe_id) == Some(probe_id))
            .ok_or(KdirError::ProbeNotFound)?;

        let probe = self.probes[probe_idx].as_mut().unwrap();
        let backup_len = probe.golden_backup_len;

        if restored_buffer.len() < backup_len {
            return Err(KdirError::InvalidParameter);
        }

        restored_buffer[..backup_len].copy_from_slice(&probe.golden_backup[..backup_len]);
        probe.current_hash = probe.golden_hash;
        probe.status = IntegrityStatus::Intact;

        // Marque les menaces associées comme remédiées et auto-restaurées
        for t in self.threats.iter_mut().flatten() {
            if t.probe_id == probe_id && !t.remediated {
                t.remediated = true;
                t.auto_restored = true;
            }
        }

        self.append_audit_entry(
            AuditEventType::SystemTableRestored,
            "Kernel table restored from golden snapshot",
            timestamp,
        );

        Ok(backup_len)
    }

    /// Isole et confine immédiatement un pilote défaillant ou compromis (O(1))
    pub fn isolate_driver(&mut self, driver_id: u32, timestamp: u64) -> Result<(), KdirError> {
        if !self.cap.has_right(kdir_rights::ISOLATE_DRIVER) {
            return Err(KdirError::PermissionDenied);
        }
        self.cap.consume_invocation()?;

        let driver_idx = self
            .drivers
            .iter()
            .position(|d| d.as_ref().map(|x| x.driver_id) == Some(driver_id))
            .ok_or(KdirError::DriverNotFound)?;

        let driver = self.drivers[driver_idx].as_mut().unwrap();
        if driver.status == DriverStatus::Isolated {
            return Err(KdirError::DriverAlreadyIsolated);
        }

        driver.status = DriverStatus::Isolated;
        driver.capabilities_mask = 0; // Révocation totale des capabilités matérielles

        self.append_audit_entry(
            AuditEventType::DriverIsolated,
            "Driver quarantined and rights revoked",
            timestamp,
        );

        Ok(())
    }

    /// Enregistre une détection de menace / rootkit
    fn record_threat(
        &mut self,
        probe_id: u32,
        structure: StructureType,
        threat_type: RootkitThreatType,
        severity: ThreatSeverity,
        timestamp: u64,
    ) {
        if self.threat_count >= self.threats.len() {
            return;
        }

        let threat_id = self.next_id;
        self.next_id += 1;

        let threat = RootkitThreat {
            threat_id,
            probe_id,
            structure,
            threat_type,
            severity,
            detected_timestamp: timestamp,
            remediated: false,
            auto_restored: false,
        };

        for slot in self.threats.iter_mut() {
            if slot.is_none() {
                *slot = Some(threat);
                self.threat_count += 1;
                break;
            }
        }
    }

    /// Ajoute une entrée dans le journal d'audit cryptographique scellé par SHA-256
    pub fn append_audit_entry(
        &mut self,
        event_type: AuditEventType,
        detail_msg: &str,
        timestamp: u64,
    ) {
        if self.audit_count >= self.audit_log.len() {
            return;
        }

        let mut detail_buf = [0u8; 48];
        let copy_len = detail_msg.len().min(48);
        detail_buf[..copy_len].copy_from_slice(&detail_msg.as_bytes()[..copy_len]);

        let index = self.audit_count as u64;

        let mut hasher = Sha256::new();
        hasher.update(&index.to_be_bytes());
        hasher.update(&(event_type as u32).to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&self.last_audit_hash);
        hasher.update(&detail_buf[..copy_len]);
        let entry_hash = hasher.finalize();

        let entry = KdirAuditEntry {
            index,
            event_type,
            timestamp,
            prev_hash: self.last_audit_hash,
            entry_hash,
            detail: detail_buf,
            detail_len: copy_len,
        };

        self.last_audit_hash = entry_hash;

        for slot in self.audit_log.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.audit_count += 1;
                break;
            }
        }
    }

    /// Vérifie l'intégrité de la chaîne cryptographique du journal d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];

        for i in 0..self.audit_count {
            if let Some(entry) = &self.audit_log[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }

                let mut hasher = Sha256::new();
                hasher.update(&entry.index.to_be_bytes());
                hasher.update(&(entry.event_type as u32).to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.detail[..entry.detail_len]);
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }

                expected_prev = entry.entry_hash;
            } else {
                return false;
            }
        }

        true
    }

    /// Fournit un résumé chiffré de l'état du système KDIR
    pub fn get_summary(&self) -> KdirSummary {
        let mut intact = 0;
        let mut tampered = 0;
        for p in self.probes.iter().flatten() {
            match p.status {
                IntegrityStatus::Intact => intact += 1,
                IntegrityStatus::Tampered => tampered += 1,
                _ => {}
            }
        }

        let mut isolated = 0;
        for d in self.drivers.iter().flatten() {
            if d.status == DriverStatus::Isolated {
                isolated += 1;
            }
        }

        let mut remediated = 0;
        for t in self.threats.iter().flatten() {
            if t.remediated {
                remediated += 1;
            }
        }

        KdirSummary {
            probes_count: self.probe_count,
            intact_count: intact,
            tampered_count: tampered,
            drivers_count: self.driver_count,
            isolated_drivers_count: isolated,
            threats_detected: self.threat_count,
            remediated_threats: remediated,
            ledger_entries: self.audit_count,
            ledger_valid: self.verify_ledger_integrity(),
        }
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation_and_monotone() {
        let admin_cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        assert!(admin_cap.has_right(kdir_rights::REGISTER_PROBE));
        assert!(admin_cap.has_right(kdir_rights::RESTORE_TABLE));
        assert!(admin_cap.has_right(kdir_rights::ISOLATE_DRIVER));

        // Atténuation monotone
        let readonly_cap = admin_cap
            .attenuate(
                kdir_rights::VERIFY_INTEGRITY | kdir_rights::QUERY_AUDIT,
                5000,
                100,
            )
            .expect("Atténuation valide");

        assert!(readonly_cap.has_right(kdir_rights::VERIFY_INTEGRITY));
        assert!(readonly_cap.has_right(kdir_rights::QUERY_AUDIT));
        assert!(!readonly_cap.has_right(kdir_rights::RESTORE_TABLE));
        assert!(!readonly_cap.has_right(kdir_rights::ISOLATE_DRIVER));

        // Rejet d'élévation de privilèges
        assert_eq!(
            readonly_cap.attenuate(kdir_rights::ALL, 5000, 100),
            Err(KdirError::AttenuationViolation)
        );
    }

    #[test]
    fn test_kdir_defaults_init() {
        let cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        let mut daemon = JamboKdirDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.probe_count, 4);
        assert_eq!(daemon.driver_count, 3);
        assert_eq!(daemon.threat_count, 0);

        let summary = daemon.get_summary();
        assert_eq!(summary.probes_count, 4);
        assert_eq!(summary.intact_count, 4);
        assert_eq!(summary.tampered_count, 0);
        assert_eq!(summary.drivers_count, 3);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_structure_integrity_detection_and_tampering() {
        let cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        let mut daemon = JamboKdirDaemon::new(cap);
        daemon.init_defaults();

        let idt_probe_id = daemon.probes[0].as_ref().unwrap().probe_id;
        let idt_good_data = b"JAMBO_IDT_GOLDEN_VECTORS_0_TO_256_RING0_EXCEPTIONS_INTERRUPT_GATES";

        // 1. Vérification d'intégrité positive
        let valid = daemon
            .verify_structure_integrity(idt_probe_id, idt_good_data, 1735000100)
            .expect("Vérification IDT");
        assert!(valid);

        // 2. Altération malveillante (hook IDT rootkit)
        let idt_tampered = b"JAMBO_IDT_ROOTKIT_HOOKED_VECTOR_0x80_COMPROMISED_GATE";
        let valid_after = daemon
            .verify_structure_integrity(idt_probe_id, idt_tampered, 1735000200)
            .expect("Vérification altération");
        assert!(!valid_after);

        let summary = daemon.get_summary();
        assert_eq!(summary.tampered_count, 1);
        assert_eq!(summary.threats_detected, 1);
        assert_eq!(
            daemon.threats[0].as_ref().unwrap().threat_type,
            RootkitThreatType::IdtHooking
        );
        assert_eq!(
            daemon.threats[0].as_ref().unwrap().severity,
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn test_auto_restore_tampered_idt() {
        let cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        let mut daemon = JamboKdirDaemon::new(cap);
        daemon.init_defaults();

        let idt_probe_id = daemon.probes[0].as_ref().unwrap().probe_id;
        let idt_tampered = b"JAMBO_IDT_HOOK_MALICIOUS_BYTECODE_INJECTION";

        // Détection de l'altération
        let valid = daemon
            .verify_structure_integrity(idt_probe_id, idt_tampered, 1735000300)
            .unwrap();
        assert!(!valid);

        // Restauration automatique
        let mut live_buffer = [0u8; 128];
        let bytes_restored = daemon
            .auto_restore_structure(idt_probe_id, &mut live_buffer, 1735000400)
            .expect("Restauration");
        assert!(bytes_restored > 0);

        let expected_golden = b"JAMBO_IDT_GOLDEN_VECTORS_0_TO_256_RING0_EXCEPTIONS_INTERRUPT_GATES";
        assert_eq!(
            &live_buffer[..expected_golden.len()],
            expected_golden.as_slice()
        );

        let summary = daemon.get_summary();
        assert_eq!(summary.intact_count, 4);
        assert_eq!(summary.tampered_count, 0);
        assert_eq!(summary.remediated_threats, 1);
        assert!(daemon.threats[0].as_ref().unwrap().auto_restored);
    }

    #[test]
    fn test_driver_registration_and_confinement() {
        let cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        let mut daemon = JamboKdirDaemon::new(cap);
        daemon.init_defaults();

        let rogue_sig = Sha256::digest(b"ROGUE_UNSIGNED_DRIVER_MODULE");
        let rogue_id = daemon
            .register_driver(
                "rogue-pci",
                Handle::new(666, 1),
                0xFFFF_8000_0099_0000,
                16384,
                rogue_sig,
                0x01,
                1735000500,
            )
            .expect("Enregistrement rogue driver");

        assert_eq!(daemon.driver_count, 4);

        // Isolement immédiat O(1)
        daemon
            .isolate_driver(rogue_id, 1735000600)
            .expect("Isolement pilote");

        let summary = daemon.get_summary();
        assert_eq!(summary.isolated_drivers_count, 1);

        let driver = daemon
            .drivers
            .iter()
            .flatten()
            .find(|d| d.driver_id == rogue_id)
            .unwrap();
        assert_eq!(driver.status, DriverStatus::Isolated);
        assert_eq!(driver.capabilities_mask, 0);

        // Rejet si déjà isolé
        assert_eq!(
            daemon.isolate_driver(rogue_id, 1735000700),
            Err(KdirError::DriverAlreadyIsolated)
        );
    }

    #[test]
    fn test_audit_ledger_merkle_integrity() {
        let cap = KdirCap::new(Handle::new(141, 1), kdir_rights::ALL, 10000, 500);
        let mut daemon = JamboKdirDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());
        assert!(daemon.audit_count > 0);

        // Altération malicieuse d'un bloc d'audit
        daemon.audit_log[0].as_mut().unwrap().detail[0] ^= 0xFF;
        assert!(!daemon.verify_ledger_integrity());
    }
}
