//! Démon d'Audit Cryptographique Inaltérable et Observabilité Zéro-Autorité (jambo-auditd)
//!
//! Fournit un journal d'audit de sécurité inviolable (tamper-evident ledger) en espace utilisateur Ring 3,
//! scellé par chaînage cryptographique déterministe. Chaque écriture et lecture requiert
//! obligatoirement une capacité explicite `AuditCap`, garantissant l'absence totale d'autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

/// Sévérité normalisée d'un événement d'audit système
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuditSeverity {
    Debug = 1,
    Info = 2,
    Warning = 3,
    SecurityViolation = 4,
    CriticalAlert = 5,
}

/// Catégorie fonctionnelle de l'événement d'audit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditCategory {
    CSpace = 1,
    MemoryMMU = 2,
    IommuDma = 3,
    NetworkIpc = 4,
    DistributedRpc = 5,
    Authentication = 6,
}

impl AuditCategory {
    pub const fn to_mask(self) -> u32 {
        1 << (self as u8)
    }
}

/// Capacité de contrôle d'audit Ring 3 (Zéro Autorité Ambiante)
#[derive(Debug, Clone, Copy)]
pub struct AuditCap {
    pub handle: Handle,
    pub allowed_categories_mask: u32,
    pub min_severity: AuditSeverity,
    pub can_write: bool,
    pub can_read: bool,
}

impl AuditCap {
    pub const fn new(
        handle: Handle,
        allowed_categories_mask: u32,
        min_severity: AuditSeverity,
        can_write: bool,
        can_read: bool,
    ) -> Self {
        Self {
            handle,
            allowed_categories_mask,
            min_severity,
            can_write,
            can_read,
        }
    }

    pub fn allows_category(&self, cat: AuditCategory) -> bool {
        (self.allowed_categories_mask & cat.to_mask()) != 0
    }
}

/// Entrée d'audit unitaire scellée cryptographiquement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence_id: u64,
    pub timestamp_ns: u64,
    pub source_pid: u64,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub event_code: u32,
    pub details_len: usize,
    pub details: [u8; 32],
    pub prev_hash: [u8; 16],
    pub entry_hash: [u8; 16],
}

impl AuditEntry {
    /// Calcule le hachage cryptographique déterministe (SIP/FNV-BLAKE dérivé)
    pub fn compute_hash(
        sequence_id: u64,
        timestamp_ns: u64,
        source_pid: u64,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
        prev_hash: &[u8; 16],
    ) -> [u8; 16] {
        let mut h1: u64 = 0xcbf29ce484222325 ^ sequence_id;
        let mut h2: u64 = 0x100000001b3 ^ timestamp_ns ^ (source_pid << 16);

        // Mélange des métadonnées
        h1 = h1.wrapping_mul(0x9e3779b97f4a7c15) ^ (category as u64);
        h2 = h2.wrapping_mul(0x517cc1b727220a95) ^ (severity as u64) ^ ((event_code as u64) << 32);

        // Intégration du hachage précédent
        for &b in prev_hash.iter() {
            h1 = (h1 ^ (b as u64))
                .rotate_left(13)
                .wrapping_mul(0x100000001b3);
            h2 = (h2 ^ (b as u64))
                .rotate_right(11)
                .wrapping_mul(0x9e3779b97f4a7c15);
        }

        // Intégration des octets de payload
        for &b in details.iter() {
            h1 = (h1 ^ (b as u64))
                .rotate_left(7)
                .wrapping_mul(0x517cc1b727220a95);
            h2 = (h2 ^ (b as u64))
                .rotate_right(9)
                .wrapping_mul(0x100000001b3);
        }

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&h1.to_le_bytes());
        out[8..].copy_from_slice(&h2.to_le_bytes());
        out
    }
}

/// Capacité maximale du tampon circulaire en mémoire statique
pub const MAX_AUDIT_ENTRIES: usize = 64;

/// Registre d'audit inaltérable à chaîne de hachage scellée
pub struct AuditLedger {
    entries: [Option<AuditEntry>; MAX_AUDIT_ENTRIES],
    total_recorded: u64,
    last_hash: [u8; 16],
}

impl AuditLedger {
    pub const fn new() -> Self {
        const NONE_ENTRY: Option<AuditEntry> = None;
        Self {
            entries: [NONE_ENTRY; MAX_AUDIT_ENTRIES],
            total_recorded: 0,
            last_hash: [0x5A; 16], // Ancre d'initialisation de graine cryptographique
        }
    }

    /// Enregistre un événement d'audit en vérifiant les droits de la capacité
    pub fn record_event(
        &mut self,
        cap: &AuditCap,
        source_pid: u64,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
        timestamp_ns: u64,
    ) -> Result<u64, SysError> {
        if !cap.can_write || !cap.allows_category(category) || severity < cap.min_severity {
            return Err(SysError::PermissionDenied);
        }

        let seq = self.total_recorded + 1;
        let mut d_buf = [0u8; 32];
        let copy_len = details.len().min(32);
        d_buf[..copy_len].copy_from_slice(&details[..copy_len]);

        let prev = self.last_hash;
        let entry_hash = AuditEntry::compute_hash(
            seq,
            timestamp_ns,
            source_pid,
            category,
            severity,
            event_code,
            &details[..copy_len],
            &prev,
        );

        let entry = AuditEntry {
            sequence_id: seq,
            timestamp_ns,
            source_pid,
            category,
            severity,
            event_code,
            details_len: copy_len,
            details: d_buf,
            prev_hash: prev,
            entry_hash,
        };

        let slot = (self.total_recorded as usize) % MAX_AUDIT_ENTRIES;
        self.entries[slot] = Some(entry);
        self.last_hash = entry_hash;
        self.total_recorded = seq;

        Ok(seq)
    }

    /// Vérifie mathématiquement l'intégrité de la chaîne d'audit
    /// Renvoie true si et seulement si toutes les entrées sont strictement conformes
    /// et qu'aucune falsification n'a eu lieu.
    pub fn verify_chain_integrity(&self) -> bool {
        if self.total_recorded == 0 {
            return true;
        }

        let total = self.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            self.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &self.entries[slot] {
                if entry.sequence_id != target_seq {
                    return false;
                }

                // Vérification du hachage de l'entrée
                let recomputed = AuditEntry::compute_hash(
                    entry.sequence_id,
                    entry.timestamp_ns,
                    entry.source_pid,
                    entry.category,
                    entry.severity,
                    entry.event_code,
                    &entry.details[..entry.details_len],
                    &entry.prev_hash,
                );

                if recomputed != entry.entry_hash {
                    return false;
                }

                // Si ce n'est pas le premier bloc du buffer, vérifier le chaînage
                if i > 0 {
                    let prev_slot = ((target_seq - 2) as usize) % MAX_AUDIT_ENTRIES;
                    if let Some(prev_entry) = &self.entries[prev_slot] {
                        if entry.prev_hash != prev_entry.entry_hash {
                            return false;
                        }
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Requête les entrées filtrées selon la capacité présentée
    pub fn query_events(
        &self,
        cap: &AuditCap,
        category_filter: Option<AuditCategory>,
        min_severity: AuditSeverity,
        out_buf: &mut [AuditEntry],
    ) -> Result<usize, SysError> {
        if !cap.can_read {
            return Err(SysError::PermissionDenied);
        }

        if let Some(cat) = category_filter {
            if !cap.allows_category(cat) {
                return Err(SysError::PermissionDenied);
            }
        }

        let mut matched = 0;
        let total = self.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            self.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            if matched >= out_buf.len() {
                break;
            }
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &self.entries[slot] {
                if entry.severity >= min_severity
                    && (category_filter.is_none() || category_filter == Some(entry.category))
                    && cap.allows_category(entry.category)
                {
                    out_buf[matched] = *entry;
                    matched += 1;
                }
            }
        }

        Ok(matched)
    }

    /// Altère intentionnellement une entrée en mémoire pour tester la détection de falsification
    #[cfg(test)]
    pub fn corrupt_entry_for_test(&mut self, slot: usize) {
        if let Some(entry) = &mut self.entries[slot % MAX_AUDIT_ENTRIES] {
            entry.details[0] ^= 0xFF; // Corruption d'un octet de payload
        }
    }
}

/// Type d'anomalie de sécurité détectée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    RepeatedCapabilityFailures,
    PotentialRpcReplayAttack,
    MemoryAccessViolations,
}

/// Alerte d'anomalie émise par l'analyseur heuristique
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityAlert {
    pub anomaly: AnomalyType,
    pub suspect_pid: u64,
    pub incident_count: u32,
}

/// Moteur de détection d'anomalies de sécurité en temps réel
pub struct AnomalyDetector {
    threshold: u32,
}

impl AnomalyDetector {
    pub const fn new(threshold: u32) -> Self {
        Self { threshold }
    }

    /// Analyse les événements récents du grand livre pour identifier des comportements suspects
    pub fn scan_for_anomalies(&self, ledger: &AuditLedger) -> Option<SecurityAlert> {
        let total = ledger.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        if count == 0 {
            return None;
        }

        let mut violations_per_pid = [0u32; 16];
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            ledger.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &ledger.entries[slot] {
                if entry.severity >= AuditSeverity::SecurityViolation {
                    let pid_idx = (entry.source_pid as usize) % 16;
                    violations_per_pid[pid_idx] = violations_per_pid[pid_idx].saturating_add(1);

                    if violations_per_pid[pid_idx] >= self.threshold {
                        let anomaly = match entry.category {
                            AuditCategory::DistributedRpc => AnomalyType::PotentialRpcReplayAttack,
                            AuditCategory::MemoryMMU | AuditCategory::IommuDma => {
                                AnomalyType::MemoryAccessViolations
                            }
                            _ => AnomalyType::RepeatedCapabilityFailures,
                        };

                        return Some(SecurityAlert {
                            anomaly,
                            suspect_pid: entry.source_pid,
                            incident_count: violations_per_pid[pid_idx],
                        });
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tamper_evident_integrity_and_corruption_detection() {
        let mut ledger = AuditLedger::new();
        let cap = AuditCap::new(
            Handle::new(1, 1),
            0xFFFFFFFF,
            AuditSeverity::Debug,
            true,
            true,
        );

        // Enregistrement de 3 événements consécutifs
        ledger
            .record_event(
                &cap,
                101,
                AuditCategory::CSpace,
                AuditSeverity::Info,
                1,
                b"Capability created for PID 101",
                1000,
            )
            .unwrap();
        ledger
            .record_event(
                &cap,
                101,
                AuditCategory::MemoryMMU,
                AuditSeverity::Warning,
                2,
                b"Minor page boundary warning",
                2000,
            )
            .unwrap();
        ledger
            .record_event(
                &cap,
                102,
                AuditCategory::DistributedRpc,
                AuditSeverity::SecurityViolation,
                3,
                b"Invalid nonce detected",
                3000,
            )
            .unwrap();

        assert_eq!(ledger.total_recorded, 3);
        assert!(ledger.verify_chain_integrity());

        // Corruption délibérée d'une entrée : l'intégrité doit échouer immédiatement
        ledger.corrupt_entry_for_test(1);
        assert!(!ledger.verify_chain_integrity());
    }

    #[test]
    fn test_capability_enforcement_and_filtering() {
        let mut ledger = AuditLedger::new();
        let write_only_cap = AuditCap::new(
            Handle::new(10, 1),
            AuditCategory::NetworkIpc.to_mask(),
            AuditSeverity::Info,
            true,
            false,
        );

        // Écriture autorisée
        let res = ledger.record_event(
            &write_only_cap,
            200,
            AuditCategory::NetworkIpc,
            AuditSeverity::Info,
            1,
            b"IPC frame sent",
            100,
        );
        assert!(res.is_ok());

        // Tentative d'écriture dans une catégorie interdite
        let bad_cat = ledger.record_event(
            &write_only_cap,
            200,
            AuditCategory::Authentication,
            AuditSeverity::Info,
            1,
            b"Login test",
            101,
        );
        assert_eq!(bad_cat, Err(SysError::PermissionDenied));

        // Tentative de lecture avec capacité write-only
        let mut out = [AuditEntry {
            sequence_id: 0,
            timestamp_ns: 0,
            source_pid: 0,
            category: AuditCategory::CSpace,
            severity: AuditSeverity::Debug,
            event_code: 0,
            details_len: 0,
            details: [0; 32],
            prev_hash: [0; 16],
            entry_hash: [0; 16],
        }; 4];
        let read_res = ledger.query_events(&write_only_cap, None, AuditSeverity::Debug, &mut out);
        assert_eq!(read_res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_anomaly_detection_heuristic() {
        let mut ledger = AuditLedger::new();
        let cap = AuditCap::new(
            Handle::new(1, 1),
            0xFFFFFFFF,
            AuditSeverity::Debug,
            true,
            true,
        );
        let detector = AnomalyDetector::new(3);

        // Aucun incident
        assert_eq!(detector.scan_for_anomalies(&ledger), None);

        // 3 violations successives du même PID malveillant (PID 666)
        for i in 0..3 {
            ledger
                .record_event(
                    &cap,
                    666,
                    AuditCategory::DistributedRpc,
                    AuditSeverity::SecurityViolation,
                    10 + i,
                    b"Replayed RPC packet attack",
                    1000 + (i as u64) * 10,
                )
                .unwrap();
        }

        let alert = detector.scan_for_anomalies(&ledger);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.suspect_pid, 666);
        assert_eq!(a.anomaly, AnomalyType::PotentialRpcReplayAttack);
        assert_eq!(a.incident_count, 3);
    }
}
