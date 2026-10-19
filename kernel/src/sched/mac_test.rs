//! Module de validation du Mandat d'Accès Contrôlé (MAC) Multi-Niveaux MLS, Bell-LaPadula & Biba (Phase 89 - v0.2.87)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_mac::{
    compartments, mac_rights, AccessType, ClassificationLevel, IntegrityLevel, JamboMacDaemon,
    MacCap, MacDecision, MacLabel, MacViolationReason,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du démon MAC multi-niveaux MLS (Phase 89)
pub fn execute_mac_daemon_test() -> bool {
    kprintln!(
        "[MAC/TEST] Démarrage du test du Mandat d'Accès Contrôlé multi-niveaux MLS (Phase 89)..."
    );

    // 1. Contrôle d'accès capabilaire (MacCap) et rejet formel d'amplification
    let admin_cap = MacCap::new(Handle::new(8901, 1), mac_rights::ALL);
    assert!(admin_cap.has_right(mac_rights::MAC_READ));
    assert!(admin_cap.has_right(mac_rights::MAC_CHECK));
    assert!(admin_cap.has_right(mac_rights::MAC_LABEL));
    assert!(admin_cap.has_right(mac_rights::MAC_ENFORCE));
    assert!(admin_cap.has_right(mac_rights::MAC_DOWNGRADE));
    assert!(admin_cap.has_right(mac_rights::MAC_AUDIT));
    assert!(admin_cap.has_right(mac_rights::MAC_ADMIN));

    let read_only_cap = admin_cap
        .attenuate(mac_rights::MAC_READ | mac_rights::MAC_CHECK | mac_rights::MAC_AUDIT)
        .expect("attenuate MacCap to read/check/audit");
    assert!(read_only_cap.has_right(mac_rights::MAC_READ));
    assert!(read_only_cap.has_right(mac_rights::MAC_CHECK));
    assert!(read_only_cap.has_right(mac_rights::MAC_AUDIT));
    assert!(!read_only_cap.has_right(mac_rights::MAC_LABEL));
    assert!(!read_only_cap.has_right(mac_rights::MAC_DOWNGRADE));
    assert!(!read_only_cap.has_right(mac_rights::MAC_ADMIN));

    // Rejet formel de toute tentative d'élévation / amplification
    assert_eq!(
        read_only_cap.attenuate(mac_rights::MAC_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboMacDaemon::new(admin_cap);
    daemon.init_defaults();

    // Rejet d'enregistrement de sujet ou objet sans MAC_LABEL
    let test_label = MacLabel::new(
        ClassificationLevel::Confidential,
        compartments::NETWORK,
        IntegrityLevel::System,
    );
    assert_eq!(
        daemon.register_subject(&read_only_cap, 99, "UnauthorizedSub", test_label, 100),
        Err(SysError::PermissionDenied),
        "Enregistrement de sujet sans MAC_LABEL doit échouer"
    );
    assert_eq!(
        daemon.register_object(&read_only_cap, 99, "UnauthorizedObj", test_label, 100),
        Err(SysError::PermissionDenied),
        "Enregistrement d'objet sans MAC_LABEL doit échouer"
    );
    kprintln!("[MAC/CAP] Modèle de sécurité capabilaire MacCap et interdiction d'amplification validés");

    // 2. Validation du modèle Bell-LaPadula (Confidentialité) : NRU & NWD
    // Sujet 4 (UserShell: Unclassified, USER, User)
    // Objet 10 (/etc/master.key: TopSecret, CRYPTO|ADMIN, Trusted)
    let d1 = daemon.evaluate_access(4, 10, AccessType::Read, 1001);
    assert_eq!(
        d1,
        MacDecision::Denied(MacViolationReason::BlpNoReadUp),
        "Bell-LaPadula Simple Security (NRU) : Unclassified ne peut pas lire TopSecret"
    );

    // Sujet 1 (SystemInit: TopSecret, ALL, Trusted)
    // Objet 13 (/home/user/document.txt: Unclassified, USER, User)
    // Note Biba : SystemInit (Trusted) qui lit document.txt (User) viole Biba NRD (contamination) !
    let d2 = daemon.evaluate_access(1, 13, AccessType::Read, 1002);
    assert_eq!(
        d2,
        MacDecision::Denied(MacViolationReason::BibaNoReadDown),
        "Biba Simple Integrity (NRD) : Sujet Trusted ne peut pas lire objet d'intégrité User"
    );

    // Sujet 2 (CryptoEnclave: Secret, CRYPTO|ADMIN, Trusted)
    // Objet 10 (/etc/master.key: TopSecret, CRYPTO|ADMIN, Trusted)
    // Test NWD (No Write Down) : CryptoEnclave (Secret) peut écrire vers master.key (TopSecret)
    let d3 = daemon.evaluate_access(2, 10, AccessType::Write, 1003);
    assert_eq!(
        d3,
        MacDecision::Granted,
        "BLP Star Property (NWD) & Biba (NWU) : Secret/Trusted écrit vers TopSecret/Trusted"
    );

    // Test NWD échec : Sujet 2 (Secret) ne peut pas écrire vers Objet 14 (Unclassified)
    let d4 = daemon.evaluate_access(2, 14, AccessType::Write, 1004);
    assert_eq!(
        d4,
        MacDecision::Denied(MacViolationReason::BlpNoWriteDown),
        "BLP Star Property (NWD) : Sujet Secret ne peut pas écrire dans objet Unclassified"
    );
    kprintln!("[MAC/BLP] Règles Bell-LaPadula (No Read Up & No Write Down) validées");

    // 3. Validation du modèle Biba (Intégrité) : NRD & NWU
    // Sujet 5 (PublicWorker: Unclassified, NONE, Untrusted)
    // Objet 12 (/dev/net0: Confidential, NETWORK, System)
    // NWU : PublicWorker (Untrusted) ne peut pas écrire dans /dev/net0 (System)
    let d5 = daemon.evaluate_access(5, 12, AccessType::Write, 1005);
    assert_eq!(
        d5,
        MacDecision::Denied(MacViolationReason::BibaNoWriteUp),
        "Biba Star Integrity (NWU) : Sujet Untrusted ne peut pas écrire dans /dev/net0 (System)"
    );

    // Même niveau de classification (Unclassified) pour tester Biba NWU isolément
    let untrusted_sub = MacLabel::new(
        ClassificationLevel::Unclassified,
        compartments::NONE,
        IntegrityLevel::Untrusted,
    );
    let system_obj = MacLabel::new(
        ClassificationLevel::Unclassified,
        compartments::NONE,
        IntegrityLevel::System,
    );
    let d6 = JamboMacDaemon::check_rules(&untrusted_sub, &system_obj, AccessType::Write);
    assert_eq!(
        d6,
        MacDecision::Denied(MacViolationReason::BibaNoWriteUp),
        "Biba Star Integrity (NWU) : Sujet Untrusted ne peut pas corrompre objet System"
    );

    // Biba NRD isolément : Sujet System ne peut pas lire objet Untrusted
    let d7 = JamboMacDaemon::check_rules(&system_obj, &untrusted_sub, AccessType::Read);
    assert_eq!(
        d7,
        MacDecision::Denied(MacViolationReason::BibaNoReadDown),
        "Biba Simple Integrity (NRD) : Sujet System ne peut pas lire objet Untrusted"
    );
    kprintln!("[MAC/BIBA] Règles Biba (No Read Down & No Write Up) validées");

    // 4. Compartiments et Treillis de Sécurité (Lattice Dominance)
    let s_net = MacLabel::new(
        ClassificationLevel::Confidential,
        compartments::NETWORK,
        IntegrityLevel::System,
    );
    let o_crypto = MacLabel::new(
        ClassificationLevel::Confidential,
        compartments::CRYPTO,
        IntegrityLevel::System,
    );
    let d8 = JamboMacDaemon::check_rules(&s_net, &o_crypto, AccessType::Read);
    assert_eq!(
        d8,
        MacDecision::Denied(MacViolationReason::CompartmentMismatch),
        "Treillis : Incompatibilité stricte de compartiments NETWORK vs CRYPTO"
    );
    kprintln!("[MAC/LATTICE] Treillis de compartiments et isolation multi-domaines validés");

    // 5. Déclassification et abaissement contrôlés (MAC_DOWNGRADE)
    let downgrade_label = MacLabel::new(
        ClassificationLevel::Confidential,
        compartments::CRYPTO,
        IntegrityLevel::Trusted,
    );
    // Échec sans MAC_DOWNGRADE
    let cap_no_down = admin_cap
        .attenuate(mac_rights::MAC_READ | mac_rights::MAC_LABEL | mac_rights::MAC_CHECK)
        .unwrap();
    assert_eq!(
        daemon.update_object_label(&cap_no_down, 10, downgrade_label, 1006),
        Err(SysError::PermissionDenied),
        "Déclassification sans capacité MAC_DOWNGRADE formellement rejetée"
    );
    // Réussite avec capacité administrative
    assert!(daemon
        .update_object_label(&admin_cap, 10, downgrade_label, 1007)
        .is_ok());
    assert_eq!(
        daemon.get_object(10).unwrap().label.level,
        ClassificationLevel::Confidential
    );
    kprintln!("[MAC/DOWNGRADE] Déclassification et contrôle strict du droit MAC_DOWNGRADE validés");

    // 6. Chaîne d'audit cryptographique SHA-256
    assert!(daemon.audit_count >= 5);
    assert_ne!(daemon.last_audit_digest, [0u8; 32]);
    kprintln!("[MAC/AUDIT] Registre d'audit scellé SHA-256 et chaîne cryptographique inviolable validés");

    // 7. Commandes interactives Shell `mac`
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("mac status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("CONTRÔLE D'ACCÈS MANDATAIRE"));
    assert!(s1.contains("Bell-LaPadula"));

    // Commande subjects
    let (st2, len2) = shell.execute_line("mac subjects", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("SystemInit"));
    assert!(s2.contains("CryptoEnclave"));

    // Commande objects
    let (st3, len3) = shell.execute_line("mac objects", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("/etc/master.key"));
    assert!(s3.contains("/dev/net0"));

    // Commande check : UserShell (4) -> document.txt (13) READ -> ACCORDÉ
    let (st4, len4) = shell.execute_line("mac check 4 13 read", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("ACCORDÉ"));

    // Commande check : UserShell (4) -> master.key (10) READ -> REFUSÉ
    let (st5, len5) = shell.execute_line("mac check 4 10 read", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    let s5 = core::str::from_utf8(&out[..len5]).unwrap_or("");
    assert!(s5.contains("REFUSÉ"));
    assert!(s5.contains("Bell-LaPadula No Read Up"));

    // Commande audit
    let (st6, len6) = shell.execute_line("mac audit", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    let s6 = core::str::from_utf8(&out[..len6]).unwrap_or("");
    assert!(s6.contains("Condensat SHA-256 d'Audit MAC"));

    kprintln!("[MAC/SHELL] Commandes d'administration et d'évaluation interactives 'mac' validées");
    kprintln!("[MAC/SUCCESS] Démon MAC MLS (Bell-LaPadula & Biba) entièrement validé (Phase 89)");

    true
}
