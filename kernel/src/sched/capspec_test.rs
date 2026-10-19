//! Module de validation de la Spécification Formelle, des Invariants CSpace et de l'Atténuation Monotone (`jambo-capspec`)
//! Phase 91 — Jalon v0.2.89
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{cap_rights, Handle, SysError};
use jambo_capspec::{
    capspec_rights, AuditAction, CapSpecCap, CapType, ConfinementProfile,
    InvariantViolation, JamboCapSpecDaemon, MAX_AUDIT_LOGS, MAX_CAP_NODES,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du moteur CapSpec (Phase 91)
pub fn execute_capspec_daemon_test() -> bool {
    kprintln!(
        "[CAPSPEC/TEST] Démarrage du test de spécification formelle et vérification d'invariants CSpace (Phase 91)..."
    );

    // 1. Contrôle d'accès capabilaire (CapSpecCap) et rejet formel d'amplification
    let admin_cap = CapSpecCap::new(Handle::new(9101, 1), capspec_rights::ALL);
    assert!(admin_cap.has_right(capspec_rights::VERIFY));
    assert!(admin_cap.has_right(capspec_rights::REGISTER_SPEC));
    assert!(admin_cap.has_right(capspec_rights::ENFORCE));
    assert!(admin_cap.has_right(capspec_rights::AUDIT));
    assert!(admin_cap.has_right(capspec_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(capspec_rights::VERIFY | capspec_rights::AUDIT)
        .expect("attenuate CapSpecCap to verify & audit");
    assert!(attenuated_cap.has_right(capspec_rights::VERIFY));
    assert!(attenuated_cap.has_right(capspec_rights::AUDIT));
    assert!(!attenuated_cap.has_right(capspec_rights::ADMIN));
    assert!(!attenuated_cap.has_right(capspec_rights::REGISTER_SPEC));
    assert!(!attenuated_cap.has_right(capspec_rights::ENFORCE));

    // Rejet formel de toute tentative d'élévation
    assert_eq!(
        attenuated_cap.attenuate(capspec_rights::ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification de droits CapSpecCap formellement rejetée"
    );

    let mut daemon = JamboCapSpecDaemon::new(admin_cap);
    daemon.init_defaults();

    // Rejet d'enregistrement de profil sans REGISTER_SPEC
    let test_prof = ConfinementProfile::strict_isolation(99);
    assert_eq!(
        daemon.register_profile(&attenuated_cap, test_prof),
        Err(SysError::PermissionDenied),
        "Enregistrement de profil sans REGISTER_SPEC doit échouer"
    );
    kprintln!("[CAPSPEC/CAP] Modèle de sécurité capabilaire CapSpecCap et rejet d'amplification validés");

    // 2. Invariant 1 : Absence d'autorité ambiante (No Ambient Authority)
    // Tout accès sans handle explicite ou avec Handle::NULL doit être immédiatement rejeté
    assert_eq!(
        daemon.verify_operation(1, Handle::NULL, cap_rights::READ),
        Err(InvariantViolation::AmbientAuthorityAttempt { pid: 1 }),
        "Tentative d'autorité ambiante (Handle NULL) formellement bloquée"
    );
    assert_eq!(
        daemon.verify_operation(1, Handle::new(0xFFFF, 1), cap_rights::READ),
        Err(InvariantViolation::InvalidCapabilityHandle { handle_val: Handle::new(0xFFFF, 1).0 }),
        "Handle forgé ou inconnu formellement rejeté"
    );
    kprintln!("[CAPSPEC/AMBIENT] Absence d'autorité ambiante et étanchéité des handles validées");

    // 3. Invariant 2 : Atténuation monotone irréversible Rights(child) ⊆ Rights(parent)
    // Racine : ID 1, Handle (1001, 1), PID 1, ALL rights
    let root_node = daemon.nodes[0].unwrap();
    assert_eq!(root_node.id, 1);
    assert_eq!(root_node.depth, 0);

    // Dérivation légitime avec sous-ensemble strict de droits pour PID 2 (ServiceWorker)
    daemon.assign_profile(&admin_cap, 2, 2).expect("assign ServiceWorker to PID 2");
    let child_rights = cap_rights::READ | cap_rights::WRITE | cap_rights::MAP;
    let child_id = daemon
        .derive_capability(&admin_cap, 1, child_rights, 2)
        .expect("Légitime dérivation avec atténuation");
    assert_eq!(child_id, 2);

    // Vérification de la validité de l'opération du child
    let child_node = daemon.nodes[1].unwrap();
    assert_eq!(child_node.rights, child_rights);
    assert_eq!(child_node.depth, 1);
    assert_eq!(child_node.parent_id, Some(1));
    assert!(child_node.verify_authenticity());

    assert_eq!(
        daemon.verify_operation(2, child_node.handle, cap_rights::READ | cap_rights::WRITE),
        Ok(()),
        "Opération conforme aux droits dérivés accordée"
    );

    // Rejet formel d'amplification lors d'une sous-dérivation : tentative d'acquérir EXECUTE non détenu
    let escalated_rights = child_rights | cap_rights::EXECUTE;
    let amp_err = daemon.derive_capability(&admin_cap, child_id, escalated_rights, 2);
    assert_eq!(
        amp_err,
        Err(InvariantViolation::RightsAmplification {
            parent_rights: child_rights,
            requested_rights: escalated_rights,
        }),
        "Amplification de droits lors d'une dérivation CSpace formellement rejetée"
    );
    kprintln!("[CAPSPEC/MONOTONIC] Atténuation monotone stricte et rejet d'amplification validés");

    // 4. Invariant 3 : Profils formels de confinement & Frontières de sécurité
    // PID 10 sous StrictIsolation (droits max READ | EXECUTE, VMO/VFS uniquement, transfert interdit)
    daemon.assign_profile(&admin_cap, 10, 1).expect("assign StrictIsolation to PID 10");

    // Tentative de dérivation avec droits d'écriture non autorisés par le profil
    let invalid_profile_rights = cap_rights::READ | cap_rights::WRITE;
    let prof_err = daemon.derive_capability(&admin_cap, 1, invalid_profile_rights, 10);
    assert_eq!(
        prof_err,
        Err(InvariantViolation::ProfileBoundaryExceeded {
            rights: invalid_profile_rights,
            max_rights: cap_rights::READ | cap_rights::EXECUTE,
        }),
        "Violation de frontière maximale de profil formellement rejetée"
    );

    // Dérivation autorisée pour PID 10 (READ seul)
    let iso_cap_id = daemon
        .derive_capability(&admin_cap, 1, cap_rights::READ, 10)
        .expect("derive valid read cap for isolated pid 10");

    // Tentative de transfert d'une capacité depuis un profil où allow_transfer = false
    let xfer_err = daemon.transfer_capability(&admin_cap, iso_cap_id, 10, 2);
    assert_eq!(
        xfer_err,
        Err(InvariantViolation::TransferProhibited { pid: 10, node_id: iso_cap_id }),
        "Transfert de capacité depuis un processus strictement confiné formellement interdit"
    );
    kprintln!("[CAPSPEC/PROFILE] Profils formels de confinement et étanchéité des frontières validés");

    // 5. Invariant 4 : Révocation en cascade déterministe
    // Arbre : Racine (1) -> Enfant (child_id=2) -> Petit-enfant (grandchild_id)
    let grandchild_rights = cap_rights::READ;
    let grandchild_id = daemon
        .derive_capability(&admin_cap, child_id, grandchild_rights, 2)
        .expect("derive grandchild capability");

    let grandchild_node = daemon.nodes[3].unwrap();
    assert_eq!(grandchild_node.id, grandchild_id);
    assert_eq!(grandchild_node.parent_id, Some(child_id));
    assert_eq!(grandchild_node.depth, 2);

    // Opération valide avant révocation
    assert_eq!(
        daemon.verify_operation(2, grandchild_node.handle, cap_rights::READ),
        Ok(())
    );

    // Révocation du nœud parent child_id
    let revoked_count = daemon
        .revoke_capability(&admin_cap, child_id)
        .expect("cascade revoke capability");
    assert_eq!(revoked_count, 2, "La révocation doit impacter l'enfant et le petit-enfant");

    // L'accès au parent et au petit-enfant doit désormais être immédiatement rejeté
    assert_eq!(
        daemon.verify_operation(2, child_node.handle, cap_rights::READ),
        Err(InvariantViolation::RevokedAccess { node_id: child_id }),
        "Accès à un nœud révoqué rejeté"
    );
    assert_eq!(
        daemon.verify_operation(2, grandchild_node.handle, cap_rights::READ),
        Err(InvariantViolation::RevokedAccess { node_id: grandchild_id }),
        "Accès à un descendant révoqué en cascade rejeté"
    );

    // La racine reste intacte
    assert_eq!(
        daemon.verify_operation(1, root_node.handle, cap_rights::READ),
        Ok(()),
        "La racine non révoquée demeure accessible"
    );
    kprintln!("[CAPSPEC/REVOKE] Révocation en cascade déterministe et intégrité de l'arbre CSpace validées");

    // 6. Contrôle global formel de tous les invariants du CSpace
    let verified = daemon.check_all_invariants();
    assert!(verified.is_ok(), "L'ensemble des invariants CSpace doit être vérifié avec succès");
    let count = verified.unwrap();
    assert!(count >= 3, "Au moins 3 nœuds CSpace vérifiés");
    kprintln!("[CAPSPEC/INVARIANTS] Validation mathématique globale des invariants CSpace réussie ({} nœuds)", count);

    // 7. Détection de falsification et inviolabilité SHA-256
    // Altérons artificiellement le token hash du nœud racine pour vérifier la détection de compromission
    let original_hash = daemon.nodes[0].unwrap().token_hash;
    daemon.nodes[0].as_mut().unwrap().token_hash = [0xFF; 32];
    assert_eq!(
        daemon.verify_operation(1, root_node.handle, cap_rights::READ),
        Err(InvariantViolation::IntegrityTampered { node_id: 1 }),
        "Falsification de jeton cryptographique immédiatement détectée"
    );
    // Restauration du hash
    daemon.nodes[0].as_mut().unwrap().token_hash = original_hash;
    assert_eq!(daemon.verify_operation(1, root_node.handle, cap_rights::READ), Ok(()));
    kprintln!("[CAPSPEC/INTEGRITY] Sceau d'authenticité SHA-256 et détection de falsification validés");

    // 8. Validation des commandes interactives du shell (`capspec`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("capspec status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("SPÉCIFICATION FORMELLE & VÉRIFICATION D'INVARIANTS CSPACE"));
    assert!(s1.contains("Absence d'Autorité Ambiante"));

    // Commande profiles
    let (st2, len2) = shell.execute_line("capspec profiles", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("StrictIsolation"));
    assert!(s2.contains("ServiceWorker"));
    assert!(s2.contains("SystemSupervisor"));

    // Commande nodes
    let (st3, len3) = shell.execute_line("capspec nodes", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("VMO"));
    assert!(s3.contains("Valide"));

    // Commande verify
    let (st4, len4) = shell.execute_line("capspec verify", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("SUCCÈS"));
    assert!(s4.contains("nœuds CSpace conformes"));

    // Commande audit
    let (st5, len5) = shell.execute_line("capspec audit", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    let s5 = core::str::from_utf8(&out[..len5]).unwrap_or("");
    assert!(s5.contains("Condensat SHA-256 d'Audit CapSpec"));

    kprintln!("[CAPSPEC/SHELL] Commandes d'administration et de vérification formelle 'capspec' validées");
    kprintln!("[CAPSPEC/SUCCESS] Moteur de spécification et d'invariants CapSpec entièrement validé (Phase 91)");

    true
}
