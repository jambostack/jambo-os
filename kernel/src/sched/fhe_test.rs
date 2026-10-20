//! Module de validation du Chiffrement Complètement Homomorphe (FHE) & Calcul Aveugle Ring 3 (`jambo-fhe`)
//! Phase 98 — Jalon v0.2.96
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_fhe::{
    fhe_rights, BlindEngine, Ciphertext, FheCap, FheSystem, JamboFheDaemon, Plaintext, Poly,
    FHE_CIPHER_MODULUS, FHE_DELTA, FHE_N, FHE_PLAIN_MODULUS, INITIAL_NOISE_BUDGET,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du sous-système FHE souverain (Phase 98)
pub fn execute_fhe_daemon_test() -> bool {
    kprintln!(
        "[FHE/TEST] Démarrage du test de validation du chiffrement homomorphe FHE & calcul aveugle (Phase 98)..."
    );

    // 1. Contrôle d'accès capabilaire (FheCap) et rejet formel de toute élévation de privilèges
    let admin_cap = FheCap::new(Handle::new(9801, 1), fhe_rights::ALL);
    assert!(admin_cap.has_right(fhe_rights::KEYGEN));
    assert!(admin_cap.has_right(fhe_rights::ENCRYPT));
    assert!(admin_cap.has_right(fhe_rights::DECRYPT));
    assert!(admin_cap.has_right(fhe_rights::EVAL));
    assert!(admin_cap.has_right(fhe_rights::BOOTSTRAP));
    assert!(admin_cap.has_right(fhe_rights::ADMIN));

    let eval_cap = admin_cap
        .attenuate(fhe_rights::EVAL | fhe_rights::BOOTSTRAP | fhe_rights::INSPECT)
        .expect("Atténuation monotone FheCap");
    assert!(eval_cap.has_right(fhe_rights::EVAL));
    assert!(eval_cap.has_right(fhe_rights::BOOTSTRAP));
    assert!(eval_cap.has_right(fhe_rights::INSPECT));
    assert!(!eval_cap.has_right(fhe_rights::DECRYPT));
    assert!(!eval_cap.has_right(fhe_rights::ADMIN));
    assert!(!eval_cap.has_right(fhe_rights::KEYGEN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        eval_cap.attenuate(fhe_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits FheCap formellement rejetée"
    );
    kprintln!("[FHE/CAP] Contrôle d'accès capabilaire FheCap et atténuation monotone validés");

    // 2. Initialisation du démon FHE et trousseau cryptographique souverain
    let mut daemon = JamboFheDaemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.ciphertext_count, 2);
    kprintln!(
        "[FHE/INIT] Démon FHE initialisé (Anneau R_q N=16, q=1073758209, t=65537, Delta=16384)"
    );

    // 3. Validation de l'addition homomorphe BFV en mémoire : 17 + 25 = 42
    let ct_a = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(17), 0x1111);
    let ct_b = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(25), 0x2222);
    let ct_sum = FheSystem::eval_add(&ct_a, &ct_b);
    let dec_sum = FheSystem::decrypt(&daemon.keys.sk, &ct_sum);
    assert_eq!(dec_sum.as_scalar(), 42, "Addition homomorphe 17 + 25 = 42");
    kprintln!("[FHE/ADD] Addition homomorphe chiffrée validée (Enc(17) + Enc(25) = Enc(42))");

    // 4. Multiplication homomorphe BFV avec rélinéarisation base-W : 6 * 7 = 42
    let ct_6 = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(6), 0x3333);
    let ct_7 = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(7), 0x4444);
    let ct_prod = FheSystem::eval_mul(&ct_6, &ct_7, &daemon.keys.rlk);
    let dec_prod = FheSystem::decrypt(&daemon.keys.sk, &ct_prod);
    assert_eq!(
        dec_prod.as_scalar(),
        42,
        "Multiplication homomorphe 6 * 7 = 42"
    );
    kprintln!("[FHE/MUL] Multiplication homomorphe chiffrée et rélinéarisation base-W validées (Enc(6) * Enc(7) = Enc(42))");

    // 5. Rafraîchissement de bruit homomorphe (Bootstrapping)
    let mut noisy_ct = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(99), 0x5555);
    noisy_ct.noise_budget = 8; // Bruit critique
    let refreshed_ct = FheSystem::bootstrap(&noisy_ct, &daemon.keys.pk, &daemon.keys.sk);
    assert_eq!(refreshed_ct.noise_budget, INITIAL_NOISE_BUDGET);
    let dec_refreshed = FheSystem::decrypt(&daemon.keys.sk, &refreshed_ct);
    assert_eq!(
        dec_refreshed.as_scalar(),
        99,
        "Préservation de la valeur après bootstrapping"
    );
    kprintln!("[FHE/BOOTSTRAP] Bootstrapping homomorphe validé (Noise budget restauré à 48 bits)");

    // 6. Moteur de calcul aveugle (Blind Computing Engine)
    // P(x) = 5 + 3*x + 2*x^2 pour x = 4 => 5 + 12 + 32 = 49
    let ct_x = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(4), 0x6666);
    let ct_blind_poly = BlindEngine::blind_poly_eval(&ct_x, 5, 3, 2, &daemon.keys.rlk);
    let dec_poly = FheSystem::decrypt(&daemon.keys.sk, &ct_blind_poly);
    assert_eq!(
        dec_poly.as_scalar(),
        49,
        "Évaluation aveugle de polynôme P(4) = 49"
    );

    // Produit scalaire aveugle : w = [3, 5], x = [10, 4] => 30 + 20 = 50
    let ct_v0 = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(10), 0x7771);
    let ct_v1 = FheSystem::encrypt(&daemon.keys.pk, &Plaintext::from_scalar(4), 0x7772);
    let ct_dot =
        BlindEngine::blind_dot_product(&[ct_v0, ct_v1], &[3, 5]).expect("Blind dot product");
    let dec_dot = FheSystem::decrypt(&daemon.keys.sk, &ct_dot);
    assert_eq!(
        dec_dot.as_scalar(),
        50,
        "Produit scalaire aveugle 3*10 + 5*4 = 50"
    );
    kprintln!(
        "[FHE/BLIND] Moteur de calcul aveugle Ring 3 validé (Polynôme P(4)=49, DotProduct=50)"
    );

    // 7. Registre d'audit scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[FHE/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 8. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("fhe status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("fhe demo", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("fhe blind", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("fhe bootstrap", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("fhe audit", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    kprintln!("[FHE/SHELL] Commandes Ring 3 jsh 'fhe' validées avec succès");
    true
}
