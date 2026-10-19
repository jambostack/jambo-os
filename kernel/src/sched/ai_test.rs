//! Module de test et validation du Sous-Système IA Local jambo-aid & Orchestrateur d'Intents (Phase 49 - v0.2.47)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_aid::{
    IntentAction, IntentOrchestrator, JamboAiDaemon, SemanticIndex, VectorEmbedding, EMBEDDING_DIM,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de l'IA locale jambo-aid et de l'orchestrateur d'intentions (Phase 49)
pub fn execute_local_ai_test() -> bool {
    kprintln!(
        "[AI/TEST] Démarrage du test du sous-système d'IA locale jambo-aid & similarité vectorielle (Phase 49)..."
    );

    // 1. Validation des primitives vectorielles (Dot product, Norme, Cosine Similarity)
    let v1 = VectorEmbedding::new([10, 20, 30, 40, 50, 60, 70, 80]);
    let v2 = VectorEmbedding::new([10, 20, 30, 40, 50, 60, 70, 80]);
    assert_eq!(v1.dot_product(&v2), 20400);
    assert!(v1.norm() > 0);
    let sim_self = v1.cosine_similarity_ppm(&v2);
    assert_eq!(sim_self, 1000); // 1.000 normalisé en parties par millier

    let v_ortho = VectorEmbedding::new([0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(v1.cosine_similarity_ppm(&v_ortho), 0);
    kprintln!("[AI/VECTOR] Algorithmes d'algèbre linéaire fixed-point (Produit scalaire, Norme, Cosinus) validés");

    // 2. Génération d'embeddings sémantiques déterministes (Tiny N-gram Hash Embedder)
    let emb1 = VectorEmbedding::from_text("jambo microkernel capabilities");
    let emb2 = VectorEmbedding::from_text("jambo microkernel capabilities");
    assert_eq!(emb1, emb2);
    assert_ne!(emb1.values, [0; EMBEDDING_DIM]);
    kprintln!("[AI/EMBED] Embedder sémantique déterministe opérationnel en no_std (Dim: 8)");

    // 3. Indexation sémantique et recherche Top-K
    let mut index = SemanticIndex::new();
    assert!(index
        .insert(
            1,
            "/docs/architecture.md",
            VectorEmbedding::new([50, 40, 30, 20, 0, 0, 0, 0]),
        )
        .is_ok());
    assert!(index
        .insert(
            2,
            "/docs/networking.md",
            VectorEmbedding::new([0, 0, 0, 0, 50, 40, 30, 20]),
        )
        .is_ok());
    assert_eq!(index.count, 2);

    let query_arch = VectorEmbedding::new([45, 35, 25, 15, 0, 0, 0, 0]);
    let nearest = index
        .search_nearest(&query_arch)
        .expect("Recherche nearest");
    assert_eq!(nearest.0, "/docs/architecture.md");

    let top_k = index.search_top_k(&query_arch, 2);
    assert_eq!(top_k[0].unwrap().0, "/docs/architecture.md");
    kprintln!("[AI/INDEX] Index vectoriel local et recherche Top-K opérationnels");

    // 4. Orchestrateur d'intentions typées (Zero-Ambient Intent Parsing)
    let mut orchestrator = IntentOrchestrator::new();
    assert_eq!(
        orchestrator.parse_intent("ouvre la console"),
        IntentAction::LaunchApplication("jambo-term")
    );
    assert_eq!(
        orchestrator.parse_intent("inspecte les permissions capstat"),
        IntentAction::InspectSystemCapabilities
    );
    assert_eq!(
        orchestrator.parse_intent("affiche les metrics cpu top"),
        IntentAction::QuerySystemMetrics
    );
    assert_eq!(
        orchestrator.parse_intent("cherche un fichier"),
        IntentAction::SearchSemanticFile("architecture.md")
    );
    assert_eq!(
        orchestrator.parse_intent("configure le reseau"),
        IntentAction::ConfigureNetwork {
            interface: "eth0",
            dhcp: true,
        }
    );
    assert_eq!(
        orchestrator.parse_intent("lance la sauvegarde backup"),
        IntentAction::PerformStorageBackup {
            destination: "/backup/cas_store.raw",
        }
    );
    assert_eq!(
        orchestrator.parse_intent("une requete completement aleatoire"),
        IntentAction::UnknownIntent
    );
    kprintln!("[AI/ORCHESTRATOR] Orchestration d'intentions sans autorité ambiante 100% conforme");

    // 5. Validation du démon JamboAiDaemon
    let mut aid = JamboAiDaemon::new();
    assert!(aid
        .index_text(1, "/vfs/system.conf", "kernel scheduler eevdf timer")
        .is_ok());
    let match_res = aid.search("scheduler").expect("Recherche sémantique");
    assert_eq!(match_res.0, "/vfs/system.conf");
    kprintln!("[AI/DAEMON] Démon JamboAiDaemon validé avec indexation automatique de texte");

    // 6. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'ai status'
    let (st_stat, len_stat) = shell.execute_line("ai status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("JamboAI Subsystem: Active"));
    kprintln!("[AI/SHELL] Commande 'ai status' validée");

    // Commande 'ai ask'
    let (st_ask, len_ask) = shell.execute_line("ai ask lance le terminal", &mut out_buf);
    assert_eq!(st_ask, ShellStatus::Success);
    let str_ask = core::str::from_utf8(&out_buf[..len_ask]).unwrap_or("");
    assert!(str_ask.contains("Intention détectée") && str_ask.contains("jambo-term"));
    kprintln!("[AI/SHELL] Commande 'ai ask' validée");

    // Commande 'ai search'
    let (st_search, len_search) = shell.execute_line("ai search security", &mut out_buf);
    assert_eq!(st_search, ShellStatus::Success);
    let str_search = core::str::from_utf8(&out_buf[..len_search]).unwrap_or("");
    assert!(str_search.contains("architecture.md") || str_search.contains("Document"));
    kprintln!("[AI/SHELL] Commande 'ai search' validée");

    // Commande 'ai embed'
    let (st_emb, len_emb) = shell.execute_line("ai embed microkernel", &mut out_buf);
    assert_eq!(st_emb, ShellStatus::Success);
    let str_emb = core::str::from_utf8(&out_buf[..len_emb]).unwrap_or("");
    assert!(str_emb.contains("Embedding calculé") && str_emb.contains("Norme"));
    kprintln!("[AI/SHELL] Commande 'ai embed' validée");

    kprintln!(
        "[AI/PASS] Sous-système d'IA locale jambo-aid, indexation vectorielle & intents validés avec succès."
    );
    true
}
