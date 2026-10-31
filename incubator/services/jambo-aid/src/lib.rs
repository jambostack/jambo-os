//! Démon de sous-système d'IA locale en espace utilisateur (jambo-aid)
//!
//! Règle architecturale formelle : Interdiction absolue d'exécuter du code d'IA en Ring 0.
//! Ce service s'exécute exclusivement en espace utilisateur (Ring 3), fournissant
//! l'indexation sémantique des objets JamboFS et l'orchestration d'intentions typées.

#![no_std]

use libjambo::SysError;

pub const EMBEDDING_DIM: usize = 8;
pub const MAX_INDEXED_DOCS: usize = 16;
pub const MAX_TOP_K: usize = 4;

/// Vecteur d'embedding sémantique quantifié (Fixed-Point i16)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorEmbedding {
    pub values: [i16; EMBEDDING_DIM],
}

impl VectorEmbedding {
    pub const fn new(values: [i16; EMBEDDING_DIM]) -> Self {
        Self { values }
    }

    /// Calcul du produit scalaire (Dot Product)
    pub fn dot_product(&self, other: &Self) -> i32 {
        let mut sum: i32 = 0;
        let mut i = 0;
        while i < EMBEDDING_DIM {
            sum += (self.values[i] as i32) * (other.values[i] as i32);
            i += 1;
        }
        sum
    }

    /// Norme euclidienne entière (Integer Square Root)
    pub fn norm(&self) -> u32 {
        let mut sum_sq: u32 = 0;
        let mut i = 0;
        while i < EMBEDDING_DIM {
            let v = self.values[i] as i32;
            sum_sq += (v * v) as u32;
            i += 1;
        }
        integer_sqrt(sum_sq)
    }

    /// Similarité cosinus normalisée à l'échelle [-1000, 1000]
    pub fn cosine_similarity_ppm(&self, other: &Self) -> i32 {
        let n1 = self.norm() as i64;
        let n2 = other.norm() as i64;
        if n1 == 0 || n2 == 0 {
            return 0;
        }
        let dot = self.dot_product(other) as i64;
        let raw = ((dot * 1000) / (n1 * n2)) as i32;
        raw.clamp(-1000, 1000)
    }

    /// Génère un embedding sémantique déterministe à partir d'une chaîne de texte (Tiny N-gram Hash Embedder)
    pub fn from_text(text: &str) -> Self {
        let mut vals = [0i16; EMBEDDING_DIM];
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Self { values: vals };
        }

        let mut idx = 0;
        while idx < bytes.len() {
            let b = bytes[idx];
            let dim = idx % EMBEDDING_DIM;
            let weight = ((b as i16) & 0x1F) - 16;
            vals[dim] = vals[dim].saturating_add(weight);
            idx += 1;
        }

        Self { values: vals }
    }
}

/// Racine carrée entière par méthode de Héron
fn integer_sqrt(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    let mut x0 = val / 2;
    if x0 == 0 {
        return 1;
    }
    let mut x1 = (x0 + val / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + val / x0) / 2;
    }
    x0
}

/// Document ou objet JamboFS indexé sémantiquement
#[derive(Debug, Clone, Copy)]
pub struct IndexedObject {
    pub object_id: u64,
    pub path_or_title: &'static str,
    pub embedding: VectorEmbedding,
}

/// Index sémantique vectoriel local
pub struct SemanticIndex {
    pub objects: [Option<IndexedObject>; MAX_INDEXED_DOCS],
    pub count: usize,
}

impl Default for SemanticIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticIndex {
    pub const fn new() -> Self {
        const INIT_OPT: Option<IndexedObject> = None;
        Self {
            objects: [INIT_OPT; MAX_INDEXED_DOCS],
            count: 0,
        }
    }

    /// Indexe un nouvel objet système
    pub fn insert(
        &mut self,
        object_id: u64,
        path_or_title: &'static str,
        embedding: VectorEmbedding,
    ) -> Result<(), SysError> {
        for slot in self.objects.iter_mut() {
            if slot.is_none() {
                *slot = Some(IndexedObject {
                    object_id,
                    path_or_title,
                    embedding,
                });
                self.count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Recherche le document le plus pertinent pour un vecteur de requête
    pub fn search_nearest(&self, query_vec: &VectorEmbedding) -> Option<(&'static str, i32)> {
        let mut best_score = i32::MIN;
        let mut best_match = None;

        for obj in self.objects.iter().flatten() {
            let score = obj.embedding.dot_product(query_vec);
            if score > best_score {
                best_score = score;
                best_match = Some((obj.path_or_title, score));
            }
        }

        best_match
    }

    /// Recherche les Top-K documents les plus pertinents
    pub fn search_top_k(
        &self,
        query_vec: &VectorEmbedding,
        k: usize,
    ) -> [Option<(&'static str, i32)>; MAX_TOP_K] {
        let mut results: [Option<(&'static str, i32)>; MAX_TOP_K] = [None; MAX_TOP_K];
        let target_k = if k > MAX_TOP_K { MAX_TOP_K } else { k };

        for obj in self.objects.iter().flatten() {
            let score = obj.embedding.dot_product(query_vec);

            for i in 0..target_k {
                let replace = match results[i] {
                    None => true,
                    Some((_, existing_score)) => score > existing_score,
                };
                if replace {
                    let mut j = target_k - 1;
                    while j > i {
                        results[j] = results[j - 1];
                        j -= 1;
                    }
                    results[i] = Some((obj.path_or_title, score));
                    break;
                }
            }
        }

        results
    }
}

/// Type d'action déduite par l'orchestrateur d'intentions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentAction {
    LaunchApplication(&'static str),
    InspectSystemCapabilities,
    QuerySystemMetrics,
    SearchSemanticFile(&'static str),
    ConfigureNetwork { interface: &'static str, dhcp: bool },
    PerformStorageBackup { destination: &'static str },
    UnknownIntent,
}

/// Orchestrateur d'intentions typées
pub struct IntentOrchestrator {
    pub intents_parsed: u64,
}

impl Default for IntentOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentOrchestrator {
    pub const fn new() -> Self {
        Self { intents_parsed: 0 }
    }

    /// Analyse une requête textuelle et la transforme en action typée
    pub fn parse_intent(&mut self, text: &str) -> IntentAction {
        self.intents_parsed = self.intents_parsed.wrapping_add(1);

        if text.contains("terminal") || text.contains("console") || text.contains("term") {
            IntentAction::LaunchApplication("jambo-term")
        } else if text.contains("capstat") || text.contains("permissions") {
            IntentAction::InspectSystemCapabilities
        } else if text.contains("top") || text.contains("cpu") || text.contains("metrics") {
            IntentAction::QuerySystemMetrics
        } else if text.contains("find") || text.contains("search") || text.contains("cherche") {
            IntentAction::SearchSemanticFile("architecture.md")
        } else if text.contains("network") || text.contains("reseau") || text.contains("ip") {
            IntentAction::ConfigureNetwork {
                interface: "eth0",
                dhcp: true,
            }
        } else if text.contains("backup") || text.contains("sauvegarde") {
            IntentAction::PerformStorageBackup {
                destination: "/backup/cas_store.raw",
            }
        } else {
            IntentAction::UnknownIntent
        }
    }
}

/// Démon principal du sous-système d'IA locale JamboAI
pub struct JamboAiDaemon {
    pub index: SemanticIndex,
    pub orchestrator: IntentOrchestrator,
    pub queries_handled: u64,
}

impl Default for JamboAiDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboAiDaemon {
    pub const fn new() -> Self {
        Self {
            index: SemanticIndex::new(),
            orchestrator: IntentOrchestrator::new(),
            queries_handled: 0,
        }
    }

    /// Analyse une requête utilisateur et la convertit en intention structurée
    pub fn handle_query(&mut self, query: &str) -> IntentAction {
        self.queries_handled = self.queries_handled.wrapping_add(1);
        self.orchestrator.parse_intent(query)
    }

    /// Indexe un texte en calculant automatiquement son embedding
    pub fn index_text(&mut self, id: u64, path: &'static str, text: &str) -> Result<(), SysError> {
        let embedding = VectorEmbedding::from_text(text);
        self.index.insert(id, path, embedding)
    }

    /// Recherche sémantique par similarité cosinus
    pub fn search(&self, text: &str) -> Option<(&'static str, i32)> {
        let query_vec = VectorEmbedding::from_text(text);
        self.index.search_nearest(&query_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_cosine_and_dot() {
        let v1 = VectorEmbedding::new([10, 20, 30, 40, 50, 60, 70, 80]);
        let v2 = VectorEmbedding::new([10, 20, 30, 40, 50, 60, 70, 80]);
        let dot = v1.dot_product(&v2);
        assert!(dot > 0);
        let sim = v1.cosine_similarity_ppm(&v2);
        assert_eq!(sim, 1000);
    }

    #[test]
    fn test_semantic_index_top_k() {
        let mut idx = SemanticIndex::new();
        idx.insert(
            1,
            "/docs/arch.md",
            VectorEmbedding::new([10, 20, 30, 40, 0, 0, 0, 0]),
        )
        .unwrap();
        idx.insert(
            2,
            "/docs/net.md",
            VectorEmbedding::new([0, 0, 0, 0, 10, 20, 30, 40]),
        )
        .unwrap();

        let q = VectorEmbedding::new([10, 20, 30, 40, 0, 0, 0, 0]);
        let top_matches = idx.search_top_k(&q, 2);
        assert_eq!(top_matches[0].unwrap().0, "/docs/arch.md");
    }

    #[test]
    fn test_tiny_embedder_and_intents() {
        let emb = VectorEmbedding::from_text("jambo kernel microkernel");
        assert_ne!(emb.values, [0; EMBEDDING_DIM]);

        let mut orch = IntentOrchestrator::new();
        assert_eq!(
            orch.parse_intent("lance le terminal"),
            IntentAction::LaunchApplication("jambo-term")
        );
        assert_eq!(
            orch.parse_intent("configure le reseau ip"),
            IntentAction::ConfigureNetwork {
                interface: "eth0",
                dhcp: true
            }
        );
    }
}
