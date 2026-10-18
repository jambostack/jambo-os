//! Démon de sous-système d'IA locale en espace utilisateur (jambo-aid)
//!
//! Règle architecturale formelle : Interdiction absolue d'exécuter du code d'IA en Ring 0.
//! Ce service s'exécute exclusivement en espace utilisateur (Ring 3), fournissant
//! l'indexation sémantique des objets JamboFS et l'orchestration d'intentions typées.

#![no_std]

use libjambo::SysError;

pub const EMBEDDING_DIM: usize = 8;
pub const MAX_INDEXED_DOCS: usize = 16;

/// Vecteur d'embedding sémantique
#[derive(Debug, Clone, Copy)]
pub struct VectorEmbedding {
    pub values: [i16; EMBEDDING_DIM],
}

impl VectorEmbedding {
    pub const fn new(values: [i16; EMBEDDING_DIM]) -> Self {
        Self { values }
    }

    /// Calcul de similarité cosinus en arithmétique entière fixe (Fixed-Point)
    pub fn dot_product(&self, other: &Self) -> i32 {
        let mut sum: i32 = 0;
        let mut i = 0;
        while i < EMBEDDING_DIM {
            sum += (self.values[i] as i32) * (other.values[i] as i32);
            i += 1;
        }
        sum
    }
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
}

/// Type d'action déduite par l'orchestrateur d'intentions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentAction {
    LaunchApplication(&'static str),
    InspectSystemCapabilities,
    QuerySystemMetrics,
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

        if text.contains("terminal") || text.contains("console") {
            IntentAction::LaunchApplication("jambo-term")
        } else if text.contains("capstat") || text.contains("permissions") {
            IntentAction::InspectSystemCapabilities
        } else if text.contains("top") || text.contains("cpu") || text.contains("metrics") {
            IntentAction::QuerySystemMetrics
        } else {
            IntentAction::UnknownIntent
        }
    }
}
