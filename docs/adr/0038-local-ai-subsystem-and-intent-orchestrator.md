# ADR 0038: Sous-Système d'IA Locale (`jambo-aid`), Indexation Vectorielle & Orchestration d'Intentions

## Statut
Accepté (Phase 49 - Jalon v0.2.47)

## Contexte
Après la validation du gestionnaire de paquets déclaratifs et des mises à jour atomiques A/B (ADR 0037, v0.2.46), JamboOS franchit une étape pionnière en intégrant une couche d'intelligence artificielle locale sans jamais compromettre les principes fondamentaux du micro-noyau :
1. **Règle Architecturale Fondamentale** :
   - **Interdiction absolue d'exécuter du code d'IA en Ring 0 / EL1**.
   - Le démon `jambo-aid` s'exécute strictement en espace utilisateur (Ring 3) confiné par la table de capacités CSpace.
2. **Algèbre Linéaire en Virgule Fixe & Indexation Vectorielle (`services/jambo-aid`)** :
   - Représentation vectorielle quantifiée `VectorEmbedding` (Dimension: 8, `i16` fixed-point) exempte de dépendances flottantes (`#![no_std]`).
   - Primitives mathématiques : produit scalaire (`dot_product`), norme euclidienne entière (`norm`) par méthode de Héron, et similarité cosinus normalisée en parties par millier (`cosine_similarity_ppm`).
   - Générateur d'embeddings déterministe textuel `from_text` (Tiny N-gram Hash Embedder).
   - Index vectoriel sémantique `SemanticIndex` avec recherche du plus proche voisin (`search_nearest`) et recherche Top-K.
3. **Orchestrateur d'Intentions Typées (`IntentOrchestrator`)** :
   - Traduction sécurisée de commandes en langage naturel en intentions structurées : `LaunchApplication`, `InspectSystemCapabilities`, `QuerySystemMetrics`, `SearchSemanticFile`, `ConfigureNetwork`, `PerformStorageBackup`.
   - Zéro autorité ambiante : l'intention déduite ne confère aucun privilège supplémentaire ; l'exécution reste subordonnée aux Handles de capacités détenus.
4. **Commandes Interactives dans le Shell `jsh`** :
   - `ai status` : état du démon d'IA locale Ring 3.
   - `ai ask <prompt>` : analyse et traduction d'une intention utilisateur.
   - `ai search <query>` : recherche sémantique par similarité cosinus dans la base documentaire.
   - `ai embed <texte>` : calcul instantané de vecteur d'embedding et affichage de sa norme.
5. **Harnais de Validation Automatisée** (`kernel/src/sched/ai_test.rs`) :
   - Validation de l'algèbre vectorielle en virgule fixe et de la similarité cosinus.
   - Validation de l'indexation sémantique et de la recherche Top-K.
   - Validation de l'orchestrateur d'intentions.
   - Validation des commandes `ai` dans `jsh`.

## Décision
1. Intégration de `jambo-aid` dans `jambo-sh` avec l'implémentation de la commande `ai`.
2. Ajout des dépendances dans `kernel/Cargo.toml` et création de `kernel/src/sched/ai_test.rs`.
3. Validation complète sous QEMU (Phase 49) et publication de la version `v0.2.47`.

## Conséquences
- Capacités sémantiques et interaction en langage naturel intégrées nativement sans alourdir le micro-noyau.
- Confinement absolu de tout code d'IA en Ring 3, éliminant tout risque d'attaque par injection de prompt sur le noyau.
