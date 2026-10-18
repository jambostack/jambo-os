# Charte d'Ingénierie pour les Blocs `unsafe` (JamboKernel)

Afin de préserver la Base Informatique de Confiance (TCB) et d'éliminer les comportements indéterminés (UB) :

1. **Interdiction dans la logique métier** : Aucun bloc `unsafe` n'est toléré dans les gestionnaires d'ordonnancement pur, la gestion des droits de capacités ou les algorithmes IPC.
2. **Confinement matériel strict** : `unsafe` est strictement restreint aux modules matériels d'interaction bas niveau (`arch::x86_64`, MMIO `VolatileCell`, rechargement de registres de contrôle `CR3`/`CR4`).
3. **Justification obligatoire** : Tout bloc `unsafe` DOIT être documenté par un bloc explicite `// SAFETY: <justification formelle>` expliquant les préconditions invariantes respectées.
4. **Vérification statique continue** : Le linter `clippy::undocumented_unsafe_blocks` et les tests algorithmiques sous `cargo miri` sont exécutés dans le pipeline CI.
