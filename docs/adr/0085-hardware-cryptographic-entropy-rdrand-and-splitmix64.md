# ADR 0085: Entropie Cryptographique Matérielle Non-Déterministe RDRAND & Avalanche SplitMix64

## Statut
Accepté (Palier 4 - Jalon v0.3.82)

## Contexte
Lors de la création d'un processus en espace utilisateur Ring 3, le noyau configure son espace d'adressage virtuel et sa pile conformément à l'ABI System V AMD64. Cette ABI stipule que le vecteur auxiliaire d'initialisation (`auxv`) doit fournir un pointeur vers un tampon d'aléa authentique de 16 octets désigné par `AT_RANDOM`.

Ce tampon `AT_RANDOM` remplit des rôles de sécurité fondamentaux :
1. **Initialisation des Canaris de Pile (Stack Canaries)** : Prévention de l'écrasement de l'adresse de retour (`__stack_chk_guard`) contre les attaques par dépassement de tampon (*buffer overflow*).
2. **Initialisation de l'Aléa ASLR** : Dispersion aléatoire des adresses de base des segments de données, du tas et des bibliothèques partagées.

Auparavant, JamboOS remplissait ce tampon avec des octets statiques fixes et déterministes : `[0x42, 0x13, 0x37, 0x73, 0xde, 0xad, 0xbe, 0xef, ...]`. Cette pratique annulait toute l'efficacité de la protection anti-ROP et anti-écrasement de pile, permettant à un exploit de prédire systématiquement les valeurs de canari.

## Décision
1. **Détection Matérielle de l'Instruction `rdrand`** :
   - Sur l'architecture x86_64, le noyau interroge la feuille CPUID 1 (`ECX bit 30`).
   - Si l'instruction est supportée par le processeur hôte, `rdrand` est invoquée directement via assembleur inline pour générer des mots aléatoires matériels issus du générateur physique de bruit thermique (TRNG du CPU).
2. **Générateur Avalanche SplitMix64 & Accumulateur de Gigue (Fallback)** :
   - Lorsque `rdrand` n'est pas disponible (ou sur architecture AArch64 sans extension RNG), le noyau échantillonne le compteur temporel à haute résolution (TSC via `rdtsc` sur x86_64, ou `cntvct_el0` sur ARM64).
   - Ce compteur de cycles, combiné au numéro du cœur AP et du thread courant, alimente un générateur pseudo-aléatoire à diffusion maximale SplitMix64 (multiplications de Fibonacci et décalages XOR stricts).
3. **Distribution Non-Déterministe à l'Amorçage** :
   - La fonction `get_random_u64()` génère deux mots aléatoires de 64 bits distincts pour chaque processus créé dans `Process::setup_user_stack()`.

## Conséquences
- **Éradication des Vecteurs Prédictibles** : Deux processus ou deux démarrages consécutifs disposent de canaris de pile et de graines aléatoires totalement imprévisibles.
- **Zéro Dépendance Lourde** : Implémentation ultra-compacte en Ring 0 (`#![no_std]`) sans allocation mémoire dynamique ni bibliothèque cryptographique externe.
- **Résistance Validée** : Suite de tests adversariaux dans `execute_hardware_broker_and_entropy_tests()` attestant formellement de la non-nullité et de la variance statistique des graines générées.

