# ADR 0065: Moteur eBPF Souverain, Vérificateur Formel DAG & Filtrage Réseau XDP (`jambo-bpfd`)

## Statut
Accepté (Phase 76 - Jalon v0.2.74)

## Contexte
La surveillance du trafic réseau en temps réel, la défense contre les attaques par déni de service (DDoS/SYN-Flood), le routage programmable et l'observabilité fine de la grappe sans modification du micro-noyau requièrent une infrastructure d'exécution de bytecode programmable in-kernel / in-service hautement sécurisée. Dans un micro-noyau de 3e génération orienté capacités (`#![no_std]`), l'exécution de code arbitraire doit offrir des garanties mathématiques absolues d'isolation, de terminaison déterministe et d'absence d'effets de bord non autorisés. Avec `services/jambo-bpfd`, JamboOS intègre une machine virtuelle eBPF souveraine :

1. **Confinement Capabilaire Strict (`BpfCap`)** :
   - Le chargement, la vérification, l'attachement, l'exécution et l'administration des programmes et cartes eBPF requièrent impérativement un jeton de capacité `BpfCap`.
   - Droits granulaires (`BPF_PROG_LOAD`, `BPF_PROG_RUN`, `BPF_PROG_ATTACH`, `BPF_MAP_CREATE`, `BPF_MAP_READ`, `BPF_MAP_WRITE`, `BPF_ADMIN`).
   - Atténuation capabilaire stricte (`attenuate`) interdisant toute élévation de privilèges (Zero-Ambient Authority).

2. **Vérificateur Formel de Sécurité et Preuve de Terminaison (`BpfVerifier`)** :
   - Invariant DAG Acyclique : interdiction formelle des sauts en arrière (`off <= 0`), éliminant mathématiquement les boucles infinies et résolvant le problème de l'arrêt pour tout programme accepté.
   - Confinement de la pile : validation stricte des décalages de pile dans l'intervalle borné `[-512, 0)` par rapport au pointeur de trame `R10`.
   - Protection de lecture seule de `R10` : toute tentative d'écriture dans le pointeur de trame est rejetée.
   - Validation des identifiants d'assistants (helpers) et terminaison garantie par instruction `EXIT`.

3. **Machine Virtuelle Sandboxed (`BpfVm`) & Jeu d'Instructions eBPF** :
   - 11 registres 64 bits (`R0` valeur de retour/verdict, `R1` contexte, `R2..R5` arguments, `R6..R9` callee-saved, `R10` stack pointer).
   - Instructions ALU64, ALU32, sauts conditionnels, transferts mémoire sécurisés et appels de helpers.
   - Borne supérieure de cycles d'exécution (`MAX_CYCLES_PER_PROG = 10_000`) protégeant contre toute famine CPU.

4. **Cartes Mémoire Partagées Haute Performance (eBPF Maps)** :
   - Types de structures : `Array` (indexé direct O(1)), `HashMap` (table associative pour adresses IP et flux), `RingBuf` (anneau de télémétrie asynchrone).
   - Manipulation bidirectionnelle noyau / usermode via les helpers `map_lookup_elem` et `map_update_elem`.

5. **Crochets Réseau XDP (eXpress Data Path) & Verdicts Déterministes** :
   - Traitement direct au niveau interface réseau sans allocation : `XDP_PASS` (transmission), `XDP_DROP` (rejet immédiat), `XDP_TX` (renvoi), `XDP_REDIRECT` (redirection).
   - Inspection du contenu des paquets en temps réel (`PACKET_READ_BYTE`, `PACKET_LEN`, calcul de somme de contrôle `CSUM_DIFF`).

6. **Commandes Shell Interactives `bpf` dans `jsh`** :
   - `bpf status` : statistiques globales, programmes vérifiés, cartes actives, paquets inspectés/acceptés/rejetés, cycles VM.
   - `bpf list` : inventaire des programmes eBPF vérifiés avec score de complexité et compteurs d'exécution.
   - `bpf maps` : visualisation des cartes de stockage en mémoire partagée.
   - `bpf verify [filter]` : démonstration et vérification formelle de filtres de paquets.
   - `bpf run <id>` : exécution contrôlée sur paquet de test synthétique avec affichage du verdict.
   - `bpf attach <id> <hook>` : liaison dynamique d'un filtre à un crochet d'interface (ex: `eth0_xdp`).

7. **Validation Noyau Dédiée (`kernel/src/sched/bpfd_test.rs`)** :
   - Couverture complète exécutée sous QEMU lors du cycle autonome (Phase 76).

## Décision
1. Conception et implémentation du démon `JamboBpfDaemon`, de `BpfCap`, du vérificateur formel `BpfVerifier`, de la machine virtuelle `BpfVm` et des cartes dans `services/jambo-bpfd`.
2. Intégration du composant dans l'environnement de commandes `services/jambo-sh`.
3. Écriture du module de tests noyau `kernel/src/sched/bpfd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.74` pour l'ensemble des modules du workspace.

## Conséquences
- Disponibilité d'une infrastructure d'instrumentation et de filtrage réseau programmable zéro-copie et mathématiquement sécurisée.
- Immunité prouvée contre les boucles infinies et les accès mémoire arbitraires.
