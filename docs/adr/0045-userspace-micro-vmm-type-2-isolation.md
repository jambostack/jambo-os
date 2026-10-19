# ADR 0045: Micro-Hyperviseur Utilisateur & Isolation Matérielle Type-2 (`jambo-vmm`)

## Statut
Accepté (Phase 56 - Jalon v0.2.54)

## Contexte
Dans la continuité du modèle d'isolation zéro-autorité de JamboOS renforcé par `jambo-authd` (Phase 55, ADR 0044), JamboOS intègre avec `services/jambo-vmm` un moniteur de micro-machines virtuelles (Micro-VMM) fonctionnant intégralement en espace utilisateur (Ring 3) :
1. **Confinement Capabilaire d'Hyperviseur (`VmCap`)** :
   - L'administration, la création, l'allocation mémoire et le piégeage matériel de chaque micro-VM sont régis par un jeton capabiliaire `VmCap`.
   - Les droits sont subdivisés de manière granulaire (`VM_CREATE`, `GUEST_RUN`, `MEMORY_MAP`, `IO_INTERCEPT`), interdisant toute action non autorisée par le CSpace.
2. **Gestion de l'Espace d'Adressage Étendu EPT / Stage-2 (`EptAddressSpace`)** :
   - Traduction matérielle des adresses physiques invitées (GPA) en adresses physiques hôtes (HPA).
   - Détection et interception des violations d'accès mémoire (`EptViolation`) avec contrôle précis des permissions RWX.
3. **vCPU & Piégeage Matériel VM-Exit (`MicroVmm`)** :
   - Émulation de vCPUs légers avec registre d'état complet (`GuestRegisters`, `VcpuState`).
   - Interception et traitement ordonné des VM-Exits : requêtes CPUID, instructions privilégiées, interruptions HLT, et accès aux ports d'E/S (COM1 port 0x3F8/0xF8, ports de diagnostic).
   - Console série virtuelle intégrée pour la communication bidirectionnelle avec le système invité.
4. **Démon Orchestrateur Ring 3 (`JamboVmmDaemon`) & Shell `jsh`** :
   - Démon utilisateur fournissant une gestion déclarative des micro-VMs.
   - Commandes interactives dans `jsh` :
     - `vmm status` : état de la micro-VM, configuration des tables EPT, droits capabilitaires et statistiques de VM-Exits.
     - `vmm step` : exécution pas-à-pas d'une instruction vCPU avec rapport immédiat de la raison d'interception (VM-Exit).
     - `vmm run` : exécution continue de la VM jusqu'au signal d'arrêt (HLT) ou quota atteint.
     - `vmm reset` : réinitialisation et rechargement de la mémoire et de l'état des vCPUs.
5. **Harnais de Validation Noyau (`kernel/src/sched/vmm_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 56) de la conformité capabilaire, de la pagination EPT, des pièges d'E/S série et du cycle de vie complet du vCPU.

## Décision
1. Enrichissement de `services/jambo-vmm/src/lib.rs` avec l'orchestrateur `JamboVmmDaemon` et le support des opcodes I/O (`0xEE`, `0xEC`).
2. Intégration de `jambo-vmm` dans `services/jambo-sh` avec l'implémentation de la commande `vmm`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de test `kernel/src/sched/vmm_test.rs`.
4. Validation complète sous QEMU (Phase 56) et publication de la version `v0.2.54`.

## Conséquences
- Possibilité d'exécuter des micro-workloads non fiables dans des enclaves matérielles Type-2 sécurisées sans compromettre l'intégrité de l'hôte.
- Respect strict du principe de moindre privilège : le moniteur VMM s'exécute en Ring 3 sans privilèges ambiants noyau.
