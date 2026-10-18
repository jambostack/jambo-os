# ADR 0013 : Synchronisation Horlogère Distribuée Haute Précision PTP/NTP (jambo-timed)

## Statut
Accepté

## Contexte
Dans une architecture de micro-noyau distribuée et capabilaire (`jambo-rpc`), dotée d'un registre d'audit cryptographique inaltérable (`jambo-auditd`) et d'hyperviseurs de micro-machines virtuelles (`jambo-vmm`, `jambo-vhostd`), une référence temporelle universelle, monotone et sub-microseconde est fondamentale.

Dans les systèmes traditionnels, la synchronisation NTP/PTP (`chrony`, `ptp4l`) s'exécute avec les privilèges `root` ou `CAP_SYS_TIME`, modifiant directement l'heure du noyau via `adjtimex` ou `settimeofday`. Cela viole le principe du moindre privilège : une compromission du démon NTP permet d'altérer l'ordre temporel des événements d'audit, de fausser les expirations de certificats et d'invalider les signatures cryptographiques.

## Décision
Nous concevons et intégrons `jambo-timed`, un démon de synchronisation horlogère distribuée en espace utilisateur Ring 3 reposant sur les principes de zéro autorité ambiante.

1. **Capacité Dédiée `TimeSyncCap`** :
   - Tout ajustement de fréquence, recalibrage ou asservissement d'horloge requiert une capacité `TimeSyncCap`.
   - Droits granulaires : `TIME_READ` (0x01), `TIME_ADJUST_FREQ` (0x02), `TIME_STEP` (0x04), `TIME_PTP_SYNC` (0x08).
   - Aucun processus standard ne peut altérer l'heure système ou modifier le skew d'horloge.

2. **Algorithme d'Asservissement Hybride et Compensation de Dérive** :
   - Filtre d'estimation de dérive (Clock Drift Filter) à boucle à verrouillage de phase (PLL / FLL) sans saut brutal d'horloge (*slewing* progressif).
   - Horloge monotone garantie sans régression temporelle : le temps ne recule jamais, même en cas de resynchronisation majeure.
   - Intégration des horloges matérielles TSC (Time Stamp Counter invariant) et CMOS RTC avec calibrage dynamique.

3. **Protocole PTP (IEEE 1588) et NTP Découplé** :
   - Échange de messages d'horodatage matériel `Sync`, `Follow_Up`, `Delay_Req`, `Delay_Resp`.
   - Calcul précis du délai de propagation aller-retour (*Round-Trip Time*) et de l'offset résiduel.

## Conséquences
- **Intégrité Cryptographique Garantie** : Les horodatages du registre d'audit `jambo-auditd` et les expirations de sessions `jambo-authd` bénéficient d'un temps garanti sans régression.
- **Sécurité Maximale** : Le noyau délègue la gestion de l'asservissement sans compromettre la stabilité de l'ordonnanceur EEVDF.
- **Conformité Micro-Noyau** : Émancipation complète des privilèges monolithiques ambients.
