# Spécification Technique — Jalon 3.7 : Métrologie Système & Télémétrie en Ring 3 (PID 12), Démon `jambo-metrics` & Commandes `metrics` (v0.3.51)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.51`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

Après les jalons 3.1 (`v0.3.45` - Résilience Matérielle FDR & TPM 2.0), 3.2 (`v0.3.46` - Runtime WebAssembly/WASI), 3.3 (`v0.3.47` - Cryptographie Post-Quantique ML-KEM/ML-DSA), 3.4 (`v0.3.48` - Surveillance d'Intégrité Noyau KDIR), 3.5 (`v0.3.49` - Confinement Mémoire & Forensics Volatile) et 3.6 (`v0.3.50` - Gestion Énergie & Fréquence CPU), JamboOS aborde la septième étape majeure du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **la Métrologie Système & Télémétrie en Séries Temporelles Haute Précision (`jambo-metrics` PID 12)**.

Dans une architecture micro-noyau moderne :
> *L'observabilité et le profilage système ne doivent jamais compromettre la compacité du Ring 0 ni générer de la contention mémoire sur le tas. Les métriques (latence IPC, utilisation mémoire VMO, débit disques, cycles CPU, alertes de surcharge) doivent être collectées, agrégées et alertées en Ring 3 par un démon dédié sans autorité ambiante, avec des tampons annulaires déterministes à temps constant $O(1)$.*

L'objectif du **Jalon 3.7 (`v0.3.51`)** est d'établir le démon **`jambo-metrics` en Ring 3 (PID 12)** :
1. Collecte de séries temporelles quantitatives en anneaux circulaires bornés (`MetricSeries`, `MetricSample`) sans allocation dynamique (`#![no_std]`, Zero Heap).
2. Calcul en ligne en temps constant des statistiques agrégées : minimum, maximum, moyenne cumulative, dernier échantillon, cardinalité.
3. Moteur d'évaluation d'alertes à seuil (`AlertRule`, conditions `GreaterThan`, `LessThan`) avec notification d'alerte immédiate.
4. Contrôle d'accès par capabilités sans autorité ambiante (`MetricsCap`) avec droits d'ingestion, de requête, d'alerte et d'administration.
5. Protocole IPC déterministe à 64 octets avec assertions statiques `size_of == 64`.
6. Commandes interactives dans le shell `jsh` : `metrics status`, `metrics query <series>`, `metrics ingest <series> <val>`, `metrics alerts`.
7. Listing complet des **12 processus Ring 3** actifs dans la commande `ps`.
8. Intégration dans le micro-noyau `kernel` (PID 12, alignement 16 octets System V ABI, ordonnancement EEVDF) et validation QEMU UEFI avec le code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-metrics`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │     jambo-metrics (PID 12)    │  │
│  │   (metrics   │                   │ • Séries Temporelles O(1)     │  │
│  │    status,   │                   │ • Min / Max / Moyenne / Last  │  │
│  │    query,    │                   │ • Moteur d'Alertes à Seuil    │  │
│  │    ingest,   │                   │ • Métriques Noyau, VMO, IPC   │  │
│  │    alerts)   │                   │ • Capabilités MetricsCap      │  │
│  └──────────────┘                   │ • Protocole IPC 64 octets     │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 12)                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur de Télémétrie Souverain (`#![no_std]`, Zéro Tas)
1. **Contrôle d'Accès par Capabilités (`MetricsCap`)** :
   - Droits granulaires : `METRICS_INGEST`, `METRICS_QUERY`, `METRICS_ALERT`, `METRICS_ADMIN`.
   - Zéro autorité ambiante, atténuation monotone stricte.
2. **Gestion des Séries Temporelles (`MetricSeries`)** :
   - Capacité fixe : 16 séries temporelles simultanées (`MAX_SERIES = 16`).
   - Tampon circulaire : 32 échantillons horodatés par série (`RING_CAPACITY = 32`).
   - Métriques préconfigurées : `cpu_load`, `ipc_latency_ns`, `vmo_usage_kb`, `sched_switches`.
3. **Moteur d'Alertes (`AlertRule`)** :
   - 16 règles configurables (`MAX_ALERT_RULES = 16`).
   - Seuils dynamiques et déclenchement d'alertes instantané lors de l'ingestion.
4. **Protocole IPC Déterministe (64 octets)** :
   - Opcodes : `GetStatus = 1`, `QuerySeries = 2`, `IngestSample = 3`, `GetAlerts = 4`.
   - Structures `MetricsRequest` et `MetricsResponse` calibrées à 64 octets exactement.

---

## 3. Commandes Shell `jsh` (PID 2)

- `metrics status` : Affiche l'état global du service de métrologie, le nombre de séries actives, le nombre d'échantillons totaux ingérés et les alertes actives.
- `metrics query <series>` : Affiche les métriques agrégées pour la série spécifiée (min, max, moyenne, dernier échantillon, total).
- `metrics ingest <series> <val>` : Injecte un échantillon numérique dans la série temporelle et teste les alertes associées.
- `metrics alerts` : Liste les règles d'alertes configurées et leur état actuel (déclenchée ou nominale).
- `ps` : Liste complète des **12 processus Ring 3** :
  `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`.

---

## 4. Intégration Micro-Noyau (`kernel`) & `xtask`

- `kernel/Cargo.toml` : version `0.3.51`.
- Extraction de `/bin/metricsd` de l'Initrd USTAR.
- Allocation de pile Ring 3 avec validation de l'alignement System V ABI : `assert_eq!(metricsd_sp % 16, 0)`.
- Ordonnancement du PID 12 dans l'ordonnanceur EEVDF.
- Journal UART : `[PASS] Métrologie Système & Télémétrie Haute Précision (jambo-metrics PID 12) validée sous QEMU.`
- `xtask` : Compilation de `jambo-metricsd` avec `libs/user-x86_64.ld` à `0x00400000`, empaquetage dans `target/initrd.tar`, bannière de disque `"Bienvenue sur JamboOS v0.3.51\n"`.
- Test QEMU automatisé avec code de sortie 33 (`isa-debug-exit`).

