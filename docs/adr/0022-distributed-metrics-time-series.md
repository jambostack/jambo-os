# ADR 0022: Moteur de Métriques Distribuées & Surveillance en Séries Temporelles (`jambo-metricsd`)

## Statut
Accepté (Phase 33 - Jalon v0.2.31)

## Contexte
Avec l'extension du cluster JamboOS à 32 phases (consensus, calcul distribué, maillage réseau chiffré, stockage CAS, équilibrage L4/L7 et coffre-fort de secrets), l'observabilité quantitative en temps réel est primordiale pour :
1. Mesurer la charge CPU, l'utilisation mémoire des Buddy/SLUB et VMOs, le débit réseau VirtIO/Mesh et la latence IPC de chaque nœud.
2. Détecter de manière proactive les dégradations de performance et les saturations de ressources avant qu'elles ne provoquent des pannes en cascade.
3. Déclencher des alertes automatiques et des décisions d'éviction (*drain*) ou de rééquilibrage de conteneurs pour `jambo-schedd`.
4. Garantir le respect strict du principe de moindre privilège via des capacités `MetricsCap` sans autorité ambiante.
5. Fonctionner en environnement contraint `#![no_std]` sans allocation dynamique non bornée.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-metricsd` (`services/jambo-metricsd`) intégrant :
1. **Échantillon de série temporelle (`MetricSample`)** :
   - Horodatage monotone (`timestamp: u64`).
   - Valeur numérique entière ou fixe (`value: u64`).
2. **Série temporelle bornée en anneau circulaire (`MetricSeries`)** :
   - Identifiant unique `name: [u8; 32]`.
   - Nœud émetteur `node_id: u16`.
   - Tampon annulaire d'échantillons (`RING_CAPACITY = 32`).
   - Agrégats précalculés : minimum, maximum, somme cumulée.
3. **Règle d'alerte à seuil (`AlertRule`)** :
   - Seuil critique (`threshold: u64`) et condition (`GreaterThan`, `LessThan`).
   - Statut actif (`triggered: bool`) et compteur d'échantillons hors-bornes.
4. **Contrôle d'accès orienté capacités (`MetricsCap`)** :
   - Droits explicites : `METRICS_INGEST` (0x01), `METRICS_QUERY` (0x02), `METRICS_ALERT` (0x04), `METRICS_ADMIN` (0x80).
5. **API de calcul statistique O(1) / O(N borné)** :
   - `ingest_metric` : insertion dans l'anneau avec mise à jour des agrégats et évaluation immédiate des règles d'alerte.
   - `query_window` : extraction de statistiques (moyenne, min, max, dernier échantillon) sur une fenêtre temporelle.

## Conséquences
- **Positives** :
  - Observabilité temps réel ultra-légère et déterministe pour tout le cluster.
  - Détection précoce d'anomalies sans dépendance externe ni saturation mémoire.
  - Confinement strict sans autorité ambiante.
- **Négatives / Arbitrages** :
  - Historique temporel borné à un nombre fixe d'échantillons récents par métrique (stratégie *drop-oldest*).
