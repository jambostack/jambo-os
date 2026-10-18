# ADR 0025: Traçage Distribué, Propagation de Contexte & Analyse de Latence (`jambo-traced`)

## Statut
Accepté (Phase 36 - Jalon v0.2.34)

## Contexte
Avec la multiplication des démons distribués coopérants au sein de JamboOS (`jambo-rpc`, `jambo-meshd`, `jambo-gwd`, `jambo-serviced`, `jambo-kvd`), une requête initiée au niveau de la passerelle d'entrée peut traverser de multiples micro-services et nœuds avant d'aboutir.

Si l'audit cryptographique (`jambo-auditd`) enregistre les événements de sécurité et le moteur de métriques (`jambo-metricsd`) agrège des séries temporelles numériques, il manque le troisième pilier fondamental de l'observabilité système : **le traçage distribué de requêtes (Distributed Tracing)**.
Pour diagnostiquer les latences anormales, identifier les cascades de pannes et comprendre le cheminement causal des flux sans dégrader les performances en espace utilisateur `#![no_std]`, le système requiert :
1. **Propagation de contexte causale** : identifiant de trace 128 bits (`TraceId`), identifiant de portée 64 bits (`SpanId`) et descripteur d'échantillonnage (*TraceFlags*).
2. **Gestionnaire de portées (*Spans*) déterministe** : enregistrement des temps de début/fin, nom de l'opération, statut d'achèvement (Ok, Error, TimedOut) et attributs clés-valeurs bornés.
3. **Tampons annulaires de traces en mémoire bornée** : collecte sans allocation dynamique illimitée, avec politique de rétention en cas de saturation (*ring buffer* borné).
4. **Contrôle d'accès sans autorité ambiante (`TraceCap`)** : seules les entités détenant les capacités adéquates peuvent injecter, extraire ou interroger des traces système.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-traced` (`services/jambo-traced`) intégrant :
1. **Contexte de trace (`TraceContext`)** :
   - `trace_id: [u8; 16]` (identifiant global unique de la transaction).
   - `span_id: u64` (identifiant de la portée courante).
   - `parent_span_id: Option<u64>` (identifiant de la portée parente).
   - `flags: u8` (drapeaux d'échantillonnage et de traçabilité active).
2. **Portée d'exécution (`TraceSpan`)** :
   - `span_id: u64`.
   - `trace_id: [u8; 16]`.
   - `parent_span_id: Option<u64>`.
   - `name: [u8; 32]`, `name_len: usize`.
   - `start_time: u64`, `end_time: u64`.
   - `status: SpanStatus` (`Active`, `Ok`, `Error`, `TimedOut`).
3. **Moteur de collecte de traces (`TraceCollector`)** :
   - Capacité bornée (`MAX_ACTIVE_SPANS = 32`, `MAX_RECORDED_SPANS = 64`).
   - Méthodes d'ouverture de portée (`start_span`), de fermeture (`finish_span`) et de calcul de latence (`span_duration`).
4. **Contrôle d'accès par capacités (`TraceCap`)** :
   - Droits explicites : `TRACE_RECORD` (0x01), `TRACE_QUERY` (0x02), `TRACE_INJECT` (0x04), `TRACE_EXTRACT` (0x08), `TRACE_ADMIN` (0x80).

## Conséquences
- **Positives** :
  - Complétude des trois piliers d'observabilité (Métriques, Journaux/Audit, Traces).
  - Diagnostic précis des chemins critiques et goulots d'étranglement de latence.
  - Zéro dégradation mémoire ni autorité ambiante.
- **Négatives / Arbitrages** :
  - Nombre maximum de portées actives et archivées fixé statiquement en mémoire `#![no_std]`.
