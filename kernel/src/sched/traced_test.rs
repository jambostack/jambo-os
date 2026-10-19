//! Module de validation du Traçage Distribué & Analyse de Latence (Phase 70 - v0.2.68)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_traced::{
    trace_flags, trace_rights, JamboTraceDaemon, SpanStatus, TraceCap, TraceCollector,
    TraceContext, TraceSpan, MAX_SPAN_NAME_LEN,
};

/// Exécute la suite de tests du traçage distribué et analyse de latence (Phase 70)
pub fn execute_distributed_tracing_test() -> bool {
    kprintln!(
        "[TRACE/TEST] Démarrage du test du traçage distribué et analyse de latence (Phase 70)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (TraceCap)
    let admin_cap = TraceCap::new(Handle::new(70, 1), trace_rights::ALL);
    assert!(admin_cap.has_right(trace_rights::TRACE_RECORD));
    assert!(admin_cap.has_right(trace_rights::TRACE_QUERY));
    assert!(admin_cap.has_right(trace_rights::TRACE_INJECT));
    assert!(admin_cap.has_right(trace_rights::TRACE_EXTRACT));
    assert!(admin_cap.has_right(trace_rights::TRACE_ADMIN));

    let query_only_cap = admin_cap
        .attenuate(trace_rights::TRACE_QUERY)
        .expect("attenuate TraceCap to query-only");
    let mut raw_collector = TraceCollector::new();
    let dummy_ctx = TraceContext::new([1; 16], 1, None, trace_flags::FLAG_SAMPLED);
    assert_eq!(
        raw_collector.start_span(&query_only_cap, b"denied_span", &dummy_ctx, 100),
        Err(SysError::PermissionDenied),
        "Démarrage de portée sans droit TRACE_RECORD doit être rejeté"
    );
    kprintln!("[TRACE/CAP] Confinement capabilaire TraceCap et autorité ambiante zéro validés");

    // 2. Contexte de trace causale W3C et sérialisation compacte
    let trace_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let root_ctx = TraceContext::new(trace_id, 1001, None, trace_flags::FLAG_SAMPLED);
    assert!(root_ctx.is_sampled());
    assert_eq!(root_ctx.parent_span_id, None);

    let child_ctx = root_ctx.create_child(1002);
    assert_eq!(child_ctx.trace_id, trace_id);
    assert_eq!(child_ctx.span_id, 1002);
    assert_eq!(child_ctx.parent_span_id, Some(1001));

    let bytes = child_ctx.to_bytes();
    let decoded = TraceContext::from_bytes(&bytes).expect("decode TraceContext");
    assert_eq!(decoded, child_ctx);
    kprintln!("[TRACE/CONTEXT] Contexte de trace causale W3C et sérialisation compacte validés");

    // 3. Cycle de vie de portée, calcul de latence et transition d'état
    let mut collector = TraceCollector::new();
    let span_id = collector.allocate_span_id();
    let ctx = TraceContext::new(trace_id, span_id, None, trace_flags::FLAG_SAMPLED);

    collector
        .start_span(&admin_cap, b"db.transaction.commit", &ctx, 1000)
        .expect("start span");
    assert_eq!(collector.active_count(), 1);

    collector
        .finish_span(&admin_cap, span_id, SpanStatus::Ok, 1250)
        .expect("finish span");
    assert_eq!(collector.active_count(), 0);
    assert_eq!(collector.total_recorded(), 1);

    let span = collector
        .find_recorded(&admin_cap, span_id)
        .expect("find span")
        .expect("span present");
    assert_eq!(span.span_id, span_id);
    assert_eq!(span.status, SpanStatus::Ok);
    assert_eq!(span.duration(), Some(250));
    kprintln!(
        "[TRACE/LIFECYCLE] Cycle de vie de portée, calcul de latence et transition d'état validés"
    );

    // 4. Arborescence distribuée et recherche par identifiant de trace
    let id_child = collector.allocate_span_id();
    let child_ctx2 = ctx.create_child(id_child);
    collector
        .start_span(&admin_cap, b"db.wal.append", &child_ctx2, 1050)
        .expect("start child span");
    collector
        .finish_span(&admin_cap, id_child, SpanStatus::Ok, 1150)
        .expect("finish child span");

    let mut out_spans = [TraceSpan {
        span_id: 0,
        trace_id: [0; 16],
        parent_span_id: None,
        name: [0; MAX_SPAN_NAME_LEN],
        name_len: 0,
        start_time: 0,
        end_time: 0,
        status: SpanStatus::Active,
    }; 4];
    let query_cnt = collector
        .query_by_trace(&admin_cap, &trace_id, &mut out_spans)
        .expect("query trace");
    assert_eq!(query_cnt, 2);
    kprintln!(
        "[TRACE/QUERY] Arborescence distribuée et recherche par identifiant de trace validées"
    );

    // 5. Démon orchestrateur JamboTraceDaemon
    let mut daemon = JamboTraceDaemon::new();
    assert_eq!(daemon.total_recorded(), 1);
    assert_eq!(daemon.active_count(), 0);

    let d_trace_id = [0x42; 16];
    let d_span_id = daemon.allocate_span_id();
    let d_ctx = TraceContext::new(d_trace_id, d_span_id, None, trace_flags::FLAG_SAMPLED);

    daemon
        .start_span(b"ipc.msg_send", &d_ctx, 500)
        .expect("d start span");
    assert_eq!(daemon.active_count(), 1);

    daemon
        .finish_span(d_span_id, SpanStatus::Ok, 560)
        .expect("d finish span");
    assert_eq!(daemon.active_count(), 0);
    assert_eq!(daemon.total_recorded(), 2);

    let d_span = daemon
        .find_recorded(d_span_id)
        .expect("d find")
        .expect("d span exists");
    assert_eq!(d_span.duration(), Some(60));
    kprintln!("[TRACE/DAEMON] Démon JamboTraceDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'trace status'
    let (st_stat, len_stat) = shell.execute_line("trace status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("TRAÇAGE DISTRIBUÉ"));
    assert!(str_stat.contains("Portées archivées"));
    assert!(str_stat.contains("TraceCap"));
    kprintln!("[TRACE/SHELL] Commande 'trace status' validée");

    // Commande 'trace span'
    let (st_span, len_span) = shell.execute_line("trace span net.packet_rx", &mut out_buf);
    assert_eq!(st_span, ShellStatus::Success);
    let str_span = core::str::from_utf8(&out_buf[..len_span]).unwrap_or("");
    assert!(str_span.contains("[TRACE/SPAN]"));
    assert!(str_span.contains("net.packet_rx"));
    assert!(str_span.contains("Durée: 45 ticks"));
    kprintln!("[TRACE/SHELL] Commande 'trace span' validée");

    // Commande 'trace query 1'
    let (st_q, len_q) = shell.execute_line("trace query 1", &mut out_buf);
    assert_eq!(st_q, ShellStatus::Success);
    let str_q = core::str::from_utf8(&out_buf[..len_q]).unwrap_or("");
    assert!(str_q.contains("[TRACE/QUERY]"));
    assert!(str_q.contains("boot.bootstrap"));
    kprintln!("[TRACE/SHELL] Commande 'trace query' validée");

    kprintln!("[TRACE/PASS] Traçage distribué et analyse de latence validés avec succès.");
    true
}
