use super::*;

fn make(name: &str, src: u16, san: u16, sink: u16) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: "test.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: src,
        sanitizer_caps: san,
        sink_caps: sink,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    }
}

#[test]
fn primary_label_priority() {
    // sink beats everything
    let s = make("f", 0xFF, 0xFF, 0x01);
    assert!(matches!(s.primary_label(), Some(DataLabel::Sink(_))));

    // source beats sanitizer
    let s = make("f", 0x01, 0x02, 0x00);
    assert!(matches!(s.primary_label(), Some(DataLabel::Source(_))));

    // sanitizer alone
    let s = make("f", 0x00, 0x04, 0x00);
    assert!(matches!(s.primary_label(), Some(DataLabel::Sanitizer(_))));

    // nothing
    let s = make("f", 0, 0, 0);
    assert!(s.primary_label().is_none());
}

#[test]
fn merge_unions_conservatively() {
    let a = make("foo", 0x01, 0x00, 0x00);
    let b = FuncSummary {
        sink_caps: 0x04,
        propagating_params: vec![0],
        tainted_sink_params: vec![0],
        callees: vec!["bar".into()],
        ..make("foo", 0x00, 0x02, 0x00)
    };

    let merged = merge_summaries(vec![a, b], None);
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "foo".into(),
        arity: Some(0),
    };
    let foo = merged.get(&key).unwrap();

    assert_eq!(foo.source_caps, 0x01);
    assert_eq!(foo.sanitizer_caps, 0x02);
    assert_eq!(foo.sink_caps, 0x04);
    assert!(foo.propagates_any());
    assert_eq!(foo.propagating_params, vec![0]);
    assert_eq!(foo.tainted_sink_params, vec![0]);
    assert_eq!(foo.callees, vec!["bar".to_string()]);
}

#[test]
fn is_interesting_detects_all_cases() {
    assert!(!make("f", 0, 0, 0).is_interesting());
    assert!(make("f", 1, 0, 0).is_interesting());
    assert!(make("f", 0, 1, 0).is_interesting());
    assert!(make("f", 0, 0, 1).is_interesting());

    let mut p = make("f", 0, 0, 0);
    p.propagating_params = vec![0];
    assert!(p.is_interesting());
}

#[test]
fn same_lang_different_namespace_no_merge() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "file_a.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "file_b.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: Cap::SHELL_ESCAPE.bits(),
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let global = merge_summaries(vec![a, b], None);

    // They should be stored under different FuncKeys
    let key_a = FuncKey {
        lang: Lang::Rust,
        namespace: "file_a.rs".into(),
        name: "helper".into(),
        arity: Some(0),
    };
    let key_b = FuncKey {
        lang: Lang::Rust,
        namespace: "file_b.rs".into(),
        name: "helper".into(),
        arity: Some(0),
    };
    assert!(global.get(&key_a).is_some());
    assert!(global.get(&key_b).is_some());
    // source_caps NOT merged
    assert_eq!(global.get(&key_a).unwrap().source_caps, Cap::all().bits());
    assert_eq!(global.get(&key_b).unwrap().source_caps, 0);
}

#[test]
fn same_lang_same_namespace_merges() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0x01,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "lib.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 0,
        sanitizer_caps: 0x02,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let global = merge_summaries(vec![a, b], None);
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "helper".into(),
        arity: Some(0),
    };
    let merged = global.get(&key).unwrap();
    assert_eq!(merged.source_caps, 0x01);
    assert_eq!(merged.sanitizer_caps, 0x02);
    assert!(merged.propagates_any());
    assert_eq!(merged.propagating_params, vec![0]);
}

#[test]
fn cross_lang_name_collision_stays_separate() {
    let py = FuncSummary {
        name: "process_data".into(),
        file_path: "handler.py".into(),
        lang: "python".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: Cap::all().bits(),
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };
    let c = FuncSummary {
        name: "process_data".into(),
        file_path: "handler.c".into(),
        lang: "c".into(),
        param_count: 1,
        param_names: vec!["s".into()],
        source_caps: 0,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let global = merge_summaries(vec![py, c], None);

    let py_key = FuncKey {
        lang: Lang::Python,
        namespace: "handler.py".into(),
        name: "process_data".into(),
        arity: Some(0),
    };
    let c_key = FuncKey {
        lang: Lang::C,
        namespace: "handler.c".into(),
        name: "process_data".into(),
        arity: Some(1),
    };

    assert!(global.get(&py_key).is_some());
    assert!(global.get(&c_key).is_some());
    // Python's source_caps NOT merged into C
    assert_eq!(global.get(&c_key).unwrap().source_caps, 0);
    assert_eq!(global.get(&py_key).unwrap().source_caps, Cap::all().bits());
}

#[test]
fn lookup_same_lang_returns_all_matches() {
    let a = FuncSummary {
        name: "helper".into(),
        file_path: "a.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 1,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };
    let b = FuncSummary {
        name: "helper".into(),
        file_path: "b.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: 2,
        sanitizer_caps: 0,
        sink_caps: 0,
        propagating_params: vec![],
        propagates_taint: false,
        tainted_sink_params: vec![],
        callees: vec![],
    };

    let global = merge_summaries(vec![a, b], None);
    let matches = global.lookup_same_lang(Lang::Rust, "helper");
    assert_eq!(matches.len(), 2);

    // No cross-language matches
    let py_matches = global.lookup_same_lang(Lang::Python, "helper");
    assert!(py_matches.is_empty());
}

#[test]
fn u16_caps_round_trip_serde() {
    let summary = FuncSummary {
        name: "dangerous".into(),
        file_path: "test.rs".into(),
        lang: "rust".into(),
        param_count: 1,
        param_names: vec!["input".into()],
        source_caps: (Cap::SQL_QUERY | Cap::CODE_EXEC).bits(),
        sanitizer_caps: Cap::CRYPTO.bits(),
        sink_caps: (Cap::SSRF | Cap::DESERIALIZE).bits(),
        propagating_params: vec![0],
        propagates_taint: false,
        tainted_sink_params: vec![0],
        callees: vec!["query".into()],
    };

    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(back.source_caps, (Cap::SQL_QUERY | Cap::CODE_EXEC).bits());
    assert_eq!(back.sanitizer_caps, Cap::CRYPTO.bits());
    assert_eq!(back.sink_caps, (Cap::SSRF | Cap::DESERIALIZE).bits());
    assert!(back.propagates_any());
    assert_eq!(back.propagating_params, vec![0]);
    // propagates_taint should NOT appear in serialized output
    assert!(!json.contains("propagates_taint"));
}

#[test]
fn backward_compat_u8_json_deserializes() {
    // Old u8-range values still deserialize correctly into u16 fields
    let json = r#"{
        "name": "old_func",
        "file_path": "legacy.py",
        "lang": "python",
        "param_count": 0,
        "param_names": [],
        "source_caps": 127,
        "sanitizer_caps": 2,
        "sink_caps": 4,
        "propagates_taint": false,
        "tainted_sink_params": [],
        "callees": []
    }"#;

    let summary: FuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(summary.source_caps, 127);
    assert_eq!(summary.sanitizer_caps, 2);
    assert_eq!(summary.sink_caps, 4);
}

#[test]
fn merge_propagating_params_union() {
    let a = FuncSummary {
        propagating_params: vec![0],
        ..make("foo", 0, 0, 0)
    };
    let b = FuncSummary {
        propagating_params: vec![1],
        ..make("foo", 0, 0, 0)
    };

    let merged = merge_summaries(vec![a, b], None);
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "foo".into(),
        arity: Some(0),
    };
    let foo = merged.get(&key).unwrap();
    assert_eq!(foo.propagating_params, vec![0, 1]);
    assert!(foo.propagates_any());
}

#[test]
fn backward_compat_legacy_propagates_taint_json() {
    // Old JSON with propagates_taint: true but no propagating_params
    let json = r#"{
        "name": "old_func",
        "file_path": "legacy.py",
        "lang": "python",
        "param_count": 1,
        "param_names": ["x"],
        "source_caps": 0,
        "sanitizer_caps": 0,
        "sink_caps": 0,
        "propagates_taint": true,
        "tainted_sink_params": [],
        "callees": []
    }"#;

    let summary: FuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.propagates_taint);
    assert!(summary.propagating_params.is_empty());
    assert!(summary.propagates_any());
    assert!(summary.is_interesting());
}

#[test]
fn propagating_params_round_trip_serde() {
    let summary = FuncSummary {
        propagating_params: vec![0, 2],
        ..make("foo", 0, 0, 0)
    };

    let json = serde_json::to_string(&summary).unwrap();
    let back: FuncSummary = serde_json::from_str(&json).unwrap();

    assert_eq!(back.propagating_params, vec![0, 2]);
    assert!(back.propagates_any());
    // propagates_taint must NOT appear in serialized output
    assert!(!json.contains("propagates_taint"));
}

#[test]
fn snapshot_caps_detects_change() {
    let a = FuncSummary {
        source_caps: 0x01,
        propagating_params: vec![0],
        ..make("foo", 0, 0, 0)
    };
    let b = make("bar", 0, 0, 0x04);

    let mut gs = merge_summaries(vec![a, b], None);

    let snap1 = gs.snapshot_caps();

    // Mutate one summary by inserting a changed version.
    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "test.rs".into(),
        name: "bar".into(),
        arity: Some(0),
    };
    let updated = FuncSummary {
        sink_caps: 0x08,
        ..make("bar", 0, 0, 0)
    };
    gs.insert(key, updated);

    let snap2 = gs.snapshot_caps();

    assert_ne!(snap1, snap2, "snapshot should detect changed caps");

    // Without further changes, snapshot should be stable.
    let snap3 = gs.snapshot_caps();
    assert_eq!(snap2, snap3, "snapshot should be stable without changes");
}

// ── SSA summary tests ───────────────────────────────────────────────────

use super::ssa_summary::{SsaFuncSummary, TaintTransform};

#[test]
fn ssa_summary_serde_round_trip_identity() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_strip_bits() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE | Cap::URL_ENCODE))],
        param_to_sink: vec![(1, Cap::SQL_QUERY)],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_add_bits() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(2, TaintTransform::AddBits(Cap::CODE_EXEC))],
        param_to_sink: vec![],
        source_caps: Cap::ENV_VAR | Cap::FILE_IO,
        param_to_sink_param: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_all_variants() {
    let summary = SsaFuncSummary {
        param_to_return: vec![
            (0, TaintTransform::Identity),
            (1, TaintTransform::StripBits(Cap::SHELL_ESCAPE)),
            (2, TaintTransform::AddBits(Cap::SSRF)),
        ],
        param_to_sink: vec![(0, Cap::SQL_QUERY), (1, Cap::CODE_EXEC | Cap::CRYPTO)],
        source_caps: Cap::all(),
        param_to_sink_param: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn global_summaries_insert_ssa_exact_key_replacement() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: Lang::Python,
        namespace: "app.py".into(),
        name: "process".into(),
        arity: Some(1),
    };

    let v1 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
    };
    gs.insert_ssa(key.clone(), v1.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v1));

    // Replace with a different summary — exact replacement, not union
    let v2 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
        param_to_sink: vec![(0, Cap::SQL_QUERY)],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
    };
    gs.insert_ssa(key.clone(), v2.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v2));
}

#[test]
fn global_summaries_merge_with_ssa_entries() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key_a = FuncKey {
        lang: Lang::Python,
        namespace: "a.py".into(),
        name: "foo".into(),
        arity: Some(1),
    };
    let key_b = FuncKey {
        lang: Lang::Python,
        namespace: "b.py".into(),
        name: "bar".into(),
        arity: Some(2),
    };

    let sum_a = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
    };
    let sum_b = SsaFuncSummary {
        param_to_return: vec![],
        param_to_sink: vec![(0, Cap::CODE_EXEC)],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
    };

    gs1.insert_ssa(key_a.clone(), sum_a.clone());
    gs2.insert_ssa(key_b.clone(), sum_b.clone());

    gs1.merge(gs2);

    assert_eq!(gs1.get_ssa(&key_a), Some(&sum_a));
    assert_eq!(gs1.get_ssa(&key_b), Some(&sum_b));
}

#[test]
fn global_summaries_is_empty_considers_ssa() {
    let mut gs = GlobalSummaries::new();
    assert!(gs.is_empty());

    let key = FuncKey {
        lang: Lang::Rust,
        namespace: "lib.rs".into(),
        name: "f".into(),
        arity: Some(1),
    };
    gs.insert_ssa(key, SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
    });

    assert!(!gs.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_param_to_sink_param() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![(0, Cap::SQL_QUERY)],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![
            (0, 0, Cap::SQL_QUERY),
            (1, 0, Cap::CODE_EXEC),
        ],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.param_to_sink_param.len(), 2);
    assert_eq!(back.param_to_sink_param[0], (0, 0, Cap::SQL_QUERY));
    assert_eq!(back.param_to_sink_param[1], (1, 0, Cap::CODE_EXEC));
}

#[test]
fn ssa_summary_backward_compat_missing_param_to_sink_param() {
    // Old JSON without param_to_sink_param should deserialize with empty vec
    let json = r#"{
        "param_to_return": [[0, "Identity"]],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.param_to_sink_param.is_empty());
}
