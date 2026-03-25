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
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn ssa_summary_serde_round_trip_strip_bits() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(
            0,
            TaintTransform::StripBits(Cap::HTML_ESCAPE | Cap::URL_ENCODE),
        )],
        param_to_sink: vec![(1, Cap::SQL_QUERY)],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
    };
    gs.insert_ssa(key.clone(), v1.clone());
    assert_eq!(gs.get_ssa(&key), Some(&v1));

    // Replace with a different summary — exact replacement, not union
    let v2 = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
        param_to_sink: vec![(0, Cap::SQL_QUERY)],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
    };
    let sum_b = SsaFuncSummary {
        param_to_return: vec![],
        param_to_sink: vec![(0, Cap::CODE_EXEC)],
        source_caps: Cap::ENV_VAR,
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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
    gs.insert_ssa(
        key,
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
        },
    );

    assert!(!gs.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_param_to_sink_param() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![(0, Cap::SQL_QUERY)],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![(0, 0, Cap::SQL_QUERY), (1, 0, Cap::CODE_EXEC)],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
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

#[test]
fn ssa_summary_serde_round_trip_container_fields() {
    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![0],
        param_to_container_store: vec![(1, 0)],
        return_type: None,
        return_abstract: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.param_container_to_return, vec![0]);
    assert_eq!(back.param_to_container_store, vec![(1, 0)]);
}

#[test]
fn ssa_summary_backward_compat_missing_container_fields() {
    // Old JSON without container fields should deserialize with empty vecs
    let json = r#"{
        "param_to_return": [[0, "Identity"]],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert!(summary.param_container_to_return.is_empty());
    assert!(summary.param_to_container_store.is_empty());
}

#[test]
fn ssa_summary_serde_round_trip_return_abstract() {
    use crate::abstract_interp::{AbstractValue, BitFact, IntervalFact, StringFact};

    let summary = SsaFuncSummary {
        param_to_return: vec![(0, TaintTransform::Identity)],
        param_to_sink: vec![],
        source_caps: Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: Some(AbstractValue {
            interval: IntervalFact {
                lo: Some(-2_147_483_648),
                hi: Some(2_147_483_647),
            },
            string: StringFact::top(),
            bits: BitFact::top(),
        }),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SsaFuncSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert!(back.return_abstract.is_some());
    let abs = back.return_abstract.unwrap();
    assert_eq!(abs.interval.lo, Some(-2_147_483_648));
    assert_eq!(abs.interval.hi, Some(2_147_483_647));
    assert!(abs.string.is_top());
}

#[test]
fn ssa_summary_backward_compat_missing_return_abstract() {
    // Old JSON without return_abstract should deserialize with None
    let json = r#"{
        "param_to_return": [],
        "param_to_sink": [],
        "source_caps": 0
    }"#;
    let summary: SsaFuncSummary = serde_json::from_str(json).unwrap();
    assert_eq!(summary.return_abstract, None);
}

// ── Phase 30: CalleeSsaBody serde + GlobalSummaries body resolution ──────

/// Helper: build a minimal CalleeSsaBody with a given number of blocks.
#[allow(dead_code)] // used by tests below
fn make_callee_body(num_blocks: usize, param_count: usize) -> crate::taint::ssa_transfer::CalleeSsaBody {
    use crate::ssa::ir::*;
    use smallvec::smallvec;

    let mut blocks = Vec::new();
    for i in 0..num_blocks {
        blocks.push(SsaBlock {
            id: BlockId(i as u32),
            phis: vec![],
            body: vec![SsaInst {
                value: SsaValue(i as u32),
                op: SsaOp::Const(Some("0".into())),
                cfg_node: petgraph::graph::NodeIndex::new(0),
                var_name: None,
                span: (0, 0),
            }],
            terminator: if i + 1 < num_blocks {
                Terminator::Goto(BlockId((i + 1) as u32))
            } else {
                Terminator::Return(Some(SsaValue(0)))
            },
            preds: smallvec![],
            succs: smallvec![],
        });
    }

    let value_defs: Vec<ValueDef> = (0..num_blocks)
        .map(|i| ValueDef {
            var_name: None,
            cfg_node: petgraph::graph::NodeIndex::new(0),
            block: BlockId(i as u32),
        })
        .collect();

    crate::taint::ssa_transfer::CalleeSsaBody {
        ssa: SsaBody {
            blocks,
            entry: BlockId(0),
            value_defs,
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
        },
        opt: crate::ssa::OptimizeResult {
            const_values: std::collections::HashMap::new(),
            type_facts: crate::ssa::type_facts::TypeFactResult {
                facts: std::collections::HashMap::new(),
            },
            alias_result: crate::ssa::alias::BaseAliasResult::empty(),
            points_to: crate::ssa::heap::PointsToResult::empty(),
            branches_pruned: 0,
            copies_eliminated: 0,
            dead_defs_removed: 0,
        },
        param_count,
        node_meta: std::collections::HashMap::new(),
    }
}

#[test]
fn callee_body_serde_round_trip_empty() {
    let body = make_callee_body(1, 0);
    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();
    assert_eq!(back.param_count, 0);
    assert_eq!(back.ssa.blocks.len(), 1);
    assert!(back.node_meta.is_empty());
}

#[test]
fn callee_body_serde_round_trip_multi_block() {
    let body = make_callee_body(5, 2);
    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();
    assert_eq!(back.param_count, 2);
    assert_eq!(back.ssa.blocks.len(), 5);
    // Verify block structure survived round-trip
    assert_eq!(back.ssa.entry, crate::ssa::ir::BlockId(0));
    assert_eq!(back.ssa.value_defs.len(), 5);
}

#[test]
fn callee_body_serde_round_trip_with_node_meta() {
    use crate::taint::ssa_transfer::CrossFileNodeMeta;
    use crate::labels::{Cap, DataLabel};

    let mut body = make_callee_body(2, 1);
    body.node_meta.insert(
        0,
        CrossFileNodeMeta {
            bin_op: Some(crate::cfg::BinOp::Add),
            labels: smallvec::smallvec![DataLabel::Sink(Cap::HTML_ESCAPE)],
        },
    );
    body.node_meta.insert(
        1,
        CrossFileNodeMeta {
            bin_op: None,
            labels: smallvec::smallvec![],
        },
    );

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();

    assert_eq!(back.node_meta.len(), 2);
    let meta0 = &back.node_meta[&0];
    assert_eq!(meta0.bin_op, Some(crate::cfg::BinOp::Add));
    assert_eq!(meta0.labels.len(), 1);
    assert!(matches!(meta0.labels[0], DataLabel::Sink(cap) if cap == Cap::HTML_ESCAPE));
    assert!(back.node_meta[&1].labels.is_empty());
}

#[test]
fn callee_body_serde_node_meta_skipped_when_empty() {
    // Verify #[serde(skip_serializing_if)] works: empty node_meta not in JSON
    let body = make_callee_body(1, 0);
    let json = serde_json::to_string(&body).unwrap();
    assert!(!json.contains("node_meta"), "empty node_meta should be omitted from JSON");

    // But it should deserialize fine from JSON without node_meta field
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();
    assert!(back.node_meta.is_empty());
}

#[test]
fn callee_body_serde_with_all_ssa_op_variants() {
    use crate::ssa::ir::*;
    use smallvec::smallvec;

    let mut body = make_callee_body(1, 0);
    // Replace the single block's body with all SsaOp variants
    let node = petgraph::graph::NodeIndex::new(0);
    body.ssa.blocks[0].body = vec![
        SsaInst { value: SsaValue(0), op: SsaOp::Const(Some("hello".into())), cfg_node: node, var_name: None, span: (0, 5) },
        SsaInst { value: SsaValue(1), op: SsaOp::Const(None), cfg_node: node, var_name: None, span: (0, 0) },
        SsaInst { value: SsaValue(2), op: SsaOp::Source, cfg_node: node, var_name: Some("src".into()), span: (6, 10) },
        SsaInst { value: SsaValue(3), op: SsaOp::Param { index: 0 }, cfg_node: node, var_name: Some("p0".into()), span: (0, 0) },
        SsaInst { value: SsaValue(4), op: SsaOp::CatchParam, cfg_node: node, var_name: None, span: (0, 0) },
        SsaInst { value: SsaValue(5), op: SsaOp::Nop, cfg_node: node, var_name: None, span: (0, 0) },
        SsaInst { value: SsaValue(6), op: SsaOp::Assign(smallvec![SsaValue(0), SsaValue(1)]), cfg_node: node, var_name: None, span: (0, 0) },
        SsaInst {
            value: SsaValue(7),
            op: SsaOp::Call {
                callee: "foo".into(),
                args: vec![smallvec![SsaValue(0)], smallvec![SsaValue(1)]],
                receiver: Some(SsaValue(2)),
            },
            cfg_node: node,
            var_name: None,
            span: (11, 20),
        },
    ];
    body.ssa.blocks[0].phis = vec![
        SsaInst {
            value: SsaValue(8),
            op: SsaOp::Phi(smallvec![(BlockId(0), SsaValue(0)), (BlockId(1), SsaValue(1))]),
            cfg_node: node,
            var_name: None,
            span: (0, 0),
        },
    ];

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();

    assert_eq!(back.ssa.blocks[0].body.len(), 8);
    assert_eq!(back.ssa.blocks[0].phis.len(), 1);

    // Spot check: Call op preserved
    match &back.ssa.blocks[0].body[7].op {
        SsaOp::Call { callee, args, receiver } => {
            assert_eq!(callee, "foo");
            assert_eq!(args.len(), 2);
            assert_eq!(*receiver, Some(SsaValue(2)));
        }
        other => panic!("expected Call, got {:?}", other),
    }
    // Spot check: Phi op preserved
    match &back.ssa.blocks[0].phis[0].op {
        SsaOp::Phi(ops) => {
            assert_eq!(ops.len(), 2);
            assert_eq!(ops[0], (BlockId(0), SsaValue(0)));
        }
        other => panic!("expected Phi, got {:?}", other),
    }
}

#[test]
fn callee_body_serde_with_branch_terminator() {
    use crate::ssa::ir::*;
    use crate::constraint::lower::ConditionExpr;

    let mut body = make_callee_body(3, 0);
    // Set a Branch terminator with a condition
    body.ssa.blocks[0].terminator = Terminator::Branch {
        cond: petgraph::graph::NodeIndex::new(0),
        true_blk: BlockId(1),
        false_blk: BlockId(2),
        condition: Some(Box::new(ConditionExpr::BoolTest {
            var: SsaValue(0),
        })),
    };

    let json = serde_json::to_string(&body).unwrap();
    let back: crate::taint::ssa_transfer::CalleeSsaBody =
        serde_json::from_str(&json).unwrap();

    match &back.ssa.blocks[0].terminator {
        Terminator::Branch { true_blk, false_blk, condition, .. } => {
            assert_eq!(*true_blk, BlockId(1));
            assert_eq!(*false_blk, BlockId(2));
            assert!(condition.is_some());
            match condition.as_deref() {
                Some(ConditionExpr::BoolTest { var }) => {
                    assert_eq!(*var, SsaValue(0));
                }
                other => panic!("expected BoolTest, got {:?}", other),
            }
        }
        other => panic!("expected Branch, got {:?}", other),
    }
}

// ── GlobalSummaries body resolution ──────────────────────────────────────

#[test]
fn global_summaries_insert_body_exact_key_replacement() {
    let mut gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "helper.py".into(),
        name: "transform".into(),
        arity: Some(2),
    };

    let body1 = make_callee_body(3, 2);
    let body2 = make_callee_body(5, 2);

    gs.insert_body(key.clone(), body1);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 3);

    // Second insert replaces (exact-key, no union)
    gs.insert_body(key.clone(), body2);
    assert_eq!(gs.get_body(&key).unwrap().ssa.blocks.len(), 5);
}

#[test]
fn global_summaries_get_body_not_found() {
    let gs = GlobalSummaries::new();
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "missing.py".into(),
        name: "nope".into(),
        arity: Some(0),
    };
    assert!(gs.get_body(&key).is_none());
}

#[test]
fn global_summaries_merge_includes_bodies() {
    let mut gs1 = GlobalSummaries::new();
    let mut gs2 = GlobalSummaries::new();

    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "func_a".into(),
        arity: Some(1),
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "func_b".into(),
        arity: Some(2),
    };

    // Need to also insert regular summaries so the by_lang_name index is populated
    gs1.insert(key1.clone(), make("func_a", 0, 0, 0));
    gs1.insert_body(key1.clone(), make_callee_body(2, 1));

    gs2.insert(key2.clone(), make("func_b", 0, 0, 0));
    gs2.insert_body(key2.clone(), make_callee_body(4, 2));

    gs1.merge(gs2);

    assert!(gs1.get_body(&key1).is_some());
    assert!(gs1.get_body(&key2).is_some());
    assert_eq!(gs1.get_body(&key1).unwrap().ssa.blocks.len(), 2);
    assert_eq!(gs1.get_body(&key2).unwrap().ssa.blocks.len(), 4);
}

#[test]
fn global_summaries_resolve_callee_body_exact_match() {
    let mut gs = GlobalSummaries::new();

    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "util.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };

    gs.insert(key.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key.clone(), make_callee_body(3, 1));

    // Resolve with matching lang/name/arity
    let resolved = gs.resolve_callee_body(
        crate::symbol::Lang::Python,
        "helper",
        Some(1),
        "app.py",
    );
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().ssa.blocks.len(), 3);
}

#[test]
fn global_summaries_resolve_callee_body_not_found() {
    let gs = GlobalSummaries::new();

    let resolved = gs.resolve_callee_body(
        crate::symbol::Lang::Python,
        "missing",
        Some(1),
        "app.py",
    );
    assert!(resolved.is_none());
}

#[test]
fn global_summaries_resolve_callee_body_ambiguous_returns_none() {
    let mut gs = GlobalSummaries::new();

    // Two functions with same name but different namespaces
    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };

    gs.insert(key1.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key1.clone(), make_callee_body(2, 1));
    gs.insert(key2.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key2.clone(), make_callee_body(4, 1));

    // Resolution from a third namespace → ambiguous → None
    let resolved = gs.resolve_callee_body(
        crate::symbol::Lang::Python,
        "helper",
        Some(1),
        "c.py",
    );
    assert!(resolved.is_none(), "ambiguous resolution should return None");
}

#[test]
fn global_summaries_resolve_callee_body_namespace_disambiguates() {
    let mut gs = GlobalSummaries::new();

    let key1 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "a.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };
    let key2 = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "b.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };

    gs.insert(key1.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key1.clone(), make_callee_body(2, 1));
    gs.insert(key2.clone(), make("helper", 0, 0, 0));
    gs.insert_body(key2.clone(), make_callee_body(4, 1));

    // Resolution from a.py → namespace match → key1 (2 blocks)
    let resolved = gs.resolve_callee_body(
        crate::symbol::Lang::Python,
        "helper",
        Some(1),
        "a.py",
    );
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap().ssa.blocks.len(), 2);
}

#[test]
fn global_summaries_resolve_body_requires_body_present() {
    let mut gs = GlobalSummaries::new();

    // Insert summary but no body
    let key = FuncKey {
        lang: crate::symbol::Lang::Python,
        namespace: "util.py".into(),
        name: "helper".into(),
        arity: Some(1),
    };
    gs.insert(key.clone(), make("helper", 0, 0, 0));
    gs.insert_ssa(key.clone(), SsaFuncSummary {
        param_to_return: vec![],
        param_to_sink: vec![],
        source_caps: crate::labels::Cap::empty(),
        param_to_sink_param: vec![],
        param_container_to_return: vec![],
        param_to_container_store: vec![],
        return_type: None,
        return_abstract: None,
    });
    // Don't insert body

    // Resolution finds the key but no body
    let resolved = gs.resolve_callee_body(
        crate::symbol::Lang::Python,
        "helper",
        Some(1),
        "app.py",
    );
    assert!(resolved.is_none(), "should return None when key resolves but no body stored");
}
