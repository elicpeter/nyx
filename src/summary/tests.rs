use super::*;

fn make(name: &str, src: u8, san: u8, sink: u8) -> FuncSummary {
    FuncSummary {
        name: name.into(),
        file_path: "test.rs".into(),
        lang: "rust".into(),
        param_count: 0,
        param_names: vec![],
        source_caps: src,
        sanitizer_caps: san,
        sink_caps: sink,
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
        propagates_taint: true,
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
    assert!(foo.propagates_taint);
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
    p.propagates_taint = true;
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
        propagates_taint: true,
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
    assert!(merged.propagates_taint);
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
        propagates_taint: true,
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
