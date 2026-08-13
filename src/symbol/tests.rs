use super::*;

#[test]
fn lang_round_trip() {
    for slug in &[
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "typescript",
        "javascript",
    ] {
        let lang = Lang::from_slug(slug).unwrap();
        assert_eq!(lang.as_str(), *slug);
    }
}

#[test]
fn lang_aliases() {
    assert_eq!(Lang::from_slug("js"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_slug("ts"), Some(Lang::TypeScript));
}

#[test]
fn func_key_display() {
    let k = FuncKey::new_function(Lang::Rust, "src/lib.rs", "my_func", Some(2));
    assert_eq!(k.to_string(), "rust::src/lib.rs::my_func/2");
}

#[test]
fn func_key_display_method_with_container() {
    let k = FuncKey::from_parts(
        Lang::Java,
        "src/OrderService.java",
        "OrderService",
        "process",
        Some(1),
        None,
        FuncKind::Method,
    );
    assert_eq!(
        k.to_string(),
        "java::src/OrderService.java::OrderService::process/1[method]"
    );
}

#[test]
fn func_key_display_closure_with_disambig() {
    let k = FuncKey::from_parts(
        Lang::JavaScript,
        "src/app.js",
        "outer",
        "<anon>",
        Some(0),
        Some(421),
        FuncKind::Closure,
    );
    assert_eq!(
        k.to_string(),
        "javascript::src/app.js::outer::<anon>/0#421[closure]"
    );
}

#[test]
fn func_key_qualified_name_free_function() {
    let k = FuncKey::new_function(Lang::Rust, "lib.rs", "foo", Some(0));
    assert_eq!(k.qualified_name(), "foo");
}

#[test]
fn func_key_qualified_name_method() {
    let k = FuncKey::from_parts(
        Lang::Python,
        "app.py",
        "Service",
        "run",
        Some(1),
        None,
        FuncKind::Method,
    );
    assert_eq!(k.qualified_name(), "Service::run");
}

#[test]
fn method_vs_function_same_name_are_distinct_keys() {
    let free = FuncKey::new_function(Lang::Python, "app.py", "process", Some(1));
    let method = FuncKey::from_parts(
        Lang::Python,
        "app.py",
        "Worker",
        "process",
        Some(1),
        None,
        FuncKind::Method,
    );
    assert_ne!(free, method);
    assert_ne!(free.qualified_name(), method.qualified_name());
}

#[test]
fn two_methods_same_name_different_containers_are_distinct() {
    let order = FuncKey::from_parts(
        Lang::Java,
        "src/Services.java",
        "OrderService",
        "process",
        Some(1),
        None,
        FuncKind::Method,
    );
    let user = FuncKey::from_parts(
        Lang::Java,
        "src/Services.java",
        "UserService",
        "process",
        Some(1),
        None,
        FuncKind::Method,
    );
    assert_ne!(order, user);
}

#[test]
fn closure_disambig_separates_same_name_siblings() {
    let a = FuncKey::from_parts(
        Lang::JavaScript,
        "f.js",
        "outer",
        "<anon>",
        Some(0),
        Some(100),
        FuncKind::Closure,
    );
    let b = FuncKey::from_parts(
        Lang::JavaScript,
        "f.js",
        "outer",
        "<anon>",
        Some(0),
        Some(205),
        FuncKind::Closure,
    );
    assert_ne!(a, b);
}

#[test]
fn legacy_json_without_new_fields_deserialises() {
    // JSON written before container/disambig/kind existed must still parse.
    let json = r#"{
        "lang": "rust",
        "namespace": "src/lib.rs",
        "name": "helper",
        "arity": 1
    }"#;
    let key: FuncKey = serde_json::from_str(json).unwrap();
    assert_eq!(key.name, "helper");
    assert_eq!(key.container, "");
    assert_eq!(key.disambig, None);
    assert_eq!(key.kind, FuncKind::Function);
}

#[test]
fn round_trip_full_fields_serde() {
    let k = FuncKey::from_parts(
        Lang::Ruby,
        "lib/worker.rb",
        "Admin::Worker",
        "run",
        Some(2),
        Some(9001),
        FuncKind::Method,
    );
    let json = serde_json::to_string(&k).unwrap();
    let back: FuncKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
}

#[test]
fn normalize_strips_root() {
    assert_eq!(
        normalize_namespace("/home/user/proj/src/lib.rs", Some("/home/user/proj")),
        "src/lib.rs"
    );
    assert_eq!(
        normalize_namespace("/home/user/proj/src/lib.rs", Some("/home/user/proj/")),
        "src/lib.rs"
    );
}

#[test]
fn normalize_fallback_on_no_root() {
    assert_eq!(normalize_namespace("test.rs", None), "test.rs");
}

#[test]
fn normalize_fallback_on_mismatch() {
    assert_eq!(
        normalize_namespace("/other/path/lib.rs", Some("/home/user/proj")),
        "/other/path/lib.rs"
    );
}

// ── Phase 02: extension + shebang + content sniff ──────────────────────────

use std::path::Path;

#[test]
fn from_extension_accepts_phase02_additions() {
    // Each of the new extensions must round-trip to the documented language.
    assert_eq!(Lang::from_extension("cjs"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("mjs"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("jsx"), Some(Lang::JavaScript));
    assert_eq!(Lang::from_extension("mts"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("cts"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("tsx"), Some(Lang::TypeScript));
    assert_eq!(Lang::from_extension("pyi"), Some(Lang::Python));
    assert_eq!(Lang::from_extension("kt"), Some(Lang::Java));
    assert_eq!(Lang::from_extension("kts"), Some(Lang::Java));
    // C++ inventory extended in Phase 01 / ast.rs: keep the helper aligned.
    assert_eq!(Lang::from_extension("cc"), Some(Lang::Cpp));
    assert_eq!(Lang::from_extension("hpp"), Some(Lang::Cpp));
}

#[test]
fn from_extension_is_case_insensitive() {
    // Real-world filesystems mix case (especially on Windows / macOS).
    assert_eq!(Lang::from_extension("PY"), Some(Lang::Python));
    assert_eq!(Lang::from_extension("Java"), Some(Lang::Java));
    assert_eq!(Lang::from_extension("JSX"), Some(Lang::JavaScript));
}

#[test]
fn from_path_or_content_extension_wins() {
    // Even with a misleading shebang the explicit extension must take
    // precedence — file-format ground truth beats hand-edited interpreter
    // hints.
    let head = b"#!/usr/bin/env node\nprint('hi')\n";
    let path = Path::new("/tmp/script.py");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_python_env() {
    let head = b"#!/usr/bin/env python3\nimport os\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_node_direct() {
    let head = b"#!/usr/local/bin/node\nconsole.log(1)\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(
        Lang::from_path_or_content(path, head),
        Some(Lang::JavaScript)
    );
}

#[test]
fn from_path_or_content_shebang_ruby_direct() {
    let head = b"#!/usr/bin/ruby\nputs 1\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Ruby));
}

#[test]
fn from_path_or_content_shebang_php() {
    let head = b"#!/usr/bin/env php\n<?php echo 1;\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_shebang_with_env_dash_flag() {
    // `env -S` is the portable trick for passing args; the second token after
    // env is the real interpreter.
    let head = b"#!/usr/bin/env -S python3 -u\nimport sys\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_shebang_unknown_interpreter_falls_through_to_sniff() {
    // bash isn't a supported language — shebang returns None — and the
    // body's `<?php` opener should still be picked up by the content sniff.
    let head = b"#!/bin/bash\n<?php echo 1; ?>\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_content_sniff_php() {
    let head = b"<?php echo 'hi'; ?>";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Php));
}

#[test]
fn from_path_or_content_content_sniff_go_package_main() {
    let head = b"package main\n\nimport \"fmt\"\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Go));
}

#[test]
fn from_path_or_content_content_sniff_java_package_semicolon() {
    let head = b"package com.example.app;\n\npublic class Main {}\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Java));
}

#[test]
fn from_path_or_content_content_sniff_python_def() {
    let head = b"\"\"\"docstring\"\"\"\n\ndef handle(x):\n    return x\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Python));
}

#[test]
fn from_path_or_content_content_sniff_rust_use_std() {
    let head = b"use std::path::Path;\n\nfn main() {}\n";
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, head), Some(Lang::Rust));
}

#[test]
fn from_path_or_content_returns_none_when_nothing_matches() {
    let path = Path::new("/tmp/runme.weird");
    assert_eq!(Lang::from_path_or_content(path, b"plain text data"), None);
}

#[test]
fn from_path_or_content_empty_head_with_unknown_extension_returns_none() {
    let path = Path::new("/tmp/runme");
    assert_eq!(Lang::from_path_or_content(path, b""), None);
}

// --- Precomputed identity hash invariants (perfhunt session-0012) ---

/// Hash a `FuncKey` through the standard `Hasher` path (also triggers the
/// `cfg(test)` integrity assertion inside `FuncKey::hash`).
fn fk_hash(k: &FuncKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut s = std::collections::hash_map::DefaultHasher::new();
    k.hash(&mut s);
    s.finish()
}

#[test]
fn funckey_from_parts_hash_stable_under_recompute() {
    let mut k = FuncKey::from_parts(
        Lang::Go,
        "server/app.go",
        "S",
        "m",
        Some(2),
        Some(7),
        FuncKind::Method,
    );
    let before = fk_hash(&k);
    k.recompute_hash();
    assert_eq!(before, fk_hash(&k), "recompute must be idempotent");
}

#[test]
fn funckey_setters_keep_key_equal_to_fresh_construction() {
    let mut k = FuncKey::from_parts(Lang::Go, "x.go", "", "f", None, None, FuncKind::Function);
    k.set_namespace("pkg/x.go");
    k.set_arity(Some(3));
    k.set_disambig(Some(9));
    let fresh = FuncKey::from_parts(
        Lang::Go,
        "pkg/x.go",
        "",
        "f",
        Some(3),
        Some(9),
        FuncKind::Function,
    );
    assert_eq!(k, fresh, "setter-mutated key must equal freshly-built key");
    assert_eq!(fk_hash(&k), fk_hash(&fresh), "Hash must agree with Eq");
}

#[test]
fn funckey_hashmap_lookup_after_namespace_mutation() {
    use std::collections::HashMap;
    let mut m: HashMap<FuncKey, u32> = HashMap::new();
    let mut key = FuncKey::from_parts(
        Lang::Rust,
        "orig.rs",
        "",
        "g",
        Some(1),
        None,
        FuncKind::Function,
    );
    key.set_namespace("src/lib.rs");
    m.insert(key, 42);
    // A key built directly with the post-mutation identity must find the entry:
    // proves the cached hash stayed consistent across the setter.
    let probe = FuncKey::from_parts(
        Lang::Rust,
        "src/lib.rs",
        "",
        "g",
        Some(1),
        None,
        FuncKind::Function,
    );
    assert_eq!(m.get(&probe), Some(&42));
}

#[test]
fn funckey_serde_roundtrip_recomputes_hash_and_omits_hash_field() {
    let k = FuncKey::from_parts(
        Lang::TypeScript,
        "src/a.ts",
        "C",
        "run",
        Some(0),
        Some(3),
        FuncKind::Constructor,
    );
    let json = serde_json::to_string(&k).unwrap();
    assert!(
        !json.contains("\"hash\""),
        "serialized FuncKey must not persist the private hash field: {json}"
    );
    let back: FuncKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
    assert_eq!(
        fk_hash(&k),
        fk_hash(&back),
        "deserialize must recompute the cached hash"
    );
}

#[test]
fn funckey_serde_wire_backcompat_defaults() {
    // Old-format JSON (no container/disambig/kind) must still load and hash,
    // proving existing SQLite summary blobs remain readable.
    let json = r#"{"lang":"go","namespace":"m.go","name":"h","arity":2}"#;
    let k: FuncKey = serde_json::from_str(json).unwrap();
    let expected =
        FuncKey::from_parts(Lang::Go, "m.go", "", "h", Some(2), None, FuncKind::Function);
    assert_eq!(k, expected);
    assert_eq!(fk_hash(&k), fk_hash(&expected));
}

#[test]
fn funckey_serialized_wire_matches_field_names() {
    // The wire form is the seven identity fields, exactly as the old derived
    // Serialize emitted them (container/disambig/kind carry serde defaults).
    let k = FuncKey::from_parts(
        Lang::Rust,
        "src/lib.rs",
        "",
        "main",
        Some(0),
        None,
        FuncKind::Function,
    );
    let v: serde_json::Value = serde_json::to_value(&k).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.get("lang").and_then(|x| x.as_str()), Some("rust"));
    assert_eq!(
        obj.get("namespace").and_then(|x| x.as_str()),
        Some("src/lib.rs")
    );
    assert_eq!(obj.get("name").and_then(|x| x.as_str()), Some("main"));
    assert!(obj.contains_key("arity"));
    assert!(!obj.contains_key("hash"));
}

#[test]
fn funckey_default_hash_consistent() {
    let d = FuncKey::default();
    let mut d2 = d.clone();
    d2.recompute_hash();
    assert_eq!(fk_hash(&d), fk_hash(&d2));
    assert_eq!(d, d2);
    // Default must equal a from_parts-built empty key (hash included).
    let empty = FuncKey::from_parts(Lang::default(), "", "", "", None, None, FuncKind::default());
    assert_eq!(d, empty);
    assert_eq!(fk_hash(&d), fk_hash(&empty));
}

#[test]
fn funckey_distinct_identities_differ() {
    let a = FuncKey::from_parts(Lang::Go, "a.go", "", "f", Some(1), None, FuncKind::Function);
    let b = FuncKey::from_parts(Lang::Go, "a.go", "", "g", Some(1), None, FuncKind::Function);
    assert_ne!(a, b);
    // container-only difference is also a distinct identity
    let c = FuncKey::from_parts(
        Lang::Go,
        "a.go",
        "S",
        "f",
        Some(1),
        None,
        FuncKind::Function,
    );
    assert_ne!(a, c);
}
