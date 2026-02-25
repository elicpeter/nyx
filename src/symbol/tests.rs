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
    let k = FuncKey {
        lang: Lang::Rust,
        namespace: "src/lib.rs".into(),
        name: "my_func".into(),
        arity: Some(2),
    };
    assert_eq!(k.to_string(), "rust::src/lib.rs::my_func/2");
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
