pub fn lowercase_ext(path: &std::path::Path) -> Option<&'static str> {
    path.extension().and_then(|s| match s.to_str()? {
        "rs" | "RS" => Some("rs"),
        "c" => Some("c"),
        "cpp" | "c++" => Some("cpp"),
        "java" => Some("java"),
        "go" => Some("go"),
        "php" => Some("php"),
        "py" | "PY" => Some("py"),
        "ts" | "TSX" | "tsx" => Some("ts"),
        "js" => Some("js"),
        "rb" | "RB" => Some("rb"),
        _ => None,
    })
}

#[test]
fn lowercase_ext_recognises_known_extensions() {
    let cases = [
        ("file.rs", Some("rs")),
        ("FILE.RS", Some("rs")),
        ("main.cpp", Some("cpp")),
        ("script.PY", Some("py")),
        ("index.tsx", Some("ts")),
        ("style.css", None), // unsupported
    ];

    for (file, expected) in cases {
        assert_eq!(
            lowercase_ext(std::path::Path::new(file)),
            expected,
            "case: {file}"
        );
    }
}
