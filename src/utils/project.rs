#![allow(clippy::collapsible_if)]

use crate::errors::{NyxError, NyxResult};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Determine `<project-name, path/to/<project>.sqlite>`.
pub fn get_project_info(project_path: &Path, config_dir: &Path) -> NyxResult<(String, PathBuf)> {
    let project_name = project_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NyxError::Other("Unable to determine project name".into()))?;

    let db_name = sanitize_project_name(project_name);
    let db_path = config_dir.join(format!("{db_name}.sqlite"));

    Ok((project_name.to_owned(), db_path))
}

pub fn sanitize_project_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| match c {
            ' ' | '\t' | '\n' | '\r' => '_',
            c if c.is_alphanumeric() || c == '_' || c == '-' => c,
            _ => '_',
        })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// A web framework detected from project manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectedFramework {
    Express,
    React,
    Flask,
    Django,
    Spring,
    Gin,
    Echo,
    Laravel,
    Rails,
    Sinatra,
    ActixWeb,
    Rocket,
    Axum,
}

/// Frameworks detected in the project root.
#[derive(Debug, Clone, Default)]
pub struct FrameworkContext {
    pub frameworks: Vec<DetectedFramework>,
}

impl FrameworkContext {
    pub fn has(&self, fw: DetectedFramework) -> bool {
        self.frameworks.contains(&fw)
    }
}

/// Maximum bytes to read from each manifest file.
const MANIFEST_READ_LIMIT: usize = 64 * 1024;

/// Read up to `MANIFEST_READ_LIMIT` bytes from a file.
fn read_bounded(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file).take(MANIFEST_READ_LIMIT as u64);
    let mut out = String::new();
    reader.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Detect frameworks from manifest files in the project root.
pub fn detect_frameworks(root: &Path) -> FrameworkContext {
    let mut fws = Vec::new();

    // ── Node.js (package.json) ──
    if let Some(content) = read_bounded(&root.join("package.json")) {
        // Crude substring search in the "dependencies" block area.
        // Good enough for detection — no JSON parsing overhead.
        if content.contains("\"express\"") {
            fws.push(DetectedFramework::Express);
        }
        if content.contains("\"react\"") {
            fws.push(DetectedFramework::React);
        }
    }

    // ── Python ──
    for name in &["requirements.txt", "Pipfile", "pyproject.toml"] {
        if let Some(content) = read_bounded(&root.join(name)) {
            let lower = content.to_ascii_lowercase();
            if lower.contains("flask") && !fws.contains(&DetectedFramework::Flask) {
                fws.push(DetectedFramework::Flask);
            }
            if lower.contains("django") && !fws.contains(&DetectedFramework::Django) {
                fws.push(DetectedFramework::Django);
            }
        }
    }

    // ── Java (Maven / Gradle) ──
    for name in &["pom.xml", "build.gradle", "build.gradle.kts"] {
        if let Some(content) = read_bounded(&root.join(name)) {
            if (content.contains("spring-boot") || content.contains("spring-web"))
                && !fws.contains(&DetectedFramework::Spring)
            {
                fws.push(DetectedFramework::Spring);
            }
        }
    }

    // ── Go (go.mod) ──
    if let Some(content) = read_bounded(&root.join("go.mod")) {
        if content.contains("gin-gonic/gin") {
            fws.push(DetectedFramework::Gin);
        }
        if content.contains("labstack/echo") {
            fws.push(DetectedFramework::Echo);
        }
    }

    // ── PHP (composer.json) ──
    if let Some(content) = read_bounded(&root.join("composer.json")) {
        if content.contains("laravel/framework") {
            fws.push(DetectedFramework::Laravel);
        }
    }

    // ── Ruby (Gemfile) ──
    if let Some(content) = read_bounded(&root.join("Gemfile")) {
        if content.contains("'rails'") || content.contains("\"rails\"") {
            fws.push(DetectedFramework::Rails);
        }
        if content.contains("'sinatra'") || content.contains("\"sinatra\"") {
            fws.push(DetectedFramework::Sinatra);
        }
    }

    // ── Rust (Cargo.toml) ──
    if let Some(content) = read_bounded(&root.join("Cargo.toml")) {
        if content.contains("actix-web") {
            fws.push(DetectedFramework::ActixWeb);
        }
        if content.contains("rocket") && !fws.contains(&DetectedFramework::Rocket) {
            fws.push(DetectedFramework::Rocket);
        }
        if content.contains("axum") {
            fws.push(DetectedFramework::Axum);
        }
    }

    FrameworkContext { frameworks: fws }
}

#[test]
fn sanitize_project_name_is_idempotent_and_lossless_enough() {
    let samples = [
        ("My Project", "my_project"),
        ("Hello-World", "hello-world"),
        ("mixed_case", "mixed_case"),
        ("tabs\tspaces\n", "tabs_spaces"),
        ("   multiple   ", "multiple"),
        ("weird@$*chars", "weird_chars"),
    ];

    for (input, expected) in samples {
        assert_eq!(sanitize_project_name(input), expected, "input: {input}");
        assert_eq!(sanitize_project_name(expected), expected);
    }
}

#[test]
fn get_project_info_uses_sanitized_name_in_sqlite_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let project_dir = root.join("Example Project");
    std::fs::create_dir(&project_dir).unwrap();

    let (project_name, db_path) =
        get_project_info(&project_dir, root).expect("should detect project");

    assert_eq!(project_name, "Example Project");
    assert_eq!(db_path, root.join("example_project.sqlite"));
}

#[test]
fn detect_frameworks_from_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("package.json"),
        r#"{"dependencies": {"express": "^4.18.0", "react": "^18.0.0"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Express));
    assert!(ctx.has(DetectedFramework::React));
    assert!(!ctx.has(DetectedFramework::Flask));
}

#[test]
fn detect_frameworks_empty_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = detect_frameworks(tmp.path());
    assert!(ctx.frameworks.is_empty());
}

#[test]
fn detect_frameworks_gemfile_rails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("Gemfile"), "gem 'rails', '~> 7.0'\ngem 'puma'\n").unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Rails));
    assert!(!ctx.has(DetectedFramework::Sinatra));
}

#[test]
fn detect_frameworks_gemfile_sinatra() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("Gemfile"), "gem 'sinatra'\ngem 'puma'\n").unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Sinatra));
    assert!(!ctx.has(DetectedFramework::Rails));
}

#[test]
fn detect_frameworks_python_flask_from_requirements() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("requirements.txt"),
        "Flask==2.3.0\nrequests>=2.28\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Flask));
    assert!(!ctx.has(DetectedFramework::Django));
}

#[test]
fn detect_frameworks_python_django_from_pyproject() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"myapp\"\ndependencies = [\"django>=4.0\"]\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Django));
    assert!(!ctx.has(DetectedFramework::Flask));
}

#[test]
fn detect_frameworks_go_mod_gin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("go.mod"),
        "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Gin));
    assert!(!ctx.has(DetectedFramework::Echo));
}

#[test]
fn detect_frameworks_go_mod_echo() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("go.mod"),
        "module example.com/app\n\nrequire (\n\tgithub.com/labstack/echo/v4 v4.11.0\n)\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Echo));
    assert!(!ctx.has(DetectedFramework::Gin));
}

#[test]
fn detect_frameworks_java_spring_from_pom_xml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("pom.xml"),
        "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.springframework.boot</groupId>\n      <artifactId>spring-boot-starter-web</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Spring));
}

#[test]
fn detect_frameworks_java_spring_from_build_gradle() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("build.gradle"),
        "plugins {\n    id 'org.springframework.boot' version '3.1.0'\n}\ndependencies {\n    implementation 'org.springframework.boot:spring-web:3.1.0'\n}\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Spring));
}

#[test]
fn detect_frameworks_php_laravel_from_composer_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("composer.json"),
        r#"{"require": {"laravel/framework": "^10.0", "php": "^8.1"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Laravel));
}

#[test]
fn detect_frameworks_rust_axum_from_cargo_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("Cargo.toml"),
        "[dependencies]\naxum = \"0.7\"\ntokio = { version = \"1\", features = [\"full\"] }\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Axum));
    assert!(!ctx.has(DetectedFramework::ActixWeb));
    assert!(!ctx.has(DetectedFramework::Rocket));
}

#[test]
fn detect_frameworks_rust_actix_web_from_cargo_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("Cargo.toml"),
        "[dependencies]\nactix-web = \"4\"\n",
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::ActixWeb));
}

#[test]
fn detect_frameworks_multiple_in_same_project() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A project using both Express and React
    fs::write(
        root.join("package.json"),
        r#"{"dependencies": {"express": "^4", "react": "^18"}}"#,
    )
    .unwrap();
    let ctx = detect_frameworks(root);
    assert!(ctx.has(DetectedFramework::Express));
    assert!(ctx.has(DetectedFramework::React));
    assert_eq!(ctx.frameworks.len(), 2);
}

#[test]
fn sanitize_project_name_numeric_and_special() {
    assert_eq!(sanitize_project_name("project123"), "project123");
    assert_eq!(sanitize_project_name("123"), "123");
    assert_eq!(sanitize_project_name("a.b.c"), "a_b_c");
    // hyphens are preserved as-is (only underscores are collapsed)
    assert_eq!(sanitize_project_name("a--b"), "a--b");
    // Leading/trailing underscores from replacements get collapsed
    assert_eq!(sanitize_project_name("__init__"), "init");
}

#[test]
fn get_project_info_returns_error_for_root_path() {
    let tmp = tempfile::tempdir().unwrap();
    // A path that ends with "/" (root) has no file_name
    let result = get_project_info(std::path::Path::new("/"), tmp.path());
    assert!(result.is_err());
}

#[test]
fn framework_context_has_is_false_for_absent_framework() {
    let ctx = FrameworkContext::default();
    assert!(!ctx.has(DetectedFramework::Express));
    assert!(!ctx.has(DetectedFramework::Flask));
    assert!(!ctx.has(DetectedFramework::Spring));
}
