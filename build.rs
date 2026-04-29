use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    render_docs_for_rustdoc();

    // Only relevant when the serve feature is active
    if std::env::var("CARGO_FEATURE_SERVE").is_err() {
        return;
    }

    let dist_dir = Path::new("src/server/assets/dist");
    let index_html = dist_dir.join("index.html");

    // Re-run build.rs only when dist output is missing/changed
    println!("cargo:rerun-if-changed=src/server/assets/dist/index.html");

    if index_html.exists() {
        // Dist already built — nothing to do
        return;
    }

    // Dist missing — try to build frontend
    let frontend_dir = Path::new("frontend");
    if !frontend_dir.join("package.json").exists() {
        emit_placeholder_and_warn(dist_dir);
        return;
    }

    // Run npm install + build
    println!("cargo:warning=Frontend dist not found, running npm install && npm run build...");
    let npm_install = Command::new("npm")
        .arg("install")
        .current_dir(frontend_dir)
        .status();

    match npm_install {
        Ok(s) if s.success() => {}
        _ => {
            emit_placeholder_and_warn(dist_dir);
            return;
        }
    }

    let npm_build = Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(frontend_dir)
        .status();

    match npm_build {
        Ok(s) if s.success() => {
            println!("cargo:warning=Frontend built successfully.");
        }
        _ => {
            emit_placeholder_and_warn(dist_dir);
        }
    }
}

// ---------------------------------------------------------------------------
// Rustdoc / docs.rs: render docs/*.md into $OUT_DIR with relative .md links
// rewritten to absolute github.com/elicpeter/nyx URLs so they resolve when the
// markdown is embedded in rustdoc via #![doc = include_str!(...)].
//
// Source of truth stays in docs/. Files that don't exist (published-crate
// builds where docs/ wasn't packaged) fall back to a one-line stub so rustdoc
// still compiles.
// ---------------------------------------------------------------------------

const GH_DOCS_BASE: &str = "https://github.com/elicpeter/nyx/blob/master/docs";

struct DocSpec {
    /// Path under docs/, e.g. "how-it-works.md" or "detectors/taint.md".
    src: &'static str,
    /// Output filename in $OUT_DIR.
    out: &'static str,
}

const DOC_SPECS: &[DocSpec] = &[
    DocSpec {
        src: "how-it-works.md",
        out: "lib_intro.md",
    },
    DocSpec {
        src: "detectors/taint.md",
        out: "taint.md",
    },
    DocSpec {
        src: "detectors/cfg.md",
        out: "cfg_analysis.md",
    },
    DocSpec {
        src: "detectors/state.md",
        out: "state.md",
    },
    DocSpec {
        src: "detectors/patterns.md",
        out: "patterns.md",
    },
    DocSpec {
        src: "auth.md",
        out: "auth_analysis.md",
    },
];

fn render_docs_for_rustdoc() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let out_dir = PathBuf::from(out_dir);
    let docs_dir = Path::new("docs");

    for spec in DOC_SPECS {
        let src_path = docs_dir.join(spec.src);
        println!("cargo:rerun-if-changed=docs/{}", spec.src);
        let out_path = out_dir.join(spec.out);
        let rendered = match std::fs::read_to_string(&src_path) {
            Ok(raw) => rewrite_doc_links(&raw, spec.src),
            Err(_) => format!(
                "See [`{base}/{src}`]({base}/{src}).\n",
                base = GH_DOCS_BASE,
                src = spec.src,
            ),
        };
        if let Err(e) = std::fs::write(&out_path, rendered) {
            println!(
                "cargo:warning=failed to write rendered doc {}: {}",
                out_path.display(),
                e
            );
        }
    }
}

/// Render markdown for embedding in rustdoc.
///
/// 1. Rewrites relative `.md` links to absolute github.com URLs:
///    - inline links:  `](path.md)` and `](path.md#anchor)`
///    - reference defs: `[id]: path.md`
/// 2. Labels unmarked fenced code blocks as `text` so rustdoc does not try
///    to compile them as Rust (and choke on Unicode like `→`).
/// 3. Annotates `rust` fences with `,ignore` so rustdoc doesn't try to
///    compile or run prose-level snippets as doctests. GitHub still
///    highlights them as Rust because it keys off the first token.
///
/// Skips link rewriting inside code fences. Skips link rewriting for URLs
/// that are already absolute (have a scheme), pure anchors (`#section`),
/// or non-`.md` paths.
fn rewrite_doc_links(content: &str, source_rel: &str) -> String {
    let source_dir = Path::new(source_rel)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut out = String::with_capacity(content.len() + 256);
    let mut in_fence = false;

    for line in content.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = body.trim_start();
        if trimmed.starts_with("```") {
            let lang = trimmed.trim_start_matches('`').trim();
            if in_fence {
                in_fence = false;
                out.push_str(line);
            } else {
                in_fence = true;
                let indent_len = body.len() - trimmed.len();
                if lang.is_empty() {
                    out.push_str(&body[..indent_len]);
                    out.push_str("```text");
                    if line.ends_with('\n') {
                        out.push('\n');
                    }
                } else if is_rust_fence_needing_ignore(lang) {
                    out.push_str(&body[..indent_len]);
                    out.push_str("```rust,ignore");
                    if line.ends_with('\n') {
                        out.push('\n');
                    }
                } else {
                    out.push_str(line);
                }
            }
            continue;
        }
        if in_fence {
            out.push_str(line);
        } else {
            rewrite_links_in_line(body, &source_dir, &mut out);
            if line.ends_with('\n') {
                out.push('\n');
            }
        }
    }

    out
}

fn rewrite_links_in_line(line: &str, source_dir: &str, out: &mut String) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Inline link: `](URL)` — markdown URLs do not contain a raw `)`.
        if i + 1 < bytes.len() && bytes[i] == b']' && bytes[i + 1] == b'(' {
            out.push_str("](");
            i += 2;
            let url_start = i;
            while i < bytes.len() && bytes[i] != b')' {
                i += 1;
            }
            let url = &line[url_start..i];
            out.push_str(&maybe_rewrite_url(url, source_dir));
        }
        // Reference def: `]: URL`.
        else if i + 2 < bytes.len()
            && bytes[i] == b']'
            && bytes[i + 1] == b':'
            && bytes[i + 2] == b' '
        {
            out.push_str("]: ");
            i += 3;
            let url_start = i;
            while i < bytes.len() && bytes[i] != b' ' {
                i += 1;
            }
            let url = &line[url_start..i];
            out.push_str(&maybe_rewrite_url(url, source_dir));
        } else {
            // `]` (0x5D) is ASCII; UTF-8 continuation bytes are 0x80-0xBF
            // and start bytes are 0xC0+, so byte-level scanning of `]` is
            // safe. For non-ASCII bytes, copy the full codepoint at once.
            let b = bytes[i];
            if b < 0x80 {
                out.push(b as char);
                i += 1;
            } else {
                let len = utf8_seq_len(b);
                let end = (i + len).min(bytes.len());
                out.push_str(&line[i..end]);
                i = end;
            }
        }
    }
}

/// True for `rust` / `rust,...` fences that don't already opt out of
/// doctest execution. We rewrite these to `rust,ignore` because the prose
/// snippets in docs/ are illustrative, not standalone-compilable.
fn is_rust_fence_needing_ignore(lang: &str) -> bool {
    let mut parts = lang.split(',').map(|p| p.trim());
    let Some(first) = parts.next() else {
        return false;
    };
    if !first.eq_ignore_ascii_case("rust") {
        return false;
    }
    for tag in parts {
        let t = tag.to_ascii_lowercase();
        if t == "ignore" || t == "no_run" || t == "compile_fail" || t == "should_panic" {
            return false;
        }
    }
    true
}

fn utf8_seq_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xC0 {
        1 // unexpected continuation; treat as single byte to make progress
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else {
        4
    }
}

fn maybe_rewrite_url(url: &str, source_dir: &str) -> String {
    if url.is_empty() {
        return url.to_string();
    }
    // Already absolute (scheme://, mailto:, ssh://, etc.) — leave alone.
    if has_scheme(url) {
        return url.to_string();
    }
    // Pure anchor — leave alone.
    if url.starts_with('#') {
        return url.to_string();
    }
    // Split off optional anchor.
    let (path, anchor) = match url.find('#') {
        Some(p) => (&url[..p], &url[p..]),
        None => (url, ""),
    };
    // Only rewrite if the path looks like a markdown file.
    if !path.ends_with(".md") {
        return url.to_string();
    }
    // Resolve relative to source_dir.
    let combined = if source_dir.is_empty() {
        path.to_string()
    } else {
        format!("{}/{}", source_dir, path)
    };
    let normalised = normalise_path(&combined);
    format!("{}/{}{}", GH_DOCS_BASE, normalised, anchor)
}

fn has_scheme(url: &str) -> bool {
    // RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    let mut chars = url.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for c in chars {
        if c == ':' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return false;
        }
    }
    false
}

fn normalise_path(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    stack.join("/")
}

fn emit_placeholder_and_warn(dist_dir: &Path) {
    // Create minimal placeholder files so compilation succeeds
    std::fs::create_dir_all(dist_dir).ok();
    std::fs::write(
        dist_dir.join("index.html"),
        "<!DOCTYPE html><html><body><h1>Frontend not built</h1><p>Run: cd frontend &amp;&amp; npm install &amp;&amp; npm run build</p></body></html>",
    )
    .ok();
    std::fs::write(dist_dir.join("app.js"), "// frontend not built\n").ok();
    std::fs::write(dist_dir.join("style.css"), "/* frontend not built */\n").ok();
    println!(
        "cargo:warning=Node.js/npm not available — wrote placeholder frontend assets. Run 'cd frontend && npm install && npm run build' for the real UI."
    );
}
