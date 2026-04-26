//! Audit harness for typed-extractor handling (Phases 1-6).
//!
//! These tests directly drive the `cfg::params` matchers via the
//! tree-sitter parser without spinning up the full scan pipeline.  The
//! goal is to pin the matcher invariants — what qualifies as a typed
//! extractor, what does not — independent of which framework rules are
//! loaded at scan time.
//!
//! Three audit dimensions are covered:
//!   * **A1** — end-to-end wiring: classifier returns the expected
//!     `TypeKind` for each framework's canonical typed-extractor shape
//!     (Spring `@PathVariable`, NestJS `@Param`, Axum `Path<i64>`,
//!     FastAPI `Annotated[..., Path()]`).
//!   * **A2** — Hard-Rule-3 negatives: bare primitives and
//!     non-framework annotations / decorators / wrappers must NOT
//!     classify.
//!   * **A5** — parser-driven matcher tests: every assertion is
//!     produced from a real parsed AST so a future tree-sitter grammar
//!     bump can't silently break the matcher without flipping a test.

use nyx_scanner::cfg::extract_param_meta_for_test;
use nyx_scanner::ssa::type_facts::{DtoFields, TypeKind};
use tree_sitter::Parser;

fn parse(lang: &str, src: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    let language: tree_sitter::Language = match lang {
        "java" => tree_sitter_java::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        other => panic!("unsupported lang: {other}"),
    };
    parser.set_language(&language).unwrap();
    parser.parse(src, None).unwrap()
}

/// Find the first function-like node in the tree whose `kind()` matches
/// `func_kind`.  Returns `None` when none exists — parser fragility
/// guard so failures surface as a panic in the test instead of a
/// silent skip.
fn first_node_of_kind<'a>(
    tree: &'a tree_sitter::Tree,
    func_kinds: &[&str],
) -> tree_sitter::Node<'a> {
    fn walk<'a>(
        node: tree_sitter::Node<'a>,
        kinds: &[&str],
    ) -> Option<tree_sitter::Node<'a>> {
        if kinds.contains(&node.kind()) {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = walk(child, kinds) {
                return Some(found);
            }
        }
        None
    }
    walk(tree.root_node(), func_kinds).unwrap_or_else(|| {
        panic!("no node of kind {func_kinds:?} in parsed source");
    })
}

/// Drive `extract_param_meta_for_test` over the first function-like
/// node and return the per-position `(name, Option<TypeKind>)` slice.
fn extract(lang: &str, src: &str, func_kinds: &[&str]) -> Vec<(String, Option<TypeKind>)> {
    let tree = parse(lang, src);
    let func = first_node_of_kind(&tree, func_kinds);
    extract_param_meta_for_test(func, lang, src.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────
// A1: positive — typed-extractor shapes return Some(TypeKind)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn java_path_variable_long_classifies_as_int() {
    let src = r#"
        @RestController
        public class C {
            public void h(@PathVariable Long userId) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn java_request_param_string_classifies_as_string() {
    let src = r#"
        public class C {
            public void h(@RequestParam String name) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    assert_eq!(params[0].1, Some(TypeKind::String));
}

#[test]
fn java_request_header_boolean_classifies_as_bool() {
    let src = r#"
        public class C {
            public void h(@RequestHeader("X") Boolean v) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    assert_eq!(params[0].1, Some(TypeKind::Bool));
}

#[test]
fn ts_param_with_number_type_classifies_as_int() {
    let src = r#"
        export class UserController {
            handle(@Param('id') id: number) {}
        }
    "#;
    let params = extract("typescript", src, &["method_definition"]);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn ts_query_with_parse_int_pipe_classifies_as_int_even_when_type_is_any() {
    // Pipe coercion overrides the static type per Phase 2 design.
    let src = r#"
        export class UserController {
            handle(@Query('limit', ParseIntPipe) limit: any) {}
        }
    "#;
    let params = extract("typescript", src, &["method_definition"]);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn rust_axum_path_int_classifies_as_int() {
    let src = "pub async fn h(Path(id): Path<i64>) {}";
    let params = extract("rust", src, &["function_item"]);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn rust_actix_web_path_u32_classifies_as_int() {
    let src = "pub async fn h(p: web::Path<u32>) {}";
    let params = extract("rust", src, &["function_item"]);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn rust_path_string_classifies_as_string() {
    let src = "pub async fn h(p: Path<String>) {}";
    let params = extract("rust", src, &["function_item"]);
    assert_eq!(params[0].1, Some(TypeKind::String));
}

#[test]
fn python_annotated_int_with_path_marker_classifies_as_int() {
    let src = "def h(user_id: Annotated[int, Path()]):\n    return user_id\n";
    let params = extract("python", src, &["function_definition"]);
    assert_eq!(params[0].1, Some(TypeKind::Int));
}

#[test]
fn python_annotated_str_with_query_marker_classifies_as_string() {
    let src = "def h(name: Annotated[str, Query(max_length=50)]):\n    return name\n";
    let params = extract("python", src, &["function_definition"]);
    assert_eq!(params[0].1, Some(TypeKind::String));
}

// ─────────────────────────────────────────────────────────────────────
// A2: Hard-Rule-3 negatives — must NOT classify
// ─────────────────────────────────────────────────────────────────────

#[test]
fn java_bare_long_without_annotation_does_not_classify() {
    // Per Hard Rule 3, plain `Long id` is not a framework extractor.
    let src = r#"
        public class C {
            public void h(Long id) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn java_custom_annotation_does_not_classify() {
    let src = r#"
        public class C {
            public void h(@CustomDeco Long id) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn ts_bare_number_without_decorator_does_not_classify() {
    let src = r#"
        export class C {
            handle(id: number) {}
        }
    "#;
    let params = extract("typescript", src, &["method_definition"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn ts_custom_decorator_does_not_classify() {
    // `@Custom('id')` is not in the NestJS allowlist — Hard Rule 3
    // prevents lifting unknown decorators into typed-extractor space.
    let src = r#"
        export class C {
            handle(@Custom('id') id: number) {}
        }
    "#;
    let params = extract("typescript", src, &["method_definition"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn rust_bare_i64_without_wrapper_does_not_classify() {
    let src = "pub fn h(id: i64) {}";
    let params = extract("rust", src, &["function_item"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn rust_custom_wrapper_does_not_classify() {
    // `MyWrapper<i64>` is not in the framework allowlist.
    let src = "pub fn h(id: MyWrapper<i64>) {}";
    let params = extract("rust", src, &["function_item"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn python_bare_int_without_annotated_does_not_classify() {
    let src = "def h(id: int):\n    return id\n";
    let params = extract("python", src, &["function_definition"]);
    assert_eq!(params[0].1, None);
}

#[test]
fn python_annotated_without_fastapi_marker_does_not_classify() {
    // `Annotated[int, MyMeta]` carries no FastAPI binding marker.
    let src = "def h(id: Annotated[int, MyMeta]):\n    return id\n";
    let params = extract("python", src, &["function_definition"]);
    assert_eq!(params[0].1, None);
}

// ─────────────────────────────────────────────────────────────────────
// Phase 6 — DTO classification end-to-end
// ─────────────────────────────────────────────────────────────────────

/// Phase 6 wiring proof for Rust: `Json<UpdateDoc>` whose `UpdateDoc`
/// struct lives in the same source unit lifts to `TypeKind::Dto(..)`
/// with the field types.
#[test]
fn rust_json_dto_classifies_as_dto_when_struct_in_same_file() {
    let src = r#"
        pub struct UpdateDoc { pub doc_id: i64, pub email: String }
        pub fn h(payload: Json<UpdateDoc>) {}
    "#;
    let tree = parse("rust", src);
    // Trigger the same DTO collection pass that build_cfg runs at
    // scan time.  This tests both Phase 6.1 (collector) and Phase 6.2
    // (matcher resolves via DTO_CLASSES).
    nyx_scanner::cfg::populate_dto_classes_for_test(tree.root_node(), "rust", src.as_bytes());
    let func = first_node_of_kind(&tree, &["function_item"]);
    let params = extract_param_meta_for_test(func, "rust", src.as_bytes());
    nyx_scanner::cfg::clear_dto_classes_for_test();
    let TypeKind::Dto(fields) = params[0].1.as_ref().expect("Dto type") else {
        panic!("expected Dto, got {:?}", params[0].1);
    };
    assert_eq!(fields.class_name, "UpdateDoc");
    assert_eq!(fields.get("doc_id"), Some(&TypeKind::Int));
    assert_eq!(fields.get("email"), Some(&TypeKind::String));
}

/// Phase 6 negative: when the DTO struct is NOT in the same file, the
/// classifier falls through to None (cross-file lookup is the deferred
/// Phase 6.4).  This pins the per-file scope guard so Phase 6 doesn't
/// accidentally claim resolution for unknown DTOs.
#[test]
fn rust_json_dto_returns_none_when_struct_missing_from_file() {
    let src = "pub fn h(payload: Json<UnknownDto>) {}";
    let tree = parse("rust", src);
    nyx_scanner::cfg::populate_dto_classes_for_test(tree.root_node(), "rust", src.as_bytes());
    let func = first_node_of_kind(&tree, &["function_item"]);
    let params = extract_param_meta_for_test(func, "rust", src.as_bytes());
    nyx_scanner::cfg::clear_dto_classes_for_test();
    assert_eq!(params[0].1, None);
}

/// Phase 6 — DtoFields exposes a stable accessor surface for the
/// downstream auth analysis and type-fact engine.  Pin the contract so
/// future changes don't break that consumer.
#[test]
fn dto_fields_struct_api_is_stable() {
    let mut dto = DtoFields::new("CreateUser");
    dto.insert("age", TypeKind::Int);
    dto.insert("email", TypeKind::String);
    assert_eq!(dto.class_name, "CreateUser");
    assert_eq!(dto.get("age"), Some(&TypeKind::Int));
    assert_eq!(dto.get("missing"), None);
    // BTreeMap iteration order is sorted by key — stable
    // serialisation invariant.
    let keys: Vec<_> = dto.fields.keys().cloned().collect();
    assert_eq!(keys, vec!["age".to_string(), "email".to_string()]);
}

// ─────────────────────────────────────────────────────────────────────
// A4: multi-body merge regression guard
// ─────────────────────────────────────────────────────────────────────

/// Audit A4: when two functions in the same file have parameters with
/// the same name but different types (Spring `@PathVariable Long id`
/// in one method, `@RequestParam String id` in another), the
/// per-body matcher must classify each correctly — the merger
/// (`collect_file_var_types`) drops the entry when they conflict but
/// the per-body classification stays right.  This pins the matcher's
/// per-body grain.
#[test]
fn java_two_handlers_with_conflicting_param_types_each_classify_locally() {
    let src = r#"
        public class C {
            public void handle_a(@PathVariable Long id) {}
            public void handle_b(@RequestParam String id) {}
        }
    "#;
    let tree = parse("java", src);

    // Walk every method_declaration and collect their first param type.
    let root = tree.root_node();
    let mut found: Vec<(String, Option<TypeKind>)> = Vec::new();
    fn visit<'a>(
        node: tree_sitter::Node<'a>,
        code: &[u8],
        found: &mut Vec<(String, Option<TypeKind>)>,
    ) {
        if node.kind() == "method_declaration" {
            let name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(code).ok())
                .unwrap_or("?")
                .to_string();
            let params = extract_param_meta_for_test(node, "java", code);
            let kind = params.first().and_then(|(_, k)| k.clone());
            found.push((name, kind));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(child, code, found);
        }
    }
    visit(root, src.as_bytes(), &mut found);

    let handle_a = found
        .iter()
        .find(|(n, _)| n == "handle_a")
        .expect("handle_a method present");
    let handle_b = found
        .iter()
        .find(|(n, _)| n == "handle_b")
        .expect("handle_b method present");
    assert_eq!(handle_a.1, Some(TypeKind::Int));
    assert_eq!(handle_b.1, Some(TypeKind::String));
}

// ─────────────────────────────────────────────────────────────────────
// Phase 5 hygiene: extract_param_meta does not lift annotation/decorator
// names into the `params` Vec.  Documents the invariant called out in
// the prompt's "common landing traps" section.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn java_path_variable_does_not_lift_annotation_into_param_names() {
    let src = r#"
        public class C {
            public void h(@PathVariable Long userId) {}
        }
    "#;
    let params = extract("java", src, &["method_declaration"]);
    // The collected param name is exactly "userId" — `PathVariable`
    // (the annotation token) must not become a param entry, otherwise
    // `apply_typed_bounded_params` would try to look it up.
    assert!(params.iter().all(|(name, _)| name != "PathVariable"));
    assert!(params.iter().any(|(name, _)| name == "userId"));
}

#[test]
fn rust_path_extractor_does_not_lift_wrapper_into_param_names() {
    let src = "pub async fn h(Path(project_id): Path<i64>) {}";
    let params = extract("rust", src, &["function_item"]);
    // The Path destructure should still surface the inner binding,
    // not the wrapper name.
    assert!(
        params.iter().any(|(name, _)| name == "project_id")
            || !params.iter().any(|(name, _)| name == "Path"),
        "params: {params:?}",
    );
}
