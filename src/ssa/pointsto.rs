//! Container operation classification for taint propagation.
//!
//! Recognises common container store/load patterns (push, pop, get, set, etc.)
//! across all supported languages so that taint flows correctly through
//! collection operations.

use crate::symbol::Lang;
use smallvec::SmallVec;

// ── Container operation model ───────────────────────────────────────────

/// Describes how a container method moves taint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerOp {
    /// Taint flows from the listed argument positions into the receiver
    /// container (e.g. `arr.push(val)` — val taint merges into arr).
    ///
    /// `index_arg`: when `Some(pos)`, the argument at that logical position
    /// is the container index/key.  If constant-propagation proves it a
    /// non-negative integer, the taint engine stores into `HeapSlot::Index(n)`
    /// instead of `HeapSlot::Elements`.  `None` → always `Elements`.
    Store {
        value_args: SmallVec<[usize; 2]>,
        index_arg: Option<usize>,
    },
    /// Taint flows from the receiver container to the call's return value
    /// (e.g. `arr.pop()`, `items.join('')`).
    ///
    /// `index_arg`: same semantics as `Store::index_arg` — when present and
    /// provably constant, loads from `HeapSlot::Index(n)`.
    Load {
        index_arg: Option<usize>,
    },
}

/// Convenience: store with a single value argument, no index tracking.
#[inline]
fn store(pos: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(pos);
    Some(ContainerOp::Store { value_args: v, index_arg: None })
}

/// Convenience: store with index tracking.  `val_pos` is the value arg,
/// `idx_pos` is the index/key arg (resolved via const propagation).
#[inline]
fn store_indexed(val_pos: usize, idx_pos: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(val_pos);
    Some(ContainerOp::Store { value_args: v, index_arg: Some(idx_pos) })
}

/// Convenience: store with two value arguments, no index tracking.
#[inline]
fn store2(a: usize, b: usize) -> Option<ContainerOp> {
    let mut v = SmallVec::new();
    v.push(a);
    v.push(b);
    Some(ContainerOp::Store { value_args: v, index_arg: None })
}

/// Convenience: load without index tracking.
#[inline]
fn load() -> Option<ContainerOp> {
    Some(ContainerOp::Load { index_arg: None })
}

/// Convenience: load with index tracking.  `idx_pos` is the index/key arg.
#[inline]
fn load_indexed(idx_pos: usize) -> Option<ContainerOp> {
    Some(ContainerOp::Load { index_arg: Some(idx_pos) })
}

// ── Classification ──────────────────────────────────────────────────────

/// Classify a callee as a container operation for the given language.
///
/// `callee` is the raw callee string from `NodeInfo.callee` (e.g.
/// `"items.push"`, `"arr.pop"`). We extract the last segment after `.`
/// for method matching. For Go builtins (e.g. `"append"`), the full name
/// is used.
///
/// Returns `None` if the callee is not a recognised container operation.
pub fn classify_container_op(callee: &str, lang: Lang) -> Option<ContainerOp> {
    // Extract method name: last segment after '.' (or full name if no dot).
    let method = callee.rsplit('.').next().unwrap_or(callee);

    match lang {
        Lang::JavaScript | Lang::TypeScript => classify_js(method),
        Lang::Python => classify_python(method),
        Lang::Java => classify_java(method),
        Lang::Go => classify_go(method, callee),
        Lang::Ruby => classify_ruby(method),
        Lang::Php => classify_php(method),
        Lang::C | Lang::Cpp => classify_cpp(method),
        Lang::Rust => classify_rust(method),
    }
}

// ── Per-language classifiers ────────────────────────────────────────────

fn classify_js(method: &str) -> Option<ContainerOp> {
    match method {
        // Array store
        "push" | "unshift" => store(0),
        // Map/Set store: map.set(key, value) — key at 0, value at 1
        "set" => store_indexed(1, 0),
        "add" => store(0),  // set.add(value)
        // Array/Map load
        "pop" | "shift" => load(),
        "join" | "flat" | "concat" | "slice" | "toString" => load(),
        // map.get(key) — key at 0
        "get" => load_indexed(0),
        "values" | "keys" | "entries" => load(),
        _ => None,
    }
}

fn classify_python(method: &str) -> Option<ContainerOp> {
    match method {
        // List store
        "append" | "extend" => store(0),
        "insert" => store_indexed(1, 0),  // list.insert(index, value) — index at 0, value at 1
        // Set store
        "add" => store(0),
        // Dict store
        "update" => store(0),
        "setdefault" => store2(0, 1), // dict.setdefault(key, default)
        // List/Dict load
        "pop" => load(),
        "get" => load_indexed(0),  // dict.get(key) / list index — key/index at 0
        "items" | "values" | "keys" => load(),
        "join" => load(),
        _ => None,
    }
}

fn classify_java(method: &str) -> Option<ContainerOp> {
    match method {
        // Collection store
        "add" | "addAll" | "putAll" | "offer" | "push" => store(0),
        // ArrayList.set(index, value) — index at 0, value at 1
        "set" => store_indexed(1, 0),
        // Map.put(key, value) — key at 0, value at 1
        "put" => store_indexed(1, 0),
        // Collection load: ArrayList.get(index) — index at 0
        "get" => load_indexed(0),
        "poll" | "peek" | "remove" | "pop" => load(),
        "stream" | "toArray" | "iterator" => load(),
        _ => None,
    }
}

fn classify_go(method: &str, callee: &str) -> Option<ContainerOp> {
    // Go `append` is a builtin: `result = append(slice, val1, val2, ...)`
    // The callee is just "append" (no receiver dot-path).
    if callee == "append" || method == "append" {
        // arg 0 = existing slice, args 1+ = values to append.
        // Handled specially in try_container_propagation (Go append mode).
        return store(1);
    }
    // Map/slice operations in Go are via index expressions, not method calls,
    // so there are fewer method-based patterns.
    match method {
        "Add" | "Set" | "Store" | "Put" => store(0),
        "Get" | "Load" | "Pop" => load(),
        _ => None,
    }
}

fn classify_ruby(method: &str) -> Option<ContainerOp> {
    match method {
        "push" | "append" | "unshift" | "store" | "<<" => store(0),
        "pop" | "shift" | "first" | "last" | "fetch" | "join" => load(),
        _ => None,
    }
}

fn classify_php(method: &str) -> Option<ContainerOp> {
    match method {
        "array_push" => store(1), // array_push(&$arr, $val) — arr is arg 0, val is arg 1
        "array_pop" | "array_shift" | "current" | "next" | "reset" => load(),
        _ => None,
    }
}

fn classify_cpp(method: &str) -> Option<ContainerOp> {
    match method {
        "push_back" | "emplace_back" | "insert" | "emplace" | "push" => store(0),
        "front" | "back" | "pop_back" | "pop_front" | "top" => load(),
        // vector.at(index) — index at 0
        "at" => load_indexed(0),
        _ => None,
    }
}

fn classify_rust(method: &str) -> Option<ContainerOp> {
    match method {
        "push" | "insert" | "extend" => store(0),
        "pop" | "first" | "last" | "iter" | "remove" => load(),
        // vec.get(index) — index at 0
        "get" => load_indexed(0),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_push_is_store() {
        let op = classify_container_op("items.push", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn js_pop_is_load() {
        let op = classify_container_op("arr.pop", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Load { .. })));
    }

    #[test]
    fn js_join_is_load() {
        let op = classify_container_op("items.join", Lang::JavaScript);
        assert!(matches!(op, Some(ContainerOp::Load { .. })));
    }

    #[test]
    fn python_append_is_store() {
        let op = classify_container_op("commands.append", Lang::Python);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn java_add_is_store() {
        let op = classify_container_op("list.add", Lang::Java);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn go_append_is_store() {
        let op = classify_container_op("append", Lang::Go);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn unknown_method_is_none() {
        assert!(classify_container_op("obj.frobnicate", Lang::JavaScript).is_none());
    }

    #[test]
    fn rust_push_is_store() {
        let op = classify_container_op("vec.push", Lang::Rust);
        assert!(matches!(op, Some(ContainerOp::Store { .. })));
    }

    #[test]
    fn store_value_args_correct() {
        // JS set → value at arg 1, index at arg 0
        if let Some(ContainerOp::Store { value_args, index_arg }) =
            classify_container_op("map.set", Lang::JavaScript)
        {
            assert_eq!(value_args.as_slice(), &[1]);
            assert_eq!(index_arg, Some(0));
        } else {
            panic!("expected Store");
        }
        // JS push → value at arg 0, no index
        if let Some(ContainerOp::Store { value_args, index_arg }) =
            classify_container_op("arr.push", Lang::JavaScript)
        {
            assert_eq!(value_args.as_slice(), &[0]);
            assert_eq!(index_arg, None);
        } else {
            panic!("expected Store");
        }
    }

    #[test]
    fn load_index_arg_correct() {
        // JS get → index at arg 0
        if let Some(ContainerOp::Load { index_arg }) =
            classify_container_op("map.get", Lang::JavaScript)
        {
            assert_eq!(index_arg, Some(0));
        } else {
            panic!("expected Load");
        }
        // JS pop → no index
        if let Some(ContainerOp::Load { index_arg }) =
            classify_container_op("arr.pop", Lang::JavaScript)
        {
            assert_eq!(index_arg, None);
        } else {
            panic!("expected Load");
        }
    }
}
