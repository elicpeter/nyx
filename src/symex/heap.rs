//! Symbolic heap: field-sensitive memory model for symbolic execution (Phase 21).
//!
//! Maps `(HeapObjectId, FieldSlot)` → `SymbolicValue`, enabling the symbolic
//! executor to track taint through object property stores/loads and container
//! operations.  Uses allocation-site identities from `PointsToResult` to
//! distinguish different objects.
//!
//! Design:
//! - `FieldSlot::Named` for object properties (per-field precision).
//! - `FieldSlot::Elements` for container contents (flow-insensitive union —
//!   deliberately lower precision than named fields).
//! - Bounded: `MAX_HEAP_ENTRIES` total, `MAX_FIELDS_PER_OBJECT` per object.
//!   Overflow silently drops the store (conservative: subsequent load → `Unknown`).
//! - `widen()` sets values to `Unknown` but preserves taint flags.
//! - `Clone` for fork-point cloning in multi-path exploration.

use std::collections::{HashMap, HashSet};

use crate::ssa::heap::{HeapObjectId, PointsToResult};
use crate::ssa::ir::{SsaBody, SsaValue};

use super::value::SymbolicValue;

/// Maximum total heap entries across all objects.
const MAX_HEAP_ENTRIES: usize = 64;

/// Maximum fields tracked per individual object.
const MAX_FIELDS_PER_OBJECT: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// Heap key: allocation-site identity + field slot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeapKey {
    pub object: HeapObjectId,
    pub field: FieldSlot,
}

/// Distinguishes named object fields from element-insensitive container slots.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldSlot {
    /// Named property: `obj.username`, `config.host`.
    Named(String),
    /// Element-insensitive container contents (flow-insensitive union of all
    /// elements).  `push` + `pop` do not track per-index identity — this is
    /// intentionally lower precision than `Named`.
    Elements,
}

/// Metadata recorded at store/load time for witness generation.
///
/// Recorded explicitly rather than reconstructed heuristically from `var_name`
/// strings, ensuring witness accuracy even when heap loads produce SSA values
/// without dotted names.
#[derive(Clone, Debug)]
pub struct FieldAccessRecord {
    /// Receiver expression text: `"user"`, `"req.body"`.
    pub object_name: String,
    /// Field name: `"name"`, `"username"`.
    pub field_name: String,
    /// The SSA value that was stored/loaded.
    pub ssa_value: SsaValue,
}

/// Bounded symbolic heap tracking field-level symbolic values and taint.
///
/// Cloned at fork points during multi-path exploration (Phase 18b).  Bounded
/// by [`MAX_HEAP_ENTRIES`] total entries and [`MAX_FIELDS_PER_OBJECT`] per
/// object to prevent blowup on object-heavy code.
#[derive(Clone, Debug)]
pub struct SymbolicHeap {
    /// Maps (object, field) → symbolic expression.
    fields: HashMap<HeapKey, SymbolicValue>,
    /// Tracks which heap keys carry taint.
    tainted_keys: HashSet<HeapKey>,
    /// Field access trace for witness generation.
    field_accesses: Vec<FieldAccessRecord>,
}

impl SymbolicHeap {
    /// Create an empty symbolic heap.
    pub fn new() -> Self {
        SymbolicHeap {
            fields: HashMap::new(),
            tainted_keys: HashSet::new(),
            field_accesses: Vec::new(),
        }
    }

    /// Store a symbolic value into a heap field.
    ///
    /// Bounded: silently drops the store if [`MAX_HEAP_ENTRIES`] or
    /// [`MAX_FIELDS_PER_OBJECT`] would be exceeded.  This is conservative —
    /// subsequent loads return `Unknown`.
    pub fn store(&mut self, key: HeapKey, value: SymbolicValue, tainted: bool) {
        // Check per-object bound (only for new fields on this object).
        if !self.fields.contains_key(&key) {
            if self.fields.len() >= MAX_HEAP_ENTRIES {
                return; // global cap
            }
            if self.fields_for_object(key.object) >= MAX_FIELDS_PER_OBJECT {
                return; // per-object cap
            }
        }
        self.fields.insert(key.clone(), value);
        if tainted {
            self.tainted_keys.insert(key);
        } else {
            self.tainted_keys.remove(&key);
        }
    }

    /// Load the symbolic value for a heap field.
    ///
    /// Returns `Unknown` if absent or evicted.
    pub fn load(&self, key: &HeapKey) -> SymbolicValue {
        self.fields
            .get(key)
            .cloned()
            .unwrap_or(SymbolicValue::Unknown)
    }

    /// Check if a heap field is tainted.
    pub fn is_tainted(&self, key: &HeapKey) -> bool {
        self.tainted_keys.contains(key)
    }

    /// Record a field access for witness generation.
    pub fn record_access(&mut self, record: FieldAccessRecord) {
        self.field_accesses.push(record);
    }

    /// Get the field access trace for witness generation.
    pub fn field_accesses(&self) -> &[FieldAccessRecord] {
        &self.field_accesses
    }

    /// Widen all heap entries to `Unknown`, preserving taint flags.
    ///
    /// Called at loop heads after bounded unrolling.  Symbolic precision is
    /// lost (we no longer know the concrete field values), but taint provenance
    /// is preserved: a tainted field remains tainted after widening.
    pub fn widen(&mut self) {
        for value in self.fields.values_mut() {
            *value = SymbolicValue::Unknown;
        }
        // tainted_keys intentionally NOT cleared.
    }

    /// Count fields stored for a specific object.
    fn fields_for_object(&self, object: HeapObjectId) -> usize {
        self.fields
            .keys()
            .filter(|k| k.object == object)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a dotted define/var_name string into `(receiver, field)`.
///
/// Splits on the last `.`:
/// - `"user.name"` → `Some(("user", "name"))`
/// - `"a.b.c"` → `Some(("a.b", "c"))`
/// - `"noDot"` → `None`
/// - `".field"` → `None` (empty receiver)
/// - `"obj."` → `None` (empty field)
pub fn split_field_access(dotted: &str) -> Option<(&str, &str)> {
    let dot_pos = dotted.rfind('.')?;
    if dot_pos == 0 || dot_pos == dotted.len() - 1 {
        return None;
    }
    Some((&dotted[..dot_pos], &dotted[dot_pos + 1..]))
}

/// Resolve a receiver name to an SSA value by scanning `value_defs` backwards.
///
/// Finds the most recent definition of `receiver_name` that precedes
/// `current_value` (by SSA value index).  Returns `None` if not found.
pub fn resolve_receiver_ssa(
    receiver_name: &str,
    ssa: &SsaBody,
    current_value: SsaValue,
) -> Option<SsaValue> {
    let limit = (current_value.0 as usize).min(ssa.value_defs.len());
    for idx in (0..limit).rev() {
        if let Some(ref name) = ssa.value_defs[idx].var_name {
            if name == receiver_name {
                return Some(SsaValue(idx as u32));
            }
        }
    }
    None
}

/// Resolve an SSA value to a singleton `HeapObjectId` via points-to analysis.
///
/// Returns `Some` only when the points-to set contains exactly one object.
/// May-alias (set size > 1) or unknown (not in result) returns `None` —
/// the caller should fall through to existing behavior (sound: never pick
/// among ambiguous options).
pub fn resolve_singleton_object(
    ssa_val: SsaValue,
    points_to: &PointsToResult,
) -> Option<HeapObjectId> {
    let pts = points_to.get(ssa_val)?;
    if pts.len() == 1 {
        pts.iter().next().copied()
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(n: u32) -> HeapObjectId {
        HeapObjectId(SsaValue(n))
    }

    fn named_key(obj_id: u32, field: &str) -> HeapKey {
        HeapKey {
            object: obj(obj_id),
            field: FieldSlot::Named(field.to_string()),
        }
    }

    fn elements_key(obj_id: u32) -> HeapKey {
        HeapKey {
            object: obj(obj_id),
            field: FieldSlot::Elements,
        }
    }

    #[test]
    fn store_load_roundtrip() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        let val = SymbolicValue::ConcreteStr("alice".to_string());
        heap.store(key.clone(), val.clone(), false);
        assert_eq!(heap.load(&key), val);
    }

    #[test]
    fn load_missing_returns_unknown() {
        let heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        assert_eq!(heap.load(&key), SymbolicValue::Unknown);
    }

    #[test]
    fn taint_propagation_through_store_load() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        heap.store(key.clone(), SymbolicValue::Symbol(SsaValue(10)), true);
        assert!(heap.is_tainted(&key));

        // Overwrite with non-tainted value
        heap.store(key.clone(), SymbolicValue::Concrete(42), false);
        assert!(!heap.is_tainted(&key));
    }

    #[test]
    fn max_heap_entries_eviction() {
        let mut heap = SymbolicHeap::new();
        // Fill MAX_HEAP_ENTRIES entries across many objects
        for i in 0..MAX_HEAP_ENTRIES as u32 {
            let key = named_key(i, "f");
            heap.store(key, SymbolicValue::Concrete(i as i64), false);
        }
        assert_eq!(heap.fields.len(), MAX_HEAP_ENTRIES);

        // 65th store should be silently dropped
        let overflow_key = named_key(999, "overflow");
        heap.store(overflow_key.clone(), SymbolicValue::Concrete(999), false);
        assert_eq!(heap.load(&overflow_key), SymbolicValue::Unknown);
        assert_eq!(heap.fields.len(), MAX_HEAP_ENTRIES);
    }

    #[test]
    fn max_fields_per_object_eviction() {
        let mut heap = SymbolicHeap::new();
        // Fill MAX_FIELDS_PER_OBJECT fields on one object
        for i in 0..MAX_FIELDS_PER_OBJECT {
            let key = named_key(0, &format!("field_{i}"));
            heap.store(key, SymbolicValue::Concrete(i as i64), false);
        }
        assert_eq!(heap.fields_for_object(obj(0)), MAX_FIELDS_PER_OBJECT);

        // 9th field on same object should be dropped
        let overflow_key = named_key(0, "overflow");
        heap.store(overflow_key.clone(), SymbolicValue::Concrete(99), false);
        assert_eq!(heap.load(&overflow_key), SymbolicValue::Unknown);
        assert_eq!(heap.fields_for_object(obj(0)), MAX_FIELDS_PER_OBJECT);

        // But a different object is fine
        let other_key = named_key(1, "ok");
        heap.store(other_key.clone(), SymbolicValue::Concrete(1), false);
        assert_eq!(heap.load(&other_key), SymbolicValue::Concrete(1));
    }

    #[test]
    fn widen_preserves_taint_clears_values() {
        let mut heap = SymbolicHeap::new();
        let key = named_key(0, "name");
        heap.store(key.clone(), SymbolicValue::ConcreteStr("alice".to_string()), true);

        heap.widen();

        // Value is Unknown after widening
        assert_eq!(heap.load(&key), SymbolicValue::Unknown);
        // Taint is preserved
        assert!(heap.is_tainted(&key));
    }

    #[test]
    fn split_field_access_cases() {
        assert_eq!(split_field_access("obj.field"), Some(("obj", "field")));
        assert_eq!(split_field_access("a.b.c"), Some(("a.b", "c")));
        assert_eq!(split_field_access("noDot"), None);
        assert_eq!(split_field_access(".field"), None);
        assert_eq!(split_field_access("obj."), None);
        assert_eq!(split_field_access(""), None);
        assert_eq!(split_field_access("."), None);
    }

    #[test]
    fn resolve_singleton_returns_none_for_absent() {
        // PointsToResult::empty() has no entries → None for any query.
        let pts = PointsToResult::empty();
        assert_eq!(resolve_singleton_object(SsaValue(0), &pts), None);
        assert_eq!(resolve_singleton_object(SsaValue(99), &pts), None);
    }

    #[test]
    fn field_slot_named_vs_elements_distinct() {
        let mut heap = SymbolicHeap::new();
        let named = named_key(0, "items");
        let elements = elements_key(0);

        heap.store(named.clone(), SymbolicValue::Concrete(1), false);
        heap.store(elements.clone(), SymbolicValue::Concrete(2), true);

        assert_eq!(heap.load(&named), SymbolicValue::Concrete(1));
        assert_eq!(heap.load(&elements), SymbolicValue::Concrete(2));
        assert!(!heap.is_tainted(&named));
        assert!(heap.is_tainted(&elements));
    }

    #[test]
    fn field_access_recording() {
        let mut heap = SymbolicHeap::new();
        assert!(heap.field_accesses().is_empty());

        heap.record_access(FieldAccessRecord {
            object_name: "user".to_string(),
            field_name: "name".to_string(),
            ssa_value: SsaValue(5),
        });

        assert_eq!(heap.field_accesses().len(), 1);
        assert_eq!(heap.field_accesses()[0].object_name, "user");
        assert_eq!(heap.field_accesses()[0].field_name, "name");
    }
}
