// Function-parameter type annotations naming an in-memory container
// (`RoaringBitmap`, `HashMap<K, V>`, `HashSet<T>`, ...) classify the
// receiver as `TypeKind::LocalCollection`, which the auth analyser
// maps to `SinkClass::InMemoryLocal` (always non-auth-relevant).
// Without this, the verb-name dispatch (`is_mutation: insert/remove`)
// classified `unsharded.insert(docid)` /
// `task_ids.insert(task_id)` as `DbMutation` and fired
// `missing_ownership_check` whenever the function had at least one
// id-shaped parameter to pass `unit_has_user_input_evidence`.
//
// Cluster surfaced from
// meilisearch/index-scheduler/src/scheduler/enterprise_edition/network.rs::balance_shards
// (`unsharded: RoaringBitmap` typed parameter) and same-pattern
// helpers across the index-scheduler.

use std::collections::{BTreeSet, HashMap, HashSet};

struct RoaringBitmap;
impl RoaringBitmap {
    fn new() -> Self { Self }
    fn insert(&mut self, _x: u32) -> bool { true }
    fn remove(&mut self, _x: u32) -> bool { true }
    fn contains(&self, _x: u32) -> bool { true }
}

// 1. Bare-typed RoaringBitmap parameter — function has id-like param
//    `docid` so user-input-evidence fires; the receiver type proves
//    the operation is in-memory bookkeeping.
fn balance_shards(mut unsharded: RoaringBitmap, docid: u32) {
    unsharded.insert(docid);
    unsharded.remove(docid);
}

// 2. `&mut RoaringBitmap` reference — ref-stripping must reach the
//    underlying type head.
fn process_docids(docids: &mut RoaringBitmap, docid: u32) {
    docids.insert(docid);
    docids.remove(docid);
    let _ = docids.contains(docid);
}

// 3. Lifetime-annotated reference: `&'a mut HashMap<...>`.
//    Module-path prefix would also be dropped; head matches `HashMap`.
fn store_shard_docids<'a>(
    new_shard_docids: &'a mut HashMap<String, u32>,
    shard: String,
    docid: u32,
) {
    new_shard_docids.insert(shard, docid);
}

// 4. Std-collection HashSet typed param.
fn add_user_id(ids: &mut HashSet<u64>, user_id: u64) {
    ids.insert(user_id);
    ids.remove(&user_id);
}

// 5. Local var bound from constructor — already covered, but pinned
//    here as a regression guard for the `RoaringBitmap::new()`
//    constructor entry.
fn build_local_set(task_id: u32) -> RoaringBitmap {
    let mut s = RoaringBitmap::new();
    s.insert(task_id);
    s
}

// 6. BTreeSet typed param.
fn collect_seen(seen: &mut BTreeSet<u32>, item_id: u32) {
    seen.insert(item_id);
}
