// Real-repo precision guard mirroring meilisearch's index-scheduler
// shape:
// crates/index-scheduler/src/scheduler/process_snapshot_creation.rs::remove_tasks
// (`unsafe fn remove_tasks(tasks: &[Task], dst: &std::path::Path,
// index_base_map_size: usize)` plus per-loop bitmap mutations on
// destructured heed `Database` handles), plus the LocalCollection
// receiver-type cluster
// (`crates/index-scheduler/src/scheduler/enterprise_edition/network.rs::balance_shards`,
// `unsharded: RoaringBitmap`).
//
// Both engine fixes must hold: the Rust `parameter` arm in
// `collect_param_names` (only descends into `pattern`, never `type`)
// and the Rust LocalCollection type-text classifier
// (`rust_type_to_local_collection`).  Without either, this file would
// produce missing-ownership-check findings on internal helpers /
// in-memory bitmap mutations.

use std::collections::{BTreeSet, HashMap, HashSet};

struct RoaringBitmap;
impl RoaringBitmap {
    fn new() -> Self { Self }
    fn insert(&mut self, _x: u32) -> bool { true }
    fn remove(&mut self, _x: u32) -> bool { true }
    fn contains(&self, _x: u32) -> bool { true }
}

struct Task { uid: u32 }

struct Database;
impl Database {
    fn delete(&self, _w: &mut u32, _u: &u32) -> Result<(), ()> { Ok(()) }
}

struct TaskQueue {
    all_tasks: Database,
    canceled_by: Database,
}

// Rust `parameter` arm: type-segment idents (`std`, `path`, `Path`)
// must NOT pollute `unit.params` and gate user-input-evidence open.
unsafe fn remove_tasks(
    tasks: &[Task],
    dst: &std::path::Path,
    sz: usize,
) -> Result<(), ()> {
    let _ = (dst, sz);
    let mut wtxn = 0u32;
    let task_queue = TaskQueue {
        all_tasks: Database,
        canceled_by: Database,
    };
    let TaskQueue { all_tasks, canceled_by } = task_queue;
    for task in tasks {
        all_tasks.delete(&mut wtxn, &task.uid)?;
        canceled_by.delete(&mut wtxn, &task.uid)?;
    }
    Ok(())
}

// LocalCollection typed param: `unsharded: RoaringBitmap` resolves to
// `TypeKind::LocalCollection`, so `unsharded.insert(docid)` /
// `unsharded.remove(docid)` classify as `SinkClass::InMemoryLocal`
// (non-auth-relevant).
fn balance_shards(mut unsharded: RoaringBitmap, docid: u32) {
    unsharded.insert(docid);
    unsharded.remove(docid);
}

// `&'a mut HashMap<...>` reference + lifetime: ref-stripping must
// reach the type head.
fn store_shard_docids<'a>(
    new_shard_docids: &'a mut HashMap<String, u32>,
    shard: String,
    docid: u32,
) {
    new_shard_docids.insert(shard, docid);
}

fn add_user_id(ids: &mut HashSet<u64>, user_id: u64) {
    ids.insert(user_id);
    ids.remove(&user_id);
}

fn collect_seen(seen: &mut BTreeSet<u32>, item_id: u32) {
    seen.insert(item_id);
}

fn build_local_set(task_id: u32) -> RoaringBitmap {
    let mut s = RoaringBitmap::new();
    s.insert(task_id);
    s
}
