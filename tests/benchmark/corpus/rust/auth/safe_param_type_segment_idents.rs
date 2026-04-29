// Internal helper whose parameter list contains type-segment idents
// that lowercase-match the framework-request-name allow-list (`path`,
// `request`, `ctx`, `body`, `path`).  Before the
// `collect_param_names` Rust-parameter arm, the recursive default arm
// pulled `std`, `path`, `Path` out of `dst: &std::path::Path` and
// pushed them into `unit.params`, `path` then matched the
// framework-name list and gated `unit_has_user_input_evidence` open,
// firing `missing_ownership_check` at every id-shaped operation in
// the body.
//
// Cluster surfaced from
// meilisearch/index-scheduler/src/scheduler/process_snapshot_creation.rs::remove_tasks
// (`unsafe fn remove_tasks(tasks: &[Task], dst: &std::path::Path,
// index_base_map_size: usize)`).  None of the actual params (`tasks`,
// `dst`, `sz`) match the user-input-evidence heuristic, so the rule
// must NOT fire on the internal task-cleanup loop.

struct Task {
    uid: u32,
}

struct Database;

impl Database {
    fn delete(&self, _w: &mut u32, _u: &u32) -> Result<(), ()> {
        Ok(())
    }
}

struct TaskQueue {
    all_tasks: Database,
    canceled_by: Database,
}

fn remove_tasks(
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
    let TaskQueue {
        all_tasks,
        canceled_by,
    } = task_queue;
    for task in tasks {
        all_tasks.delete(&mut wtxn, &task.uid)?;
        canceled_by.delete(&mut wtxn, &task.uid)?;
    }
    Ok(())
}

// Same shape with a typed wrapper whose tail segment lowercases to
// `path` (`PathBuf` → `pathbuf` does NOT match, but `Path` does).
// Confirms the Rust `parameter` arm in `collect_param_names` keeps
// `Path` out of `unit.params` even when wrapped in a generic.

struct Wrapper<T>(T);
struct PathHandle;
struct Item {
    uid: u32,
}
struct Repo;
impl Repo {
    fn delete(&self, _u: &u32) {}
}

fn cleanup_internal(out: Wrapper<PathHandle>, items: &[Item]) {
    let _ = out;
    let repo = Repo;
    for item in items {
        repo.delete(&item.uid);
    }
}
