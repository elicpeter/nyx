// Phase 5 typed-extractor exclusion: an Axum-style `Path<i64>`
// parameter is a framework-validated numeric extractor.  The runtime
// guarantees a numeric value, so even though `project_id` reaches a
// SQL helper, the rule must NOT fire — the value cannot carry an
// injection payload nor bypass ownership.
use axum::extract::Path;

struct Db;
impl Db {
    fn fetch(&self, _q: &str, _a: &[i64]) {}
}

pub async fn read_project(Path(project_id): Path<i64>) {
    let db = Db;
    db.fetch("SELECT * FROM projects WHERE id = ?1", &[project_id]);
}
