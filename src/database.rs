pub mod index {
    use crate::commands::scan::Diag;
    use crate::errors::{NyxError, NyxResult};
    use crate::patterns::Severity;
    use r2d2::{Pool, PooledConnection};
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
    use std::fs;
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// DB schema (foreign‑keys enabled).
    const SCHEMA: &str = r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            path TEXT NOT NULL,
            hash BLOB NOT NULL,
            mtime INTEGER NOT NULL,
            scanned_at INTEGER NOT NULL,
            UNIQUE(project, path)
        );

        CREATE TABLE IF NOT EXISTS issues (file_id INTEGER NOT NULL
                              REFERENCES files(id)
                              ON DELETE CASCADE,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            line INTEGER NOT NULL,
            col INTEGER NOT NULL,
            PRIMARY KEY (file_id, rule_id, line, col));

        CREATE TABLE IF NOT EXISTS function_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            summary TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, arity)
        );

        CREATE TABLE IF NOT EXISTS ssa_function_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash BLOB NOT NULL,
            name TEXT NOT NULL,
            arity INTEGER NOT NULL DEFAULT -1,
            lang TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(project, file_path, name, arity)
        );
    "#;

    // TODO: ADD CLEANS FOR EACH TABLE BASED ON PROJECT WHICH RUNS ON CLEAN
    // TODO: ADD DROP AND GIVE A CLI PARAMETER FOR DROP

    /// A single issue row, ready for insertion.
    #[derive(Debug, Clone)]
    pub struct IssueRow<'a> {
        pub rule_id: &'a str,
        pub severity: &'a str,
        pub line: i64,
        pub col: i64,
    }

    pub struct Indexer {
        conn: PooledConnection<SqliteConnectionManager>,
        project: String,
    }

    impl Indexer {
        pub fn init(database_path: &Path) -> NyxResult<Arc<Pool<SqliteConnectionManager>>> {
            let _span = tracing::info_span!("db_init", path = %database_path.display()).entered();
            // NO_MUTEX is safe because r2d2 ensures each pooled connection
            // is only ever used by one thread at a time.  Combined with WAL
            // mode this allows concurrent readers + a single writer without
            // the global serialization that FULL_MUTEX causes.
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            let manager = SqliteConnectionManager::file(database_path).with_flags(flags);
            let pool = Arc::new(Pool::new(manager)?);

            {
                let conn = pool.get()?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.pragma_update(None, "synchronous", "NORMAL")?;
                conn.pragma_update(None, "cache_size", "-8000")?; // 8 MB
                conn.pragma_update(None, "temp_store", "MEMORY")?;
                conn.pragma_update(None, "mmap_size", "268435456")?; // 256 MB
                conn.execute_batch(SCHEMA)?;

                // Migrate: if the function_summaries table has the old schema
                // (missing `arity` column), drop and recreate it.
                let has_arity: bool = conn
                    .prepare("PRAGMA table_info(function_summaries)")
                    .and_then(|mut s| {
                        let cols: Vec<String> = s
                            .query_map([], |r| r.get::<_, String>(1))?
                            .filter_map(Result::ok)
                            .collect();
                        Ok(cols.iter().any(|c| c == "arity"))
                    })
                    .unwrap_or(true);

                if !has_arity {
                    tracing::info!("migrating function_summaries: adding arity column");
                    conn.execute_batch("DROP TABLE IF EXISTS function_summaries;")?;
                    conn.execute_batch(
                        "CREATE TABLE IF NOT EXISTS function_summaries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            project TEXT NOT NULL,
                            file_path TEXT NOT NULL,
                            file_hash BLOB NOT NULL,
                            name TEXT NOT NULL,
                            arity INTEGER NOT NULL DEFAULT -1,
                            lang TEXT NOT NULL,
                            summary TEXT NOT NULL,
                            updated_at INTEGER NOT NULL,
                            UNIQUE(project, file_path, name, arity)
                        );",
                    )?;
                }
            }
            Ok(pool)
        }

        pub fn from_pool(project: &str, pool: &Pool<SqliteConnectionManager>) -> NyxResult<Self> {
            let conn = pool.get()?;
            Ok(Self {
                conn,
                project: project.to_owned(),
            })
        }

        // helper so code below can treat PooledConnection like &Connection
        fn c(&self) -> &Connection {
            self.conn.deref()
        }

        /// Return true when the file *content* or *mtime* changed since the last scan.
        ///
        /// Short-circuits on mtime: if the stored mtime matches the
        /// filesystem mtime, the file is assumed unchanged (skip hash).
        #[allow(dead_code)] // used in tests and by should_scan_with_hash callers may fall back
        pub fn should_scan(&self, path: &Path) -> NyxResult<bool> {
            let meta = fs::metadata(path)?;
            let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;

            let row: Option<(Vec<u8>, i64)> = self
                .conn
                .query_row(
                    "SELECT hash, mtime FROM files WHERE project = ?1 AND path = ?2",
                    params![self.project, path.to_string_lossy()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            Ok(match row {
                Some((stored_hash, stored_mtime)) => {
                    if stored_mtime != mtime {
                        // mtime changed — must re-scan
                        true
                    } else {
                        // mtime matches — compare hash only if cheap
                        // (the caller already read the file and can use
                        // should_scan_with_hash instead for full accuracy)
                        let digest = Self::digest_file(path)?;
                        stored_hash != digest
                    }
                }
                None => true,
            })
        }

        /// Like [`should_scan`] but accepts a pre-computed hash to avoid
        /// redundant file reads.
        pub fn should_scan_with_hash(&self, path: &Path, hash: &[u8]) -> NyxResult<bool> {
            let row: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT hash FROM files WHERE project = ?1 AND path = ?2",
                    params![self.project, path.to_string_lossy()],
                    |r| r.get(0),
                )
                .optional()?;

            Ok(match row {
                Some(stored_hash) => stored_hash != hash,
                None => true,
            })
        }

        /// Insert or update the `files` row and return its id.
        pub fn upsert_file(&self, path: &Path) -> NyxResult<i64> {
            let bytes = fs::read(path)?;
            let hash = Self::digest_bytes(&bytes);
            self.upsert_file_with_hash(path, &hash)
        }

        /// Insert or update the `files` row using a pre-computed hash.
        /// Avoids redundant file reads when the caller already has the hash.
        pub fn upsert_file_with_hash(&self, path: &Path, hash: &[u8]) -> NyxResult<i64> {
            let meta = fs::metadata(path)?;
            let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let scanned_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let path_str = path.to_string_lossy();

            // Use a single statement: upsert then query the id.
            self.c().execute(
                "INSERT INTO files (project, path, hash, mtime, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(project,path) DO UPDATE
                 SET hash = excluded.hash,
                     mtime = excluded.mtime,
                     scanned_at = excluded.scanned_at",
                params![self.project, path_str, hash, mtime, scanned_at],
            )?;

            let id: i64 = self.c().query_row(
                "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                params![self.project, path_str],
                |r| r.get(0),
            )?;
            Ok(id)
        }

        /// Replace all issues for `file_id` with the supplied set.
        pub fn replace_issues<'a>(
            &mut self,
            file_id: i64,
            issues: impl IntoIterator<Item = IssueRow<'a>>,
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            tx.execute("DELETE FROM issues WHERE file_id = ?", params![file_id])?;

            {
                let mut stmt = tx.prepare(
                    "INSERT INTO issues (file_id, rule_id, severity, line, col)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for iss in issues {
                    stmt.execute(params![
                        file_id,
                        iss.rule_id,
                        iss.severity,
                        iss.line,
                        iss.col
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        }

        /// Gets the issues for a specific file so we don't have to rescan
        pub fn get_issues_from_file(&self, path: &Path) -> NyxResult<Vec<Diag>> {
            let file_id: i64 = self.c().query_row(
                "SELECT id FROM files WHERE project = ?1 AND path = ?2",
                params![self.project, path.to_string_lossy()],
                |r| r.get(0),
            )?;

            let mut stmt = self.c().prepare(
                "SELECT rule_id, severity, line, col
         FROM issues
         WHERE file_id = ?1",
            )?;

            let issue_iter = stmt.query_map([file_id], |row| {
                let sev_str: String = row.get(1)?;
                Ok(Diag {
                    path: path.to_string_lossy().to_string(),
                    id: row.get::<_, String>(0)?, // rule_id
                    line: row.get::<_, i64>(2)? as usize,
                    col: row.get::<_, i64>(3)? as usize,
                    severity: Severity::from_str(&sev_str).unwrap(),
                    category: crate::patterns::FindingCategory::Security,
                    path_validated: false,
                    guard_kind: None,
                    message: None,
                    labels: vec![],
                    confidence: None,
                    evidence: None,
                    rank_score: None,
                    rank_reason: None,
                    suppressed: false,
                    suppression: None,
                    rollup: None,
                })
            })?;

            Ok(issue_iter.filter_map(Result::ok).collect())
        }

        /// Atomically replace all function summaries for a single file.
        ///
        /// Deletes every existing summary row for `(project, file_path)` then
        /// inserts the new set.  This keeps the table in sync when a file is
        /// re‑parsed and its functions change.
        pub fn replace_summaries_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            summaries: &[crate::summary::FuncSummary],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO function_summaries
                        (project, file_path, file_hash, name, arity, lang, summary, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )?;

                for s in summaries {
                    let json = serde_json::to_string(s)
                        .map_err(|e| NyxError::Msg(format!("summary serialise: {e}")))?;
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        s.name,
                        s.param_count as i64,
                        s.lang,
                        json,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Atomically replace all SSA function summaries for a single file.
        pub fn replace_ssa_summaries_for_file(
            &mut self,
            file_path: &Path,
            file_hash: &[u8],
            summaries: &[(String, usize, String, String, crate::summary::ssa_summary::SsaFuncSummary)],
        ) -> NyxResult<()> {
            let tx = self.conn.transaction()?;
            let path_str = file_path.to_string_lossy();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            tx.execute(
                "DELETE FROM ssa_function_summaries WHERE project = ?1 AND file_path = ?2",
                params![self.project, path_str],
            )?;

            {
                let mut stmt = tx.prepare(
                    "INSERT OR REPLACE INTO ssa_function_summaries
                        (project, file_path, file_hash, name, arity, lang, namespace, summary, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )?;

                for (name, arity, lang, namespace, summary) in summaries {
                    let json = serde_json::to_string(summary)
                        .map_err(|e| NyxError::Msg(format!("SSA summary serialise: {e}")))?;
                    stmt.execute(params![
                        self.project,
                        path_str,
                        file_hash,
                        name,
                        *arity as i64,
                        lang,
                        namespace,
                        json,
                        now
                    ])?;
                }
            }

            tx.commit()?;
            Ok(())
        }

        /// Load every function summary for this project.
        ///
        /// Reads all JSON strings from SQLite in one pass, then
        /// deserializes them in parallel with rayon for large result sets.
        pub fn load_all_summaries(&self) -> NyxResult<Vec<crate::summary::FuncSummary>> {
            let mut stmt = self
                .c()
                .prepare("SELECT summary FROM function_summaries WHERE project = ?1")?;

            let jsons: Vec<String> = stmt
                .query_map([&self.project], |row| row.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect();

            // Parallel JSON deserialization for large sets
            if jsons.len() > 256 {
                use rayon::prelude::*;
                let results: Vec<_> = jsons
                    .par_iter()
                    .filter_map(|json| {
                        serde_json::from_str::<crate::summary::FuncSummary>(json).ok()
                    })
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(jsons.len());
                for json in &jsons {
                    if let Ok(s) = serde_json::from_str::<crate::summary::FuncSummary>(json) {
                        out.push(s);
                    }
                }
                Ok(out)
            }
        }

        /// Load every SSA function summary for this project.
        ///
        /// Returns rows with full metadata for `FuncKey` reconstruction:
        /// `(file_path, name, lang, arity, namespace, SsaFuncSummary)`.
        pub fn load_all_ssa_summaries(
            &self,
        ) -> NyxResult<Vec<(String, String, String, i64, String, crate::summary::ssa_summary::SsaFuncSummary)>> {
            let mut stmt = self.c().prepare(
                "SELECT file_path, name, lang, arity, namespace, summary
                 FROM ssa_function_summaries WHERE project = ?1",
            )?;

            let rows: Vec<(String, String, String, i64, String, String)> = stmt
                .query_map([&self.project], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();

            if rows.len() > 256 {
                use rayon::prelude::*;
                let results: Vec<_> = rows
                    .par_iter()
                    .filter_map(|(fp, name, lang, arity, ns, json)| {
                        serde_json::from_str::<crate::summary::ssa_summary::SsaFuncSummary>(json)
                            .ok()
                            .map(|s| (fp.clone(), name.clone(), lang.clone(), *arity, ns.clone(), s))
                    })
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(rows.len());
                for (fp, name, lang, arity, ns, json) in &rows {
                    if let Ok(s) =
                        serde_json::from_str::<crate::summary::ssa_summary::SsaFuncSummary>(json)
                    {
                        out.push((fp.clone(), name.clone(), lang.clone(), *arity, ns.clone(), s));
                    }
                }
                Ok(out)
            }
        }

        /// gets files from the database
        pub fn get_files(&self, project: &str) -> NyxResult<Vec<PathBuf>> {
            let mut stmt = self.c().prepare(
                "SELECT path
         FROM files
         WHERE project = ?1",
            )?;

            let file_iter = stmt.query_map([project], |row| row.get::<_, String>(0))?;

            Ok(file_iter
                .map(|p| p.map(PathBuf::from))
                .collect::<Result<_, _>>()?)
        }

        // -------------------------------------------------------------------------
        // Maintenance utilities
        // -------------------------------------------------------------------------
        pub fn clear(&self) -> NyxResult<()> {
            self.c().execute_batch(
                r#"
        PRAGMA foreign_keys = OFF;

        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS function_summaries;
        DROP TABLE IF EXISTS ssa_function_summaries;

        PRAGMA foreign_keys = ON;
        VACUUM;
        "#,
            )?;

            self.c().execute_batch(SCHEMA)?;
            Ok(())
        }

        pub fn vacuum(&self) -> NyxResult<()> {
            self.c().execute("VACUUM;", [])?;
            Ok(())
        }

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------
        #[allow(dead_code)] // used by should_scan() and tests
        fn digest_file(path: &Path) -> NyxResult<Vec<u8>> {
            let mut hasher = blake3::Hasher::new();
            let mut file = fs::File::open(path)?;
            std::io::copy(&mut file, &mut hasher)?;
            Ok(hasher.finalize().as_bytes().to_vec())
        }

        /// Hash already-read bytes without re-reading from disk.
        pub fn digest_bytes(bytes: &[u8]) -> Vec<u8> {
            let mut hasher = blake3::Hasher::new();
            hasher.update(bytes);
            hasher.finalize().as_bytes().to_vec()
        }
    }
}

#[test]
fn indexer_should_scan_and_upsert_logic() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("sample.rs");
    std::fs::write(&file, "fn main() {}").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();

    // first time: nothing in DB → must scan
    assert!(idx.should_scan(&file).unwrap());

    // after upsert: no changes → should *not* scan
    idx.upsert_file(&file).unwrap();
    assert!(!idx.should_scan(&file).unwrap());

    // modify contents
    std::thread::sleep(std::time::Duration::from_millis(25)); // ensure mtime tick
    std::fs::write(&file, "fn main() { /* changed */ }").unwrap();
    assert!(idx.should_scan(&file).unwrap());
}

#[test]
fn replace_issues_and_query_back() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let file = td.path().join("code.go");
    std::fs::write(&file, "package main").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();
    let fid = idx.upsert_file(&file).unwrap();

    let issues = [
        index::IssueRow {
            rule_id: "X1",
            severity: "High",
            line: 3,
            col: 7,
        },
        index::IssueRow {
            rule_id: "X2",
            severity: "Low",
            line: 4,
            col: 1,
        },
    ];
    idx.replace_issues(fid, issues.clone()).unwrap();

    let stored = idx.get_issues_from_file(&file).unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X1" && d.severity == crate::patterns::Severity::High)
    );
    assert!(
        stored
            .iter()
            .any(|d| d.id == "X2" && d.severity == crate::patterns::Severity::Low)
    );
}

#[test]
fn clear_and_vacuum_reset_tables() {
    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("f.rs");
    std::fs::write(&f, "//").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let idx = index::Indexer::from_pool("proj", &pool).unwrap();
    idx.upsert_file(&f).unwrap();

    assert!(!idx.get_files("proj").unwrap().is_empty());
    idx.clear().unwrap();
    idx.vacuum().unwrap();
    assert!(idx.get_files("proj").unwrap().is_empty());
}

#[test]
fn ssa_summaries_round_trip() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("app.py");
    std::fs::write(&f, "def process(data): return data").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"def process(data): return data");
    let summaries = vec![
        (
            "process".to_string(),
            1_usize,
            "python".to_string(),
            "app.py".to_string(),
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::Identity)],
                param_to_sink: vec![],
                source_caps: Cap::empty(),
                param_to_sink_param: vec![],
            },
        ),
        (
            "sanitize".to_string(),
            1_usize,
            "python".to_string(),
            "app.py".to_string(),
            SsaFuncSummary {
                param_to_return: vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))],
                param_to_sink: vec![(0, Cap::SQL_QUERY)],
                source_caps: Cap::ENV_VAR,
                param_to_sink_param: vec![],
            },
        ),
    ];

    idx.replace_ssa_summaries_for_file(&f, &hash, &summaries).unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 2);

    // Check first summary
    let (_, name1, lang1, arity1, ns1, sum1) = loaded.iter()
        .find(|(_, n, _, _, _, _)| n == "process")
        .unwrap();
    assert_eq!(name1, "process");
    assert_eq!(lang1, "python");
    assert_eq!(*arity1, 1);
    assert_eq!(ns1, "app.py");
    assert_eq!(sum1.param_to_return, vec![(0, TaintTransform::Identity)]);
    assert!(sum1.param_to_sink.is_empty());

    // Check second summary
    let (_, name2, _, _, _, sum2) = loaded.iter()
        .find(|(_, n, _, _, _, _)| n == "sanitize")
        .unwrap();
    assert_eq!(name2, "sanitize");
    assert_eq!(sum2.param_to_return, vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))]);
    assert_eq!(sum2.param_to_sink, vec![(0, Cap::SQL_QUERY)]);
    assert_eq!(sum2.source_caps, Cap::ENV_VAR);
}

#[test]
fn ssa_summaries_hash_rescan_replaces_stale() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("lib.py");
    std::fs::write(&f, "v1").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash_v1 = index::Indexer::digest_bytes(b"v1");
    let sums_v1 = vec![(
        "old_func".to_string(),
        1_usize,
        "python".to_string(),
        "lib.py".to_string(),
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v1, &sums_v1).unwrap();

    // Simulate file change: different function, different hash
    let hash_v2 = index::Indexer::digest_bytes(b"v2");
    let sums_v2 = vec![(
        "new_func".to_string(),
        2_usize,
        "python".to_string(),
        "lib.py".to_string(),
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::StripBits(Cap::SHELL_ESCAPE))],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v2, &sums_v2).unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 1, "old summary should be replaced, not duplicated");
    assert_eq!(loaded[0].1, "new_func");
}

#[test]
fn clear_drops_ssa_summaries_table() {
    use crate::labels::Cap;
    use crate::summary::ssa_summary::{SsaFuncSummary, TaintTransform};

    let td = tempfile::tempdir().unwrap();
    let db = td.path().join("nyx.sqlite");
    let f = td.path().join("test.py");
    std::fs::write(&f, "x").unwrap();

    let pool = index::Indexer::init(&db).unwrap();
    let mut idx = index::Indexer::from_pool("proj", &pool).unwrap();

    let hash = index::Indexer::digest_bytes(b"x");
    let sums = vec![(
        "f".to_string(),
        1_usize,
        "python".to_string(),
        "test.py".to_string(),
        SsaFuncSummary {
            param_to_return: vec![(0, TaintTransform::Identity)],
            param_to_sink: vec![],
            source_caps: Cap::empty(),
            param_to_sink_param: vec![],
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash, &sums).unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 1);

    idx.clear().unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 0);
}
