pub mod index {
    #![allow(clippy::too_many_arguments, clippy::type_complexity)]

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

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            scan_root TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            duration_secs REAL,
            engine_version TEXT,
            languages TEXT,
            files_scanned INTEGER,
            files_skipped INTEGER,
            finding_count INTEGER,
            findings_json TEXT,
            timing_json TEXT,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_metrics (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
            cfg_nodes INTEGER,
            call_edges INTEGER,
            functions_analyzed INTEGER,
            summaries_reused INTEGER,
            unresolved_calls INTEGER
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            file_path TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id);

        CREATE TABLE IF NOT EXISTS triage_states (
            fingerprint TEXT PRIMARY KEY,
            state TEXT NOT NULL DEFAULT 'open',
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS triage_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_state TEXT NOT NULL,
            new_state TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_triage_audit_fp ON triage_audit_log(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_triage_audit_ts ON triage_audit_log(timestamp);

        CREATE TABLE IF NOT EXISTS triage_suppression_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suppress_by TEXT NOT NULL,
            match_value TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'suppressed',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(suppress_by, match_value)
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

    /// A scan record for DB persistence.
    #[derive(Debug, Clone)]
    pub struct ScanRecord {
        pub id: String,
        pub status: String,
        pub scan_root: String,
        pub started_at: Option<String>,
        pub finished_at: Option<String>,
        pub duration_secs: Option<f64>,
        pub engine_version: Option<String>,
        pub languages: Option<String>,
        pub files_scanned: Option<i64>,
        pub files_skipped: Option<i64>,
        pub finding_count: Option<i64>,
        pub findings_json: Option<String>,
        pub timing_json: Option<String>,
        pub error: Option<String>,
    }

    /// A triage audit log entry.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct AuditEntry {
        pub id: i64,
        pub fingerprint: String,
        pub action: String,
        pub previous_state: String,
        pub new_state: String,
        pub note: String,
        pub timestamp: String,
    }

    /// A pattern-based suppression rule.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct SuppressionRule {
        pub id: i64,
        pub suppress_by: String,
        pub match_value: String,
        pub state: String,
        pub note: String,
        pub created_at: String,
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
            summaries: &[(
                String,
                usize,
                String,
                String,
                crate::summary::ssa_summary::SsaFuncSummary,
            )],
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
        ) -> NyxResult<
            Vec<(
                String,
                String,
                String,
                i64,
                String,
                crate::summary::ssa_summary::SsaFuncSummary,
            )>,
        > {
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
                            .map(|s| {
                                (
                                    fp.clone(),
                                    name.clone(),
                                    lang.clone(),
                                    *arity,
                                    ns.clone(),
                                    s,
                                )
                            })
                    })
                    .collect();
                Ok(results)
            } else {
                let mut out = Vec::with_capacity(rows.len());
                for (fp, name, lang, arity, ns, json) in &rows {
                    if let Ok(s) =
                        serde_json::from_str::<crate::summary::ssa_summary::SsaFuncSummary>(json)
                    {
                        out.push((
                            fp.clone(),
                            name.clone(),
                            lang.clone(),
                            *arity,
                            ns.clone(),
                            s,
                        ));
                    }
                }
                Ok(out)
            }
        }

        /// Load symbol metadata (name, arity, lang, namespace) for a single file.
        ///
        /// Lighter than `load_all_ssa_summaries` — skips JSON deserialization of
        /// the full summary body and filters by file_path in the query.
        pub fn load_ssa_summaries_for_file(
            &self,
            file_path: &str,
        ) -> NyxResult<Vec<(String, i64, String, String)>> {
            let mut stmt = self.c().prepare(
                "SELECT name, arity, lang, namespace
                 FROM ssa_function_summaries
                 WHERE project = ?1 AND file_path = ?2",
            )?;
            let rows: Vec<(String, i64, String, String)> = stmt
                .query_map(rusqlite::params![self.project, file_path], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
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
        // Scan persistence
        // -------------------------------------------------------------------------

        /// Insert a new scan record.
        pub fn insert_scan(&self, record: &ScanRecord) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR REPLACE INTO scans (id, status, scan_root, started_at, finished_at,
                 duration_secs, engine_version, languages, files_scanned, files_skipped,
                 finding_count, findings_json, timing_json, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    record.id,
                    record.status,
                    record.scan_root,
                    record.started_at,
                    record.finished_at,
                    record.duration_secs,
                    record.engine_version,
                    record.languages,
                    record.files_scanned,
                    record.files_skipped,
                    record.finding_count,
                    record.findings_json,
                    record.timing_json,
                    record.error,
                ],
            )?;
            Ok(())
        }

        /// Update a scan record status and completion fields.
        pub fn update_scan(
            &self,
            id: &str,
            status: &str,
            finished_at: Option<&str>,
            duration_secs: Option<f64>,
            finding_count: Option<i64>,
            findings_json: Option<&str>,
            timing_json: Option<&str>,
            error: Option<&str>,
            files_scanned: Option<i64>,
            languages: Option<&str>,
        ) -> NyxResult<()> {
            self.c().execute(
                "UPDATE scans SET status = ?2, finished_at = ?3, duration_secs = ?4,
                 finding_count = ?5, findings_json = ?6, timing_json = ?7, error = ?8,
                 files_scanned = ?9, languages = ?10
                 WHERE id = ?1",
                params![
                    id,
                    status,
                    finished_at,
                    duration_secs,
                    finding_count,
                    findings_json,
                    timing_json,
                    error,
                    files_scanned,
                    languages,
                ],
            )?;
            Ok(())
        }

        /// Get a single scan record by ID.
        pub fn get_scan(&self, id: &str) -> NyxResult<Option<ScanRecord>> {
            let result = self
                .c()
                .query_row(
                    "SELECT id, status, scan_root, started_at, finished_at, duration_secs,
                     engine_version, languages, files_scanned, files_skipped, finding_count,
                     findings_json, timing_json, error
                     FROM scans WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok(ScanRecord {
                            id: row.get(0)?,
                            status: row.get(1)?,
                            scan_root: row.get(2)?,
                            started_at: row.get(3)?,
                            finished_at: row.get(4)?,
                            duration_secs: row.get(5)?,
                            engine_version: row.get(6)?,
                            languages: row.get(7)?,
                            files_scanned: row.get(8)?,
                            files_skipped: row.get(9)?,
                            finding_count: row.get(10)?,
                            findings_json: row.get(11)?,
                            timing_json: row.get(12)?,
                            error: row.get(13)?,
                        })
                    },
                )
                .optional()?;
            Ok(result)
        }

        /// List scan records, most recent first, up to `limit`.
        pub fn list_scans(&self, limit: i64) -> NyxResult<Vec<ScanRecord>> {
            let mut stmt = self.c().prepare(
                "SELECT id, status, scan_root, started_at, finished_at, duration_secs,
                 engine_version, languages, files_scanned, files_skipped, finding_count,
                 findings_json, timing_json, error
                 FROM scans ORDER BY started_at DESC LIMIT ?1",
            )?;
            let rows = stmt
                .query_map(params![limit], |row| {
                    Ok(ScanRecord {
                        id: row.get(0)?,
                        status: row.get(1)?,
                        scan_root: row.get(2)?,
                        started_at: row.get(3)?,
                        finished_at: row.get(4)?,
                        duration_secs: row.get(5)?,
                        engine_version: row.get(6)?,
                        languages: row.get(7)?,
                        files_scanned: row.get(8)?,
                        files_skipped: row.get(9)?,
                        finding_count: row.get(10)?,
                        findings_json: row.get(11)?,
                        timing_json: row.get(12)?,
                        error: row.get(13)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
        }

        /// Delete a scan and its associated metrics/logs (FK CASCADE).
        pub fn delete_scan(&self, id: &str) -> NyxResult<usize> {
            let rows = self
                .c()
                .execute("DELETE FROM scans WHERE id = ?1", params![id])?;
            Ok(rows)
        }

        /// Insert scan metrics for a completed scan.
        pub fn insert_scan_metrics(
            &self,
            scan_id: &str,
            metrics: &crate::server::progress::ScanMetricsSnapshot,
        ) -> NyxResult<()> {
            self.c().execute(
                "INSERT OR REPLACE INTO scan_metrics (scan_id, cfg_nodes, call_edges,
                 functions_analyzed, summaries_reused, unresolved_calls)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    scan_id,
                    metrics.cfg_nodes as i64,
                    metrics.call_edges as i64,
                    metrics.functions_analyzed as i64,
                    metrics.summaries_reused as i64,
                    metrics.unresolved_calls as i64,
                ],
            )?;
            Ok(())
        }

        /// Get scan metrics by scan ID.
        pub fn get_scan_metrics(
            &self,
            scan_id: &str,
        ) -> NyxResult<Option<crate::server::progress::ScanMetricsSnapshot>> {
            let result = self
                .c()
                .query_row(
                    "SELECT cfg_nodes, call_edges, functions_analyzed,
                     summaries_reused, unresolved_calls
                     FROM scan_metrics WHERE scan_id = ?1",
                    params![scan_id],
                    |row| {
                        Ok(crate::server::progress::ScanMetricsSnapshot {
                            cfg_nodes: row.get::<_, i64>(0)? as u64,
                            call_edges: row.get::<_, i64>(1)? as u64,
                            functions_analyzed: row.get::<_, i64>(2)? as u64,
                            summaries_reused: row.get::<_, i64>(3)? as u64,
                            unresolved_calls: row.get::<_, i64>(4)? as u64,
                        })
                    },
                )
                .optional()?;
            Ok(result)
        }

        /// Insert scan log entries.
        pub fn insert_scan_logs(
            &self,
            scan_id: &str,
            logs: &[crate::server::scan_log::ScanLogEntry],
        ) -> NyxResult<()> {
            let mut stmt = self.c().prepare(
                "INSERT INTO scan_logs (scan_id, timestamp, level, message, file_path, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for log in logs {
                stmt.execute(params![
                    scan_id,
                    log.timestamp.to_rfc3339(),
                    log.level.to_string(),
                    log.message,
                    log.file_path,
                    log.detail,
                ])?;
            }
            Ok(())
        }

        /// Get scan logs, optionally filtered by level.
        pub fn get_scan_logs(
            &self,
            scan_id: &str,
            level_filter: Option<&str>,
        ) -> NyxResult<Vec<crate::server::scan_log::ScanLogEntry>> {
            let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(level) = level_filter {
                    (
                        "SELECT timestamp, level, message, file_path, detail
                         FROM scan_logs WHERE scan_id = ?1 AND level = ?2
                         ORDER BY id ASC",
                        vec![Box::new(scan_id.to_string()), Box::new(level.to_string())],
                    )
                } else {
                    (
                        "SELECT timestamp, level, message, file_path, detail
                         FROM scan_logs WHERE scan_id = ?1
                         ORDER BY id ASC",
                        vec![Box::new(scan_id.to_string())],
                    )
                };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    let ts_str: String = row.get(0)?;
                    let level_str: String = row.get(1)?;
                    Ok((
                        ts_str,
                        level_str,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })?
                .filter_map(Result::ok)
                .filter_map(|(ts_str, level_str, message, file_path, detail)| {
                    let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                        .ok()?
                        .with_timezone(&chrono::Utc);
                    let level = level_str.parse().ok()?;
                    Some(crate::server::scan_log::ScanLogEntry {
                        timestamp,
                        level,
                        message,
                        file_path,
                        detail,
                    })
                })
                .collect();
            Ok(rows)
        }

        // -------------------------------------------------------------------------
        // Triage state management
        // -------------------------------------------------------------------------

        /// Get the triage state for a single finding fingerprint.
        /// Returns (state, note, updated_at) or None if no triage state exists.
        #[allow(dead_code)]
        pub fn get_triage_state(
            &self,
            fingerprint: &str,
        ) -> NyxResult<Option<(String, String, String)>> {
            let result = self
                .c()
                .query_row(
                    "SELECT state, note, updated_at FROM triage_states WHERE fingerprint = ?1",
                    params![fingerprint],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            Ok(result)
        }

        /// Set the triage state for a single finding. Upserts the state and
        /// appends an audit log entry. Returns the previous state (or "open").
        #[allow(dead_code)]
        pub fn set_triage_state(
            &self,
            fingerprint: &str,
            state: &str,
            note: &str,
            action: &str,
        ) -> NyxResult<String> {
            let now = chrono::Utc::now().to_rfc3339();
            let prev: String = self
                .c()
                .query_row(
                    "SELECT state FROM triage_states WHERE fingerprint = ?1",
                    params![fingerprint],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| "open".to_string());

            self.c().execute(
                "INSERT INTO triage_states (fingerprint, state, note, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE
                 SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at",
                params![fingerprint, state, note, now],
            )?;

            self.c().execute(
                "INSERT INTO triage_audit_log (fingerprint, action, previous_state, new_state, note, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![fingerprint, action, prev, state, note, now],
            )?;

            Ok(prev)
        }

        /// Bulk set triage state. Returns vec of (fingerprint, previous_state).
        pub fn set_triage_states_bulk(
            &self,
            fingerprints: &[String],
            state: &str,
            note: &str,
            action: &str,
        ) -> NyxResult<Vec<(String, String)>> {
            let now = chrono::Utc::now().to_rfc3339();
            let mut results = Vec::with_capacity(fingerprints.len());

            // Read all previous states first
            let mut prev_stmt = self
                .c()
                .prepare("SELECT state FROM triage_states WHERE fingerprint = ?1")?;

            for fp in fingerprints {
                let prev: String = prev_stmt
                    .query_row(params![fp], |row| row.get(0))
                    .optional()?
                    .unwrap_or_else(|| "open".to_string());
                results.push((fp.clone(), prev));
            }
            drop(prev_stmt);

            // Upsert all states
            let mut upsert_stmt = self.c().prepare(
                "INSERT INTO triage_states (fingerprint, state, note, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(fingerprint) DO UPDATE
                 SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at",
            )?;
            for fp in fingerprints {
                upsert_stmt.execute(params![fp, state, note, now])?;
            }
            drop(upsert_stmt);

            // Insert audit log entries
            let mut audit_stmt = self.c().prepare(
                "INSERT INTO triage_audit_log (fingerprint, action, previous_state, new_state, note, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for (fp, prev) in &results {
                audit_stmt.execute(params![fp, action, prev, state, note, now])?;
            }

            Ok(results)
        }

        /// Load all triage states as a map: fingerprint → (state, note, updated_at).
        pub fn get_all_triage_states(
            &self,
        ) -> NyxResult<std::collections::HashMap<String, (String, String, String)>> {
            let mut stmt = self
                .c()
                .prepare("SELECT fingerprint, state, note, updated_at FROM triage_states")?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .filter_map(Result::ok)
                .map(|(fp, state, note, updated)| (fp, (state, note, updated)))
                .collect();
            Ok(rows)
        }

        /// List triage states with optional state filter, paginated.
        /// Returns (entries, total_count).
        pub fn list_triage_states(
            &self,
            state_filter: Option<&str>,
            limit: i64,
            offset: i64,
        ) -> NyxResult<(Vec<(String, String, String, String)>, i64)> {
            let (sql, count_sql, params_vec): (&str, &str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(state) = state_filter {
                    (
                        "SELECT fingerprint, state, note, updated_at FROM triage_states
                         WHERE state = ?1 ORDER BY updated_at DESC LIMIT ?2 OFFSET ?3",
                        "SELECT COUNT(*) FROM triage_states WHERE state = ?1",
                        vec![
                            Box::new(state.to_string()),
                            Box::new(limit),
                            Box::new(offset),
                        ],
                    )
                } else {
                    (
                        "SELECT fingerprint, state, note, updated_at FROM triage_states
                         ORDER BY updated_at DESC LIMIT ?1 OFFSET ?2",
                        "SELECT COUNT(*) FROM triage_states",
                        vec![Box::new(limit), Box::new(offset)],
                    )
                };

            let total: i64 = if let Some(state) = state_filter {
                self.c()
                    .query_row(count_sql, params![state], |row| row.get(0))?
            } else {
                self.c().query_row(count_sql, [], |row| row.get(0))?
            };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();
            Ok((rows, total))
        }

        /// Get the audit log, optionally filtered by fingerprint, paginated.
        /// Returns (entries, total_count).
        pub fn get_audit_log(
            &self,
            fingerprint_filter: Option<&str>,
            limit: i64,
            offset: i64,
        ) -> NyxResult<(Vec<AuditEntry>, i64)> {
            let (sql, count_sql, params_vec): (&str, &str, Vec<Box<dyn rusqlite::types::ToSql>>) =
                if let Some(fp) = fingerprint_filter {
                    (
                        "SELECT id, fingerprint, action, previous_state, new_state, note, timestamp
                         FROM triage_audit_log WHERE fingerprint = ?1
                         ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3",
                        "SELECT COUNT(*) FROM triage_audit_log WHERE fingerprint = ?1",
                        vec![Box::new(fp.to_string()), Box::new(limit), Box::new(offset)],
                    )
                } else {
                    (
                        "SELECT id, fingerprint, action, previous_state, new_state, note, timestamp
                         FROM triage_audit_log ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
                        "SELECT COUNT(*) FROM triage_audit_log",
                        vec![Box::new(limit), Box::new(offset)],
                    )
                };

            let total: i64 = if let Some(fp) = fingerprint_filter {
                self.c()
                    .query_row(count_sql, params![fp], |row| row.get(0))?
            } else {
                self.c().query_row(count_sql, [], |row| row.get(0))?
            };

            let mut stmt = self.c().prepare(sql)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    Ok(AuditEntry {
                        id: row.get(0)?,
                        fingerprint: row.get(1)?,
                        action: row.get(2)?,
                        previous_state: row.get(3)?,
                        new_state: row.get(4)?,
                        note: row.get(5)?,
                        timestamp: row.get(6)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok((rows, total))
        }

        /// Add a pattern-based suppression rule.
        pub fn add_suppression_rule(
            &self,
            suppress_by: &str,
            match_value: &str,
            state: &str,
            note: &str,
        ) -> NyxResult<i64> {
            let now = chrono::Utc::now().to_rfc3339();
            self.c().execute(
                "INSERT OR REPLACE INTO triage_suppression_rules
                 (suppress_by, match_value, state, note, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![suppress_by, match_value, state, note, now],
            )?;
            Ok(self.c().last_insert_rowid())
        }

        /// Get all suppression rules.
        pub fn get_suppression_rules(&self) -> NyxResult<Vec<SuppressionRule>> {
            let mut stmt = self.c().prepare(
                "SELECT id, suppress_by, match_value, state, note, created_at
                 FROM triage_suppression_rules ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(SuppressionRule {
                        id: row.get(0)?,
                        suppress_by: row.get(1)?,
                        match_value: row.get(2)?,
                        state: row.get(3)?,
                        note: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect();
            Ok(rows)
        }

        /// Delete a suppression rule by ID. Returns true if a row was deleted.
        pub fn delete_suppression_rule(&self, id: i64) -> NyxResult<bool> {
            let count = self.c().execute(
                "DELETE FROM triage_suppression_rules WHERE id = ?1",
                params![id],
            )?;
            Ok(count > 0)
        }

        // -------------------------------------------------------------------------
        // Maintenance utilities
        // -------------------------------------------------------------------------
        pub fn clear(&self) -> NyxResult<()> {
            self.c().execute_batch(
                r#"
        PRAGMA foreign_keys = OFF;

        DROP TABLE IF EXISTS scan_logs;
        DROP TABLE IF EXISTS scan_metrics;
        DROP TABLE IF EXISTS scans;
        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS function_summaries;
        DROP TABLE IF EXISTS ssa_function_summaries;
        DROP TABLE IF EXISTS triage_states;
        DROP TABLE IF EXISTS triage_audit_log;
        DROP TABLE IF EXISTS triage_suppression_rules;

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
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
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
                param_container_to_return: vec![],
                param_to_container_store: vec![],
                return_type: None,
                return_abstract: None,
            },
        ),
    ];

    idx.replace_ssa_summaries_for_file(&f, &hash, &summaries)
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(loaded.len(), 2);

    // Check first summary
    let (_, name1, lang1, arity1, ns1, sum1) = loaded
        .iter()
        .find(|(_, n, _, _, _, _)| n == "process")
        .unwrap();
    assert_eq!(name1, "process");
    assert_eq!(lang1, "python");
    assert_eq!(*arity1, 1);
    assert_eq!(ns1, "app.py");
    assert_eq!(sum1.param_to_return, vec![(0, TaintTransform::Identity)]);
    assert!(sum1.param_to_sink.is_empty());

    // Check second summary
    let (_, name2, _, _, _, sum2) = loaded
        .iter()
        .find(|(_, n, _, _, _, _)| n == "sanitize")
        .unwrap();
    assert_eq!(name2, "sanitize");
    assert_eq!(
        sum2.param_to_return,
        vec![(0, TaintTransform::StripBits(Cap::HTML_ESCAPE))]
    );
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
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v1, &sums_v1)
        .unwrap();

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
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash_v2, &sums_v2)
        .unwrap();

    let loaded = idx.load_all_ssa_summaries().unwrap();
    assert_eq!(
        loaded.len(),
        1,
        "old summary should be replaced, not duplicated"
    );
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
            param_container_to_return: vec![],
            param_to_container_store: vec![],
            return_type: None,
            return_abstract: None,
        },
    )];
    idx.replace_ssa_summaries_for_file(&f, &hash, &sums)
        .unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 1);

    idx.clear().unwrap();
    assert_eq!(idx.load_all_ssa_summaries().unwrap().len(), 0);
}
