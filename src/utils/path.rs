use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

pub const DEFAULT_UI_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoPathError {
    InvalidPath,
    NotFound,
    OutsideRoot,
    NotFile,
    NotDirectory,
    TooLarge,
    InvalidText,
    Io,
}

#[derive(Debug, Clone)]
pub struct ResolvedRepoPath {
    pub root: PathBuf,
    pub canonical: PathBuf,
    pub relative: String,
}

#[derive(Debug, Clone)]
pub struct OpenedTextFile {
    pub resolved: ResolvedRepoPath,
    pub content: String,
}

fn contains_parent_traversal(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn io_error_kind(err: &io::Error) -> RepoPathError {
    match err.kind() {
        io::ErrorKind::NotFound => RepoPathError::NotFound,
        _ => RepoPathError::Io,
    }
}

pub fn canonicalize_root(scan_root: &Path) -> Result<PathBuf, RepoPathError> {
    fs::canonicalize(scan_root).map_err(|err| io_error_kind(&err))
}

pub fn resolve_repo_path(
    scan_root: &Path,
    requested: &str,
) -> Result<ResolvedRepoPath, RepoPathError> {
    if requested.is_empty() || contains_parent_traversal(requested) {
        return Err(RepoPathError::InvalidPath);
    }

    let root = canonicalize_root(scan_root)?;
    let requested_path = Path::new(requested);
    let target = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        root.join(requested_path)
    };

    let canonical = fs::canonicalize(&target).map_err(|err| io_error_kind(&err))?;
    if !canonical.starts_with(&root) {
        return Err(RepoPathError::OutsideRoot);
    }

    let relative = canonical
        .strip_prefix(&root)
        .unwrap_or(Path::new(""))
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_string();

    Ok(ResolvedRepoPath {
        root,
        canonical,
        relative,
    })
}

pub fn resolve_repo_dir(
    scan_root: &Path,
    requested: Option<&str>,
) -> Result<ResolvedRepoPath, RepoPathError> {
    let resolved = match requested {
        Some(path) if !path.is_empty() => resolve_repo_path(scan_root, path)?,
        _ => {
            let root = canonicalize_root(scan_root)?;
            ResolvedRepoPath {
                relative: String::new(),
                canonical: root.clone(),
                root,
            }
        }
    };

    let metadata = fs::metadata(&resolved.canonical).map_err(|err| io_error_kind(&err))?;
    if !metadata.file_type().is_dir() {
        return Err(RepoPathError::NotDirectory);
    }

    Ok(resolved)
}

pub fn open_repo_text_file(
    scan_root: &Path,
    requested: &str,
    max_bytes: u64,
) -> Result<OpenedTextFile, RepoPathError> {
    let resolved = resolve_repo_path(scan_root, requested)?;

    let metadata = fs::metadata(&resolved.canonical).map_err(|err| io_error_kind(&err))?;
    if !metadata.file_type().is_file() {
        return Err(RepoPathError::NotFile);
    }
    if metadata.len() > max_bytes {
        return Err(RepoPathError::TooLarge);
    }
    let file = File::open(&resolved.canonical).map_err(|err| io_error_kind(&err))?;

    let mut reader = BufReader::new(file);
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .map_err(|err| match err.kind() {
            io::ErrorKind::InvalidData => RepoPathError::InvalidText,
            _ => RepoPathError::Io,
        })?;

    Ok(OpenedTextFile { resolved, content })
}

pub fn path_stays_within_root(scan_root: &Path, path: &Path) -> Result<bool, RepoPathError> {
    let root = canonicalize_root(scan_root)?;
    let canonical = fs::canonicalize(path).map_err(|err| io_error_kind(&err))?;
    Ok(canonical.starts_with(&root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolve_repo_path_accepts_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("src").join("main.rs");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "fn main() {}").unwrap();

        let resolved = resolve_repo_path(dir.path(), "src/main.rs").unwrap();
        assert_eq!(resolved.relative, "src/main.rs");
        assert_eq!(resolved.canonical, fs::canonicalize(file).unwrap());
    }

    #[test]
    fn resolve_repo_path_accepts_absolute_paths_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("main.rs");
        fs::write(&file, "fn main() {}").unwrap();

        let resolved = resolve_repo_path(dir.path(), file.to_string_lossy().as_ref()).unwrap();
        assert_eq!(resolved.relative, "main.rs");
    }

    #[test]
    fn resolve_repo_path_rejects_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_repo_path(dir.path(), "../secret").unwrap_err();
        assert_eq!(err, RepoPathError::InvalidPath);
    }

    #[test]
    fn resolve_repo_path_rejects_absolute_paths_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();

        let err =
            resolve_repo_path(dir.path(), outside.path().to_string_lossy().as_ref()).unwrap_err();
        assert_eq!(err, RepoPathError::OutsideRoot);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_repo_path_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, "secret").unwrap();

        let link = dir.path().join("escape.txt");
        symlink(&outside_file, &link).unwrap();

        let err = resolve_repo_path(dir.path(), "escape.txt").unwrap_err();
        assert_eq!(err, RepoPathError::OutsideRoot);
    }

    #[test]
    fn open_repo_text_file_rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let err = open_repo_text_file(dir.path(), ".", DEFAULT_UI_MAX_FILE_BYTES).unwrap_err();
        assert_eq!(err, RepoPathError::NotFile);
    }

    #[cfg(unix)]
    #[test]
    fn open_repo_text_file_rejects_unix_sockets() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("scanner.sock");
        let Ok(_listener) = UnixListener::bind(&socket_path) else {
            return;
        };

        let err =
            open_repo_text_file(dir.path(), "scanner.sock", DEFAULT_UI_MAX_FILE_BYTES).unwrap_err();
        assert_eq!(err, RepoPathError::NotFile);
    }

    #[test]
    fn open_repo_text_file_rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big.txt");
        fs::write(&file, "123456").unwrap();

        let err = open_repo_text_file(dir.path(), "big.txt", 5).unwrap_err();
        assert_eq!(err, RepoPathError::TooLarge);
    }
}
