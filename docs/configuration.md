# Configuration

Nyx uses TOML configuration files. A default config is auto-generated on first run.

## File Locations

| Platform | Directory |
|----------|-----------|
| Linux | `~/.config/nyx/` |
| macOS | `~/Library/Application Support/nyx/` |
| Windows | `%APPDATA%\elicpeter\nyx\config\` |

Run `nyx config path` to see the exact directory on your system.

## File Precedence

1. **`nyx.conf`** — Default config (auto-created from built-in template on first run)
2. **`nyx.local`** — User overrides (loaded on top of defaults)

Both files are optional. CLI flags take precedence over both.

## Merge Strategy

| Type | Behavior |
|------|----------|
| Scalars (`mode`, `min_severity`, booleans) | User value wins |
| Arrays (`excluded_extensions`, `excluded_directories`) | Union + deduplicate |
| Analysis rules | Per-language union with deduplication |

Example:
```toml
# nyx.conf (default):
excluded_extensions = ["jpg", "png", "exe"]

# nyx.local (user):
excluded_extensions = ["foo", "jpg"]

# Effective result:
# ["exe", "foo", "jpg", "png"]  — sorted, deduped union
```

---

## Full Schema

### `[scanner]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `"full"` \| `"ast"` \| `"cfg"` | `"full"` | Analysis mode |
| `min_severity` | `"Low"` \| `"Medium"` \| `"High"` | `"Low"` | Minimum severity to report |
| `max_file_size_mb` | int \| null | null | Max file size in MiB; null = unlimited |
| `excluded_extensions` | [string] | `["jpg", "png", "gif", "mp4", ...]` | File extensions to skip |
| `excluded_directories` | [string] | `["node_modules", ".git", "target", ...]` | Directories to skip |
| `excluded_files` | [string] | `[]` | Specific files to skip |
| `read_global_ignore` | bool | `false` | Honor global ignore file |
| `read_vcsignore` | bool | `true` | Honor `.gitignore` / `.hgignore` |
| `require_git_to_read_vcsignore` | bool | `true` | Require `.git` dir to apply gitignore |
| `one_file_system` | bool | `false` | Don't cross filesystem boundaries |
| `follow_symlinks` | bool | `false` | Follow symbolic links |
| `scan_hidden_files` | bool | `false` | Scan dot-files |
| `include_nonprod` | bool | `false` | Keep original severity for test/vendor paths |
| `enable_state_analysis` | bool | `false` | Enable resource lifecycle + auth state analysis. Detects use-after-close, double-close, resource leaks (per-function scope), and unauthenticated access. Requires `mode = "full"` or `mode = "cfg"`. |

### `[database]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `""` | Custom SQLite DB path; empty = platform default |

### `[output]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_format` | `"console"` \| `"json"` \| `"sarif"` | `"console"` | Default output format |
| `quiet` | bool | `false` | Suppress status messages |
| `max_results` | int \| null | null | Cap number of findings; null = unlimited |
| `attack_surface_ranking` | bool | `true` | Enable attack-surface ranking |
| `min_score` | int \| null | null | Minimum rank score to include; null = no minimum |

### `[performance]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `worker_threads` | int \| null | null | Worker thread count; null/0 = auto-detect |
| `batch_size` | int | `100` | Files per index batch |
| `channel_multiplier` | int | `4` | Channel capacity = threads x multiplier |
| `rayon_thread_stack_size` | int | `8388608` | Rayon thread stack size in bytes (8 MiB) |
| `prune` | bool | `false` | Stop traversing into matching directories |

### `[analysis.languages.<slug>]`

Per-language custom rules. `<slug>` is one of: `rust`, `javascript`, `typescript`, `python`, `go`, `java`, `c`, `cpp`, `php`, `ruby`.

| Field | Type | Description |
|-------|------|-------------|
| `rules` | array of rule objects | Custom label rules |
| `terminators` | [string] | Functions that terminate execution |
| `event_handlers` | [string] | Event handler function names |

**Rule object**:

```toml
[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml"]
kind = "sanitizer"        # "source" | "sanitizer" | "sink"
cap = "html_escape"       # "env_var" | "html_escape" | "shell_escape" |
                          # "url_encode" | "json_parse" | "file_io" | "all"
```

---

## Example Configurations

### Minimal override (`nyx.local`)

```toml
[scanner]
min_severity = "Medium"

[output]
default_format = "json"
max_results = 100
```

### CI-optimized

```toml
[scanner]
mode = "full"
min_severity = "Medium"
excluded_directories = ["node_modules", ".git", "target", "vendor", "dist"]

[output]
quiet = true
default_format = "sarif"

[performance]
worker_threads = 4
```

### Custom rules for a Node.js project

```toml
[analysis.languages.javascript]
terminators = ["process.exit", "abort"]
event_handlers = ["addEventListener"]

[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml", "sanitizeInput"]
kind = "sanitizer"
cap = "html_escape"

[[analysis.languages.javascript.rules]]
matchers = ["dangerouslySetInnerHTML"]
kind = "sink"
cap = "html_escape"

[[analysis.languages.javascript.rules]]
matchers = ["getRequestBody", "readUserInput"]
kind = "source"
cap = "all"
```

### Adding rules via CLI

```bash
# Add a sanitizer
nyx config add-rule --lang javascript --matcher escapeHtml --kind sanitizer --cap html_escape

# Add a terminator
nyx config add-terminator --lang javascript --name process.exit

# Verify
nyx config show
```
