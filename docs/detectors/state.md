# State model analysis

Tracks resource lifecycle and authentication state through a function. Detects use-after-close, double-close, leaks, and unauthenticated access to privileged operations.

State analysis is on by default. Disable with `scanner.enable_state_analysis = false`. It runs in `--mode full` and `--mode taint`; AST-only mode skips it.

## Rule IDs

| Rule ID | Severity |
|---|---|
| `state-use-after-close` | High |
| `state-double-close` | Medium |
| `state-resource-leak` | Medium |
| `state-resource-leak-possible` | Low |
| `state-unauthed-access` | High |

## What it detects

**`state-use-after-close`**: Resource transitions to CLOSED (via `close`, `fclose`, `disconnect`, …), then a use operation happens on it.

```c
FILE *f = fopen("data.txt", "r");
fclose(f);
fread(buf, 1, 100, f);  // state-use-after-close
```

**`state-double-close`**: Resource closed twice. Crashes or undefined behaviour on most runtimes.

**`state-resource-leak`**: Resource opened but never closed on any path through the function. Definite leak.

**`state-resource-leak-possible`**: Resource closed on some paths but not others. Lower confidence; often an early-return error path.

**`state-unauthed-access`**: A function recognised as a web handler reaches a privileged sink without an auth call on the path.

A function counts as a web handler if its name starts with `handle_`, `route_`, or `api_` (sufficient on its own), or starts with `serve_`/`process_` and the file uses web-shaped parameter names (`request`, `req`, `ctx`, `res`, `response`, `w`, `writer`, language-dependent). `main` is excluded.

## Managed-resource suppression

Several language-specific cleanup patterns suppress leak findings:

| Pattern | Languages | Effect |
|---|---|---|
| RAII / Drop | Rust | All leak findings suppressed except `alloc`/`dealloc` |
| Smart pointers | C++ | `make_unique`/`make_shared` treated as managed; raw `new`/`malloc` still tracked |
| `defer` | Go | `defer f.Close()` suppresses leak at exit |
| `with` context manager | Python | `with open(f) as f:` suppresses leak for the bound name |
| try-with-resources | Java | TWR-bound resources suppressed |

## What it can't detect

- **Cross-function resource ownership.** Open in one function, close in another, leak gets reported in the opener. The most common FP source for leak detection.
- **Factory / builder functions** that return a resource for the caller to manage.
- **Variable shadowing across scopes.** Same name in inner and outer scope shares one symbol; an inner close masks an outer leak.
- **Resources stored in collections.** Handles in arrays / maps / channels and cleaned up via iteration are not tracked.
- **Dynamic dispatch.** Close called via trait object or interface may not be recognised.
- **Type-state authentication.** `AuthenticatedRequest<T>` and similar Rust patterns are not recognised as auth.

## Common false positives

| Scenario | Why | Mitigation |
|---|---|---|
| Factory returns a resource | Caller owns it | Known limitation |
| Framework-managed handles | Connection pool, request scope | Exclude framework code or downgrade |
| Variable name shadowing | Same name reused | Known limitation |

## Per-language detection

| Language | Leak | Double-close | Use-after-close | Notes |
|---|---|---|---|---|
| C | yes | yes | yes | `fopen`/`fclose`, `malloc`/`free`, `pthread_mutex_*` |
| C++ | yes | yes | yes | C pairs plus `new`/`delete`; smart pointers suppressed |
| Python | yes | yes | yes | `with` suppressed; `open`, `socket`, `connect` |
| Go | yes | yes | yes | `defer` suppressed; `os.Open` / `.Close` |
| Rust | unsafe only | n/a | n/a | RAII suppresses everything except `alloc`/`dealloc` |
| JavaScript | yes | yes | partial | `fs.openSync`/`closeSync` |
| TypeScript | yes | yes | partial | Same as JS |
| PHP | yes | yes | partial | `fopen`/`fclose`, `curl_init`/`curl_close`, `mysqli_*` |
| Ruby | partial | partial | partial | `File.open`/`close`, `TCPSocket` |
| Java | limited | limited | limited | Constructor-callee matching is incomplete |

## Tuning

```bash
nyx scan . --severity ">=MEDIUM"   # Skip "possible" leaks (Low)
```

```toml
[scanner]
enable_state_analysis = true        # default
excluded_directories  = ["tests", "test", "spec"]
```

## Recognised pairs

The state engine ships these acquire/release pairs. Custom pairs are not yet configurable; file an issue if you need one.

**C / C++**

| Acquire | Release |
|---|---|
| `fopen` | `fclose` |
| `open` | `close` |
| `socket` | `close` |
| `malloc`, `calloc`, `realloc` | `free` |
| `pthread_mutex_lock` | `pthread_mutex_unlock` |
| `new`, `new[]` *(C++)* | `delete`, `delete[]` |

**Rust**

| Acquire | Release |
|---|---|
| `File::open`, `File::create` | `drop`, `close` |
| `TcpStream::connect` | `shutdown` |
| `lock`, `read`, `write` (Mutex/RwLock) | `drop` |

**Java**

| Acquire | Release |
|---|---|
| `new FileInputStream` (and friends) | `close` |
| `getConnection` | `close` |
| `new Socket` | `close` |

Go, Python, JavaScript, Ruby, PHP follow language-idiomatic equivalents.

## Use-after-close triggers

These operations on a closed resource fire `state-use-after-close`:

```
read, write, send, recv, fread, fwrite, fgets, fputs, fprintf, fscanf,
fflush, fseek, ftell, rewind, feof, ferror, fgetc, fputc, getc, putc,
ungetc, query, execute, fetch, sendto, recvfrom, ioctl, fcntl,
strcpy, strncpy, strcat, strncat, memcpy, memmove, memset, memcmp,
strcmp, strncmp, strlen, sprintf, snprintf
```
