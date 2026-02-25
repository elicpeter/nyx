# State Model Analysis

## Summary

Nyx's state model analysis tracks **resource lifecycle** and **authentication state** through a function using monotone dataflow over bounded lattices. It detects use-after-close bugs, double-close bugs, resource leaks, and unauthenticated access to privileged operations.

State analysis is **opt-in** — enable it with `scanner.enable_state_analysis = true` in config. It requires `mode = "full"` or `mode = "cfg"`.

## Rule IDs

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `state-use-after-close` | High | Variable used after being closed/released |
| `state-double-close` | Medium | Resource closed twice |
| `state-resource-leak` | Medium | Resource opened but never closed (definite) |
| `state-resource-leak-possible` | Low | Resource may not be closed on all paths |
| `state-unauthed-access` | High | Privileged operation reached without authentication |

## What It Detects

### Use-after-close (`state-use-after-close`)

A resource transitions to the CLOSED state (via `close()`, `fclose()`, `disconnect()`, etc.), then a use operation (`read`, `write`, `send`, `recv`, `query`, etc.) is performed on it.

```c
FILE *f = fopen("data.txt", "r");
fclose(f);
fread(buf, 1, 100, f);  // state-use-after-close
```

### Double-close (`state-double-close`)

A resource is closed twice. This can cause crashes or undefined behavior.

```python
f = open("data.txt")
f.close()
f.close()  # state-double-close
```

### Resource leak (`state-resource-leak`)

A resource is opened but never closed on any path through the function. This is a definite leak.

```java
FileInputStream fis = new FileInputStream("data.txt");
process(fis);
// function exits without fis.close() — state-resource-leak
```

### Possible resource leak (`state-resource-leak-possible`)

A resource is closed on some paths but not others.

```go
f, err := os.Open("data.txt")
if err != nil {
    return  // f not closed here
}
f.Close()  // closed here
// state-resource-leak-possible on the error path
```

### Unauthenticated access (`state-unauthed-access`)

A function identified as a web handler reaches a privileged sink (shell execution, file I/O) without any authentication check on the path.

```javascript
app.post('/admin/exec', (req, res) => {
    // No auth check
    exec(req.body.command);  // state-unauthed-access
});
```

## What It Cannot Detect

- **Cross-function resource management**: Resources opened in one function and closed in another are not tracked. This is the most common source of false positives for leak detection.
- **RAII / defer / try-with-resources**: Implicit cleanup via language-level constructs (Rust's `Drop`, Go's `defer`, Java's try-with-resources, Python's `with`) is not recognized. These patterns will produce false-positive leak findings.
- **Dynamic dispatch**: If `close()` is called through a trait object or interface, it may not be recognized.
- **Authentication via type system**: Rust's type-state pattern (e.g. `AuthenticatedRequest<T>`) is not recognized as an auth check.
- **Complex authorization logic**: Only recognized function name patterns are checked.

## Common False Positives

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| RAII / Drop / defer cleanup | Implicit cleanup not visible | Known limitation; filter by severity |
| Resource returned to caller | Ownership transferred, not leaked | Known limitation |
| Framework-managed resources | Web framework manages connection lifecycle | Exclude framework-generated handlers |
| Try-with-resources (Java) | Language construct not parsed | Known limitation |
| Context manager (Python `with`) | Block construct not tracked | Known limitation |

## Common False Negatives

| Scenario | Why it's missed |
|----------|----------------|
| Resource closed in helper function | Cross-function tracking not implemented |
| Auth in middleware | Auth check happens before handler is called |
| Double-close via aliased reference | Alias analysis not performed |

## Confidence Signals

| Signal | Meaning |
|--------|---------|
| **Definite leak (state-resource-leak)** | Resource is never closed on any path — high confidence |
| **Use-after-close** | Read/write operation after explicit close — high confidence |
| **Web handler detected** | Entry point matched by parameter naming convention |
| **Possible leak (state-resource-leak-possible)** | Resource closed on some but not all paths — lower confidence |

## Tuning and Noise Controls

### Enable state analysis

```toml
[scanner]
enable_state_analysis = true
```

### Severity filtering

```bash
# Skip possible-leak findings (Low severity)
nyx scan . --severity ">=MEDIUM"
```

### Exclude test files

```toml
[scanner]
excluded_directories = ["tests", "test", "spec"]
```

## Resource Pairs

The state engine recognizes these acquire/release pairs per language:

### C/C++
| Acquire | Release | Resource |
|---------|---------|----------|
| `fopen` | `fclose` | File handle |
| `open` | `close` | File descriptor |
| `socket` | `close` | Socket |
| `malloc`, `calloc`, `realloc` | `free` | Heap memory |
| `pthread_mutex_lock` | `pthread_mutex_unlock` | Mutex |

### Rust
| Acquire | Release | Resource |
|---------|---------|----------|
| `File::open`, `File::create` | `drop`, `close` | File handle |
| `TcpStream::connect` | `shutdown` | TCP connection |
| `lock`, `read`, `write` (on Mutex/RwLock) | `drop` | Lock guard |

### Java
| Acquire | Release | Resource |
|---------|---------|----------|
| `new FileInputStream` | `close` | File stream |
| `getConnection` | `close` | DB connection |
| `new Socket` | `close` | Socket |

### Go, Python, JavaScript, Ruby, PHP
Similar patterns with language-specific function names.

## Use Patterns (Trigger use-after-close)

The following operations on a closed resource trigger `state-use-after-close`:

```
read, write, send, recv, fread, fwrite, fgets, fputs, fprintf, fscanf,
fflush, fseek, ftell, rewind, feof, ferror, fgetc, fputc, getc, putc,
ungetc, query, execute, fetch, sendto, recvfrom, ioctl, fcntl
```

## Technical Details

### Resource Lifecycle Lattice

```
UNINIT → OPEN → CLOSED
              → MOVED
```

States are tracked as bitflags, allowing the lattice to represent uncertainty (e.g. OPEN|CLOSED means the resource is open on some paths and closed on others).

### Auth Level Lattice

```
Unauthed < Authed < Admin
```

Join semantics: take the minimum (conservative). If any path is unauthenticated, the result is unauthenticated.
