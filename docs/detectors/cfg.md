# CFG Structural Analysis

## Summary

Nyx builds an intra-procedural control-flow graph (CFG) for each function and analyzes structural properties: whether sinks are guarded by sanitizers or validators, whether web handlers check authentication, whether resources are released on all exit paths, and whether error-handling code terminates properly.

These detectors use **dominator analysis** — they check whether a guard node dominates (must execute before) a sink node on the CFG.

## Rule IDs

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `cfg-unguarded-sink` | High/Medium | Sink reachable without a dominating guard or sanitizer |
| `cfg-auth-gap` | High | Web handler reaches privileged sink without auth check |
| `cfg-unreachable-sink` | Medium | Dangerous function in unreachable code |
| `cfg-unreachable-sanitizer` | Low | Sanitizer in unreachable code |
| `cfg-unreachable-source` | Low | Source in unreachable code |
| `cfg-error-fallthrough` | High/Medium | Error check doesn't terminate; dangerous code follows |
| `cfg-resource-leak` | Medium | Resource acquired but not released on all exit paths |
| `cfg-lock-not-released` | Medium | Lock acquired but not released on all exit paths |

## What It Detects

### Unguarded sinks (`cfg-unguarded-sink`)
A sink call (e.g. `system()`, `eval()`, `Command::new()`) is reachable from the function entry without passing through a guard or sanitizer that matches the sink's capability.

### Auth gaps (`cfg-auth-gap`)
A function identified as a web handler (by parameter naming conventions like `req`, `res`, `ctx`, `request`) reaches a privileged sink (shell execution, file I/O) without a prior call to an authentication function (`is_authenticated`, `require_auth`, `check_permission`, etc.).

### Unreachable security code (`cfg-unreachable-*`)
Sinks, sanitizers, or sources in dead code branches. This often indicates a refactoring error where security-critical code was accidentally made unreachable.

### Error fallthrough (`cfg-error-fallthrough`)
An error check (null check, error return check) does not terminate the function or loop back. Execution continues to a dangerous operation on the error path.

### Resource leaks (`cfg-resource-leak`, `cfg-lock-not-released`)
A resource acquisition call (e.g. `File::open`, `fopen`, `socket`, `Lock`) is not matched by a release call (e.g. `close`, `fclose`, `unlock`) on all exit paths from the function.

## What It Cannot Detect

- **Inter-procedural guards**: If authentication is checked in a middleware function that calls this handler, the CFG detector cannot see it. It only analyzes one function at a time.
- **Dynamic dispatch**: Virtual method calls, function pointers, and closures are opaque to the CFG.
- **Complex guard patterns**: Only recognized guard function names are checked. Custom validation logic (e.g. `if password == expected`) is not recognized as a guard.
- **Correct sanitization**: The detector checks that *some* guard dominates the sink, not that the guard is *correct*. A guard that always passes would suppress the finding.
- **Cross-function resource flows**: If a file handle is opened in one function and closed in another, the detector will report a leak in the first function.

## Common False Positives

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Framework-level auth middleware | Handler doesn't call auth directly | Document as expected; suppress with severity filter |
| Resource closed via RAII/defer | Implicit cleanup not visible to CFG | Currently not detected; known limitation |
| Custom guard function name | Function not in the recognized guard list | Add the function name as a sanitizer in config |
| Test handlers | Intentionally skip auth in tests | Default non-prod downgrade reduces severity; or exclude test dirs |

## Common False Negatives

| Scenario | Why it's missed |
|----------|----------------|
| Auth in called function | Cross-function guards not tracked |
| Guard via type system | Type-level guarantees (e.g. Rust's `AuthenticatedUser` wrapper) not analyzed |
| Resource closed in finally/defer | Some cleanup patterns not recognized |

## Confidence Signals

| Signal | Meaning |
|--------|---------|
| **Evidence lists guard nodes** | Shows which guards were checked and found missing |
| **Sink has high capability** | Shell execution or file I/O sinks are higher risk |
| **Handler detection matched** | Web handler identification is based on conventional parameter names |

## Tuning and Noise Controls

### Add custom guards/sanitizers

```toml
[[analysis.languages.python.rules]]
matchers = ["validate_request", "check_csrf"]
kind = "sanitizer"
cap = "all"
```

### Add auth rules

Auth checks are recognized by function name. If your codebase uses non-standard names:

```toml
[[analysis.languages.javascript.rules]]
matchers = ["ensureLoggedIn", "requirePermission"]
kind = "sanitizer"
cap = "all"
```

### Filter results

```bash
# Skip low-severity unreachable findings
nyx scan . --severity ">=MEDIUM"
```

### Disable CFG analysis

```bash
nyx scan . --mode ast   # AST patterns only
```

## Examples

### Unguarded sink

```go
func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", cmd).Run()  // cfg-unguarded-sink: no guard dominates
}
```

### Auth gap

```javascript
app.get('/admin/delete', (req, res) => {
    // No is_authenticated() call
    db.execute("DELETE FROM users WHERE id = " + req.params.id);
    // cfg-auth-gap: web handler reaches privileged sink without auth
});
```

### Resource leak

```c
void process() {
    FILE *f = fopen("data.txt", "r");  // acquire
    if (error) {
        return;  // cfg-resource-leak: f not closed on this path
    }
    fclose(f);
}
```

## Guard Rules

Nyx recognizes these function name patterns as guards:

| Pattern | Applies to |
|---------|-----------|
| `validate*`, `sanitize*` | All sinks |
| `check_*`, `verify_*`, `assert_*` | All sinks |
| `shell_escape` | Shell execution sinks |
| `html_escape` | HTML/XSS sinks |
| `url_encode` | URL sinks |
| `which` | Shell execution (binary lookup) |

### Auth rules

| Pattern | Category |
|---------|----------|
| `is_authenticated`, `require_auth`, `check_permission` | Common |
| `authorize`, `authenticate`, `require_login` | Common |
| `check_auth`, `verify_token`, `validate_token` | Common |
| `middleware.auth`, `auth.required` | Go |
| `isAuthenticated`, `checkPermission`, `hasAuthority`, `hasRole` | Java |
