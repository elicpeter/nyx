# Rust Rules

Nyx detects Rust vulnerabilities through AST patterns (memory safety, code quality) and taint analysis (command injection via `env::var` → `Command::new`).

## Taint Sources

| Function | Capability | Source Kind |
|----------|-----------|-------------|
| `std::env::var`, `env::var` | `all` | EnvironmentConfig |

## Taint Sinks

| Function | Required Capability |
|----------|-------------------|
| `Command::new`, `Command::arg`, `Command::args` | `SHELL_ESCAPE` |
| `Command::status`, `Command::output` | `SHELL_ESCAPE` |
| `fs::read_to_string`, `fs::write`, `fs::read`, `File::open`, `File::create` | `FILE_IO` |

## Taint Sanitizers

| Function | Strips Capability |
|----------|------------------|
| `html_escape::encode_safe`, `sanitize_html` | `HTML_ESCAPE` |
| `shell_escape::unix::escape`, `sanitize_shell` | `SHELL_ESCAPE` |

> **Note:** `fs::read_to_string` was moved from taint sources to sinks to support path traversal detection (`env::var` → `fs::read_to_string`).

---

## AST Pattern Rules

### Memory Safety

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rs.memory.transmute` | High | A | `std::mem::transmute` -- unchecked type reinterpretation |
| `rs.memory.copy_nonoverlapping` | High | A | `ptr::copy_nonoverlapping` -- raw pointer memcpy |
| `rs.memory.get_unchecked` | High | A | `get_unchecked` / `get_unchecked_mut` -- unchecked indexing |
| `rs.memory.mem_zeroed` | High | A | `std::mem::zeroed` -- may be UB for non-POD types |
| `rs.memory.ptr_read` | High | A | `ptr::read` / `ptr::read_volatile` -- raw pointer dereference |
| `rs.memory.narrow_cast` | Low | A | `as u8`/`i8`/`u16`/`i16` -- possible truncation |
| `rs.memory.mem_forget` | Low | A | `std::mem::forget` -- may leak resources |

### Code Quality

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rs.quality.unsafe_block` | Medium | A | `unsafe { }` block -- manual memory safety obligation |
| `rs.quality.unsafe_fn` | Medium | A | `unsafe fn` declaration |
| `rs.quality.unwrap` | Low | A | `.unwrap()` -- panics on `None`/`Err` |
| `rs.quality.expect` | Low | A | `.expect()` -- panics on `None`/`Err` |
| `rs.quality.panic_macro` | Low | A | `panic!()` macro invocation |
| `rs.quality.todo` | Low | A | `todo!()` / `unimplemented!()` placeholder |

---

## Examples

### `rs.memory.transmute`: Unchecked type reinterpretation

**Vulnerable:**
```rust
let x: u32 = 42;
let y: f32 = unsafe { std::mem::transmute(x) };
```

**Safe alternative:**
```rust
let x: u32 = 42;
let y: f32 = f32::from_bits(x);
```

### `rs.quality.unsafe_block`: Unsafe block

**Flagged:**
```rust
unsafe {
    let ptr = &x as *const i32;
    println!("{}", *ptr);
}
```

**Safe alternative:**
```rust
// Use safe abstractions when possible
println!("{}", x);
```

### Taint: `env::var` → `Command::new`

**Vulnerable:**
```rust
let cmd = std::env::var("USER_CMD").unwrap();
Command::new("sh").arg("-c").arg(&cmd).output()?;
```

**Safe alternative:**
```rust
let cmd = std::env::var("USER_CMD").unwrap();
// Validate against allowlist
let allowed = ["ls", "whoami", "date"];
if allowed.contains(&cmd.as_str()) {
    Command::new(&cmd).output()?;
}
```
