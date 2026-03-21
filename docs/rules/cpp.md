# C++ Rules

C++ rules inherit C banned-function concerns and add C++-specific patterns like dangerous casts.

## Taint Labels

C++ shares taint labels with C. See [C Rules](c.md) for the full source/sink/sanitizer listing.

---

## AST Pattern Rules

### Memory Safety

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `cpp.memory.gets` | High | A | `gets()` -- no bounds checking, always exploitable |
| `cpp.memory.strcpy` | High | A | `strcpy()` -- no bounds checking on destination |
| `cpp.memory.strcat` | High | A | `strcat()` -- no bounds checking on destination |
| `cpp.memory.sprintf` | High | A | `sprintf()` -- no length limit on output |
| `cpp.memory.reinterpret_cast` | Medium | A | `reinterpret_cast` -- type-punning cast |
| `cpp.memory.const_cast` | Medium | A | `const_cast` -- removes const/volatile qualifier |
| `cpp.memory.printf_no_fmt` | High | B | `printf(var)` -- format-string vulnerability |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `cpp.cmdi.system` | High | A | `system()` -- shell command execution |
| `cpp.cmdi.popen` | High | A | `popen()` -- shell command execution |

---

## Examples

### `cpp.memory.reinterpret_cast`: Type-punning cast

**Flagged:**
```cpp
int x = 42;
float* fp = reinterpret_cast<float*>(&x);  // Type-punning, may violate strict aliasing
```

**Safe alternative:**
```cpp
int x = 42;
float f;
std::memcpy(&f, &x, sizeof(f));  // Well-defined type punning
```

### `cpp.memory.const_cast`: Removing const

**Flagged:**
```cpp
void process(const std::string& s) {
    char* p = const_cast<char*>(s.c_str());  // Removes const
    p[0] = 'X';  // Undefined behavior
}
```

**Safe alternative:**
```cpp
void process(std::string s) {  // Take by value
    s[0] = 'X';
}
```
