# C Rules

Nyx detects C vulnerabilities through AST patterns (banned functions, format strings) and taint analysis (user input → shell execution, buffer overflow sinks).

## Taint Sources

| Function | Capability | Source Kind |
|----------|-----------|-------------|
| `getenv` | `all` | EnvironmentConfig |
| `fgets`, `scanf`, `fscanf`, `gets`, `read` | `all` | UserInput |

## Taint Sinks

| Function | Required Capability |
|----------|-------------------|
| `system`, `popen`, `exec*` family | `SHELL_ESCAPE` |
| `sprintf`, `strcpy`, `strcat` | `HTML_ESCAPE` |
| `printf`, `fprintf` | `FMT_STRING` |
| `fopen`, `open` | `FILE_IO` |

---

## AST Pattern Rules

### Memory Safety (Banned Functions)

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `c.memory.gets` | High | A | `gets()` -- no bounds checking, always exploitable |
| `c.memory.strcpy` | High | A | `strcpy()` -- no bounds checking on destination buffer |
| `c.memory.strcat` | High | A | `strcat()` -- no bounds checking on destination buffer |
| `c.memory.sprintf` | High | A | `sprintf()` -- no length limit on output buffer |
| `c.memory.scanf_percent_s` | High | A | `scanf("%s")` -- unbounded string read |
| `c.memory.printf_no_fmt` | High | B | `printf(var)` -- format-string vulnerability (non-literal first arg) |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `c.cmdi.system` | High | A | `system()` -- shell command execution |
| `c.cmdi.popen` | Medium | A | `popen()` -- shell command execution with pipe |

---

## Examples

### `c.memory.gets`: Banned function

**Vulnerable:**
```c
char buf[64];
gets(buf);  // No bounds checking -- buffer overflow
```

**Safe alternative:**
```c
char buf[64];
fgets(buf, sizeof(buf), stdin);
```

### `c.memory.printf_no_fmt`: Format string

**Vulnerable:**
```c
char *user_input = get_input();
printf(user_input);  // Format string vulnerability
```

**Safe alternative:**
```c
char *user_input = get_input();
printf("%s", user_input);
```

### `c.cmdi.system`: Shell execution

**Vulnerable:**
```c
char cmd[256];
snprintf(cmd, sizeof(cmd), "ls %s", user_dir);
system(cmd);  // Command injection if user_dir contains shell metacharacters
```

**Safe alternative:**
```c
// Use execvp with explicit argument array
char *args[] = {"ls", user_dir, NULL};
execvp("ls", args);
```
