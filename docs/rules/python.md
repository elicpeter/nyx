# Python Rules

Nyx detects Python vulnerabilities through AST patterns and taint analysis, covering code execution, command injection, deserialization, SQL injection, and weak crypto.

## Taint Labels

Python has partial taint label coverage. Sources, sinks, and sanitizers are defined in `src/labels/python.rs`.

---

## AST Pattern Rules

### Code Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.code_exec.eval` | High | A | `eval()` — dynamic code execution |
| `py.code_exec.exec` | High | A | `exec()` — dynamic code execution |
| `py.code_exec.compile` | Medium | A | `compile()` with exec/eval mode |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.cmdi.os_system` | High | A | `os.system()` — shell command execution |
| `py.cmdi.os_popen` | High | A | `os.popen()` — shell command execution |
| `py.cmdi.subprocess_shell` | High | B | `subprocess.*` with `shell=True` |

### Deserialization

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.deser.pickle_loads` | High | A | `pickle.loads()` / `pickle.load()` — arbitrary object deserialization |
| `py.deser.yaml_load` | High | A | `yaml.load()` without SafeLoader |
| `py.deser.shelve_open` | Medium | A | `shelve.open()` — pickle-backed deserialization |

### SQL Injection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.sqli.execute_format` | Medium | B | `cursor.execute()` with string concatenation |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.crypto.md5` | Low | A | `hashlib.md5()` — weak hash algorithm |
| `py.crypto.sha1` | Low | A | `hashlib.sha1()` — weak hash algorithm |

### Template Injection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `py.xss.jinja_from_string` | Medium | A | `jinja2.Template.from_string()` — template injection |

---

## Examples

### `py.deser.pickle_loads` — Unsafe deserialization

**Vulnerable:**
```python
import pickle
data = pickle.loads(request.body)  # Arbitrary code execution
```

**Safe alternative:**
```python
import json
data = json.loads(request.body)  # JSON is safe
```

### `py.cmdi.subprocess_shell` — Shell execution

**Vulnerable:**
```python
import subprocess
subprocess.call(user_input, shell=True)  # Command injection
```

**Safe alternative:**
```python
import subprocess
import shlex
subprocess.call(shlex.split(user_input), shell=False)
# Or better: use an explicit command list
subprocess.call(["ls", "-la", user_dir])
```

### `py.deser.yaml_load` — Unsafe YAML

**Vulnerable:**
```python
import yaml
config = yaml.load(user_data)  # Can instantiate arbitrary objects
```

**Safe alternative:**
```python
import yaml
config = yaml.safe_load(user_data)  # Only basic Python types
```

### `py.sqli.execute_format` — SQL concatenation

**Vulnerable:**
```python
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
```

**Safe alternative:**
```python
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```
