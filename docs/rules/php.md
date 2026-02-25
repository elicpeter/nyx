# PHP Rules

Nyx detects PHP vulnerabilities through AST patterns and taint analysis, covering code execution, command injection, deserialization, SQL injection, path traversal, and weak crypto.

## Taint Labels

PHP has minimal taint label coverage. Sources, sinks, and sanitizers are defined in `src/labels/php.rs`.

---

## AST Pattern Rules

### Code Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.code_exec.eval` | High | A | `eval()` — dynamic code execution |
| `php.code_exec.create_function` | High | A | `create_function()` — deprecated eval-like constructor |
| `php.code_exec.preg_replace_e` | High | A | `preg_replace` with `/e` modifier — code execution via regex |
| `php.code_exec.assert_string` | High | A | `assert()` with string argument — evaluates PHP code |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.cmdi.system` | High | A | `system`/`shell_exec`/`exec`/`passthru`/`proc_open`/`popen` |

### Deserialization

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.deser.unserialize` | High | A | `unserialize()` — PHP object injection |

### SQL Injection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.sqli.query_concat` | Medium | B | `mysql_query`/`mysqli_query` with concatenated SQL |

### Path Traversal

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.path.include_variable` | High | B | `include`/`require` with variable path — file inclusion |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `php.crypto.md5` | Low | A | `md5()` — weak hash function |
| `php.crypto.sha1` | Low | A | `sha1()` — weak hash function |
| `php.crypto.rand` | Low | A | `rand()`/`mt_rand()` — not cryptographically secure |

---

## Examples

### `php.code_exec.eval` — Dynamic code execution

**Vulnerable:**
```php
eval($_GET['code']);
```

**Safe alternative:**
```php
// Never use eval with user input
// Use a template engine or allowlisted operations
```

### `php.deser.unserialize` — Object injection

**Vulnerable:**
```php
$obj = unserialize($_COOKIE['data']);
```

**Safe alternative:**
```php
$data = json_decode($_COOKIE['data'], true);
```

### `php.path.include_variable` — File inclusion

**Vulnerable:**
```php
include($_GET['page']);  // Local/remote file inclusion
```

**Safe alternative:**
```php
$allowed = ['home', 'about', 'contact'];
$page = in_array($_GET['page'], $allowed) ? $_GET['page'] : 'home';
include("pages/{$page}.php");
```

### `php.sqli.query_concat` — SQL concatenation

**Vulnerable:**
```php
mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id']);
```

**Safe alternative:**
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE id=?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```
