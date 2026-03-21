# Go Rules

Nyx detects Go vulnerabilities through AST patterns and taint analysis, covering command execution, unsafe pointer usage, TLS misconfiguration, weak crypto, SQL injection, hardcoded secrets, and deserialization.

## Taint Labels

Go has moderate taint label coverage. Sources, sinks, and sanitizers are defined in `src/labels/go.rs`.

### Sources

| Matcher | Cap |
|---------|-----|
| `os.Getenv` | all |
| `http.Request`, `r.FormValue`, `r.URL`, `r.Body`, `r.Header` | all |
| `r.URL.Query`, `r.URL.Query.Get`, `Request.FormValue`, `Request.URL` | all |

### Sanitizers

| Matcher | Cap |
|---------|-----|
| `html.EscapeString`, `template.HTMLEscapeString` | HTML_ESCAPE |
| `url.QueryEscape`, `url.PathEscape` | URL_ENCODE |
| `filepath.Clean`, `filepath.Base` | FILE_IO |

### Sinks

| Matcher | Cap |
|---------|-----|
| `exec.Command` | SHELL_ESCAPE |
| `db.Query`, `db.Exec`, `db.QueryRow`, `db.Prepare` | SQL_QUERY |
| `fmt.Fprintf`, `fmt.Sprintf`, `fmt.Printf` | FMT_STRING |
| `os.Open`, `os.OpenFile`, `os.Create`, `ioutil.ReadFile`, `os.ReadFile` | FILE_IO |
| `template.HTML`, `template.JS`, `template.CSS` | HTML_ESCAPE |
| `http.Get`, `http.Post`, `http.NewRequest`, `net.Dial`, `net.DialTimeout` | SSRF |
| `md5.New`, `md5.Sum`, `sha1.New`, `sha1.Sum`, `des.NewCipher`, `rc4.NewCipher` | CRYPTO |

> **Note:** Chained calls like `r.URL.Query().Get("host")` are normalized by stripping internal `()` segments before matching, so `r.URL.Query.Get` matches the source rule.

---

## AST Pattern Rules

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.cmdi.exec_command` | High | A | `exec.Command()` -- arbitrary process execution |

### Memory Safety

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.memory.unsafe_pointer` | Medium | A | `unsafe.Pointer` -- bypasses Go type system |

### Insecure Transport

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.transport.insecure_skip_verify` | High | A | `InsecureSkipVerify: true` -- disables TLS certificate validation |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.crypto.md5` | Low | A | `md5.New()` / `md5.Sum()` -- weak hash algorithm |
| `go.crypto.sha1` | Low | A | `sha1.New()` / `sha1.Sum()` -- weak hash algorithm |

### SQL Injection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.sqli.query_concat` | Medium | B | `db.Query`/`Exec`/`QueryRow` with concatenated string |

### Secrets

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.secrets.hardcoded_key` | Medium | A | Variable with secret-like name assigned a string literal |

### Deserialization

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `go.deser.gob_decode` | Medium | A | `gob.NewDecoder` -- Go binary deserialization |

---

## Examples

### `go.transport.insecure_skip_verify`: TLS misconfiguration

**Vulnerable:**
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,  // Disables certificate verification
    },
}
```

**Safe alternative:**
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        // Use proper CA certificates
        RootCAs: certPool,
    },
}
```

### `go.sqli.query_concat`: SQL concatenation

**Vulnerable:**
```go
rows, err := db.Query("SELECT * FROM users WHERE id=" + userID)
```

**Safe alternative:**
```go
rows, err := db.Query("SELECT * FROM users WHERE id=$1", userID)
```

### `go.secrets.hardcoded_key`: Hardcoded secret

**Flagged:**
```go
apiKey := "sk-1234567890abcdef"
password := "hunter2"
```

**Safe alternative:**
```go
apiKey := os.Getenv("API_KEY")
password := os.Getenv("DB_PASSWORD")
```

### `go.cmdi.exec_command`: Command execution

**Vulnerable:**
```go
cmd := exec.Command("sh", "-c", userInput)
cmd.Run()
```

**Safe alternative:**
```go
// Use explicit command and arguments, not shell
cmd := exec.Command("ls", "-la", safeDir)
cmd.Run()
```
