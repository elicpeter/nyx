# Ruby Rules

Nyx detects Ruby vulnerabilities through AST patterns and taint analysis, covering code execution, command injection, deserialization, reflection, SSRF, and weak crypto.

## Taint Labels

Ruby has moderate taint label coverage. Sources, sinks, and sanitizers are defined in `src/labels/ruby.rs`.

### Sources

| Matcher | Cap |
|---------|-----|
| `ENV`, `gets` | all |
| `params` | all |

> **Note:** Ruby's `params[:cmd]` subscript access is detected via `element_reference` node handling in the CFG. Sinatra/Rails `do...end` blocks are walked as function scopes.

### Sanitizers

| Matcher | Cap |
|---------|-----|
| `CGI.escapeHTML`, `ERB::Util.html_escape` | HTML_ESCAPE |
| `Shellwords.escape`, `Shellwords.shellescape` | SHELL_ESCAPE |

### Sinks

| Matcher | Cap |
|---------|-----|
| `system`, `exec` | SHELL_ESCAPE |
| `eval` | SHELL_ESCAPE |
| `puts`, `print` | HTML_ESCAPE |

---

## AST Pattern Rules

### Code Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.code_exec.eval` | High | A | `Kernel#eval` — dynamic code execution |
| `rb.code_exec.instance_eval` | High | A | `instance_eval` — evaluates string in object context |
| `rb.code_exec.class_eval` | High | A | `class_eval` / `module_eval` — evaluates string in class context |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.cmdi.backtick` | High | A | Backtick shell execution (`` `cmd` ``) |
| `rb.cmdi.system_interp` | High | A | `system`/`exec` call — command execution risk |

### Deserialization

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.deser.yaml_load` | High | A | `YAML.load` — arbitrary object deserialization |
| `rb.deser.marshal_load` | High | A | `Marshal.load` — arbitrary Ruby object deserialization |

### Reflection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.reflection.send_dynamic` | Medium | B | `send()` with non-symbol argument — arbitrary method dispatch |
| `rb.reflection.constantize` | Medium | A | `constantize` / `safe_constantize` — dynamic class resolution |

### SSRF

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.ssrf.open_uri` | Medium | A | `Kernel#open` with HTTP URL — SSRF via open-uri |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `rb.crypto.md5` | Low | A | `Digest::MD5` — weak hash algorithm |

---

## Examples

### `rb.deser.yaml_load` — Unsafe YAML deserialization

**Vulnerable:**
```ruby
data = YAML.load(params[:config])  # Arbitrary object instantiation
```

**Safe alternative:**
```ruby
data = YAML.safe_load(params[:config])  # Only basic Ruby types
```

### `rb.cmdi.backtick` — Backtick shell execution

**Vulnerable:**
```ruby
output = `ls #{user_dir}`  # Command injection via interpolation
```

**Safe alternative:**
```ruby
require 'open3'
output, status = Open3.capture2('ls', user_dir)
```

### `rb.reflection.send_dynamic` — Dynamic method dispatch

**Vulnerable:**
```ruby
obj.send(params[:method], params[:arg])  # Arbitrary method invocation
```

**Safe alternative:**
```ruby
allowed = %w[name email phone]
if allowed.include?(params[:method])
  obj.send(params[:method])
end
```

### `rb.deser.marshal_load` — Marshal deserialization

**Vulnerable:**
```ruby
obj = Marshal.load(request.body.read)
```

**Safe alternative:**
```ruby
data = JSON.parse(request.body.read)
```
