# Java Rules

Nyx detects Java vulnerabilities through AST patterns and taint analysis, covering deserialization, command execution, reflection, SQL injection, weak crypto, and XSS.

## Taint Labels

Java has moderate taint label coverage. Sources, sinks, and sanitizers are defined in `src/labels/java.rs`.

### Sources

| Matcher | Cap |
|---------|-----|
| `System.getenv` | all |
| `getParameter`, `getInputStream`, `getHeader`, `getCookies`, `getReader`, `getQueryString`, `getPathInfo` | all |
| `readObject`, `readLine` | all |

### Sanitizers

| Matcher | Cap |
|---------|-----|
| `HtmlUtils.htmlEscape`, `StringEscapeUtils.escapeHtml4` | HTML_ESCAPE |

### Sinks

| Matcher | Cap |
|---------|-----|
| `Runtime.exec`, `ProcessBuilder` | SHELL_ESCAPE |
| `executeQuery`, `executeUpdate`, `prepareStatement` | SHELL_ESCAPE |
| `Class.forName` | SHELL_ESCAPE |
| `println`, `print`, `write` | HTML_ESCAPE |

---

## AST Pattern Rules

### Deserialization

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.deser.readobject` | High | A | `ObjectInputStream.readObject()` -- unsafe deserialization |

### Command Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.cmdi.runtime_exec` | High | A | `Runtime.getRuntime().exec()` -- shell command execution |

### Reflection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.reflection.class_forname` | Medium | A | `Class.forName()` -- dynamic class loading |
| `java.reflection.method_invoke` | Medium | A | `Method.invoke()` -- reflective method invocation |

### SQL Injection

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.sqli.execute_concat` | Medium | B | SQL `execute*()` with concatenated string argument |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.crypto.insecure_random` | Low | A | `new Random()` -- `java.util.Random` is not cryptographically secure |
| `java.crypto.weak_digest` | Low | A | `MessageDigest.getInstance("MD5"/"SHA1")` |

### XSS

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `java.xss.getwriter_print` | Medium | A | `response.getWriter().print/println/write` -- direct output |

---

## Examples

### `java.deser.readobject`: Unsafe deserialization

**Vulnerable:**
```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // Arbitrary object instantiation
```

**Safe alternative:**
```java
// Use a safe format like JSON
ObjectMapper mapper = new ObjectMapper();
MyType obj = mapper.readValue(request.getInputStream(), MyType.class);
```

### `java.sqli.execute_concat`: SQL concatenation

**Vulnerable:**
```java
String query = "SELECT * FROM users WHERE id=" + userId;
stmt.executeQuery(query);  // SQL injection
```

**Safe alternative:**
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
ps.setString(1, userId);
ResultSet rs = ps.executeQuery();
```

### `java.cmdi.runtime_exec`: Command execution

**Vulnerable:**
```java
Runtime.getRuntime().exec("cmd /c " + userCommand);
```

**Safe alternative:**
```java
ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "dir");
// Use explicit argument list, never concatenate user input
```

### `java.reflection.class_forname`: Dynamic class loading

**Flagged:**
```java
Class<?> cls = Class.forName(className);
Object obj = cls.getDeclaredConstructor().newInstance();
```

**Safe alternative:**
```java
// Use an allowlist of permitted class names
Map<String, Class<?>> allowed = Map.of("User", User.class, "Order", Order.class);
Class<?> cls = allowed.get(className);
if (cls != null) { /* ... */ }
```
