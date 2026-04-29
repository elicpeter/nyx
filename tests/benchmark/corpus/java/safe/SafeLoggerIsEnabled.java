// `cfg-error-fallthrough` previously fired on
// `if (logger.isErrorEnabled()) { print(...) } more_code()`
// because the condition_vars contained `isErrorEnabled` and the
// rule's `lower.contains("err")` heuristic matched it as an error
// identifier.  Spring's SpringApplication.java:854 has this exact
// shape — a logging-enabled gate, not an error check.
//
// The fix (`is_error_var_ident`) restricts the err identifier to
// `err` / `error` (case-insensitive) or snake-case `err_*` / `*_err`
// / `error_*` / `*_error` — camelCase method names like
// `isErrorEnabled` / `getError` no longer trigger the rule.
public class SafeLoggerIsEnabled {

    interface Logger {
        boolean isErrorEnabled();
    }

    private final Logger logger;

    public SafeLoggerIsEnabled(Logger logger) {
        this.logger = logger;
    }

    public void run(String failure) {
        if (logger.isErrorEnabled()) {
            System.out.println("Application run failed: " + failure);
        }
        registerLoggedException(failure);
    }

    private void registerLoggedException(String failure) {
        // sink that runs unconditionally after the if
    }
}
