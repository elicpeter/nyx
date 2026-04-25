// Fixture: Java arrow-switch with integer-literal cases that exercise
// per-case path-constraint forking in the symex executor.
//
// Arrow-switch (`case N -> {...}`) has no fall-through, so each arm gets
// a `code == N` path constraint when the executor explores it. The safe
// arm sanitizes before reaching the sink so it should not be reported.

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class switch_java {
    static String sanitize(String s) {
        return s.replace("'", "''");
    }

    public static void dispatch(Connection conn, int code, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        switch (code) {
            case 500 -> {
                // Raw path: tainted userInput flows into the SQL sink.
                stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
            }
            case 200 -> {
                // Safe path: sanitize first.
                String safe = sanitize(userInput);
                stmt.executeQuery("SELECT * FROM users WHERE name = '" + safe + "'");
            }
            default -> {
                stmt.executeQuery("SELECT 1");
            }
        }
    }
}
