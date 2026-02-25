import java.io.*;
import java.sql.*;
import java.util.Random;

/**
 * Simulates a Java backend service handling HTTP requests.
 * Contains realistic vulnerability patterns found in enterprise Java code.
 */
public class Service {

    private Connection dbConn;

    public Service(Connection dbConn) {
        this.dbConn = dbConn;
    }

    // ───── Command execution from environment ─────

    /**
     * POST /admin/maintenance
     * Runs a maintenance command from environment config.
     * VULN: System.getenv flows into Runtime.exec (command injection)
     */
    public String handleMaintenance() throws IOException {
        String cmd = System.getenv("MAINTENANCE_CMD");
        Process proc = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * POST /admin/deploy
     * Constructs a deploy command from multiple env vars.
     * VULN: System.getenv flows into Runtime.exec
     */
    public void handleDeploy() throws IOException {
        String target = System.getenv("DEPLOY_HOST");
        String artifact = System.getenv("ARTIFACT_PATH");
        String command = "scp " + artifact + " " + target + ":/opt/app/";
        Runtime.getRuntime().exec(command);
    }

    // ───── SQL injection via string concatenation ─────

    /**
     * GET /api/users/search
     * Searches users with a query parameter concatenated into SQL.
     * VULN: System.getenv flows into executeQuery (SQL injection)
     */
    public ResultSet searchUsers(String searchTerm) throws SQLException {
        String table = System.getenv("USERS_TABLE");
        String sql = "SELECT * FROM " + table + " WHERE name LIKE '%" + searchTerm + "%'";
        Statement stmt = dbConn.createStatement();
        return stmt.executeQuery(sql);
    }

    /**
     * POST /api/audit/log
     * Writes an audit log entry using concatenated SQL.
     * VULN: String concatenation in executeUpdate (SQL injection)
     */
    public void logAuditEvent(String event, String userId) throws SQLException {
        String sql = "INSERT INTO audit_log (event, user_id, ts) VALUES ('"
            + event + "', '" + userId + "', NOW())";
        Statement stmt = dbConn.createStatement();
        stmt.executeUpdate(sql);
    }

    // ───── Deserialization ─────

    /**
     * POST /api/session/restore
     * Deserializes a session object from a byte stream.
     * VULN: ObjectInputStream.readObject on untrusted data
     */
    public Object restoreSession(InputStream sessionData) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(sessionData);
        Object session = ois.readObject();
        ois.close();
        return session;
    }

    // ───── Reflection ─────

    /**
     * POST /api/plugins/load
     * Dynamically loads a class by name from environment config.
     * VULN: System.getenv flows into Class.forName (unsafe reflection)
     */
    public Object loadPlugin() throws Exception {
        String className = System.getenv("PLUGIN_CLASS");
        Class<?> pluginClass = Class.forName(className);
        return pluginClass.getDeclaredConstructor().newInstance();
    }

    // ───── Weak randomness ─────

    /**
     * Generates a session token using java.util.Random.
     * VULN: insecure random — should use SecureRandom for tokens
     */
    public String generateSessionToken() {
        Random rng = new Random();
        long tokenValue = rng.nextLong();
        return Long.toHexString(tokenValue);
    }

    // ───── Safe patterns ─────

    /**
     * SAFE: uses PreparedStatement (parameterized query).
     */
    public ResultSet safeSearch(String term) throws SQLException {
        PreparedStatement pstmt = dbConn.prepareStatement(
            "SELECT * FROM users WHERE name LIKE ?"
        );
        pstmt.setString(1, "%" + term + "%");
        return pstmt.executeQuery();
    }
}
