import java.sql.*;
import java.security.SecureRandom;

class Negative {
    // Safe: parameterized query
    void safeQuery(Connection conn, String user) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, user);
        ResultSet rs = ps.executeQuery();
    }

    // Safe: SecureRandom instead of Random
    void safeRandom() {
        SecureRandom sr = new SecureRandom();
        int token = sr.nextInt();
    }

    // Safe: no concatenation in SQL
    void safeLiteralQuery(Statement stmt) throws Exception {
        stmt.executeQuery("SELECT COUNT(*) FROM users");
    }
}
