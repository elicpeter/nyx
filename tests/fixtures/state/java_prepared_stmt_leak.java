import java.sql.*;

class Dao {
    void queryUnsafe(Connection conn, String sql) {
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, "value");
        ResultSet rs = stmt.executeQuery();
        // stmt never closed — leak
    }
}
