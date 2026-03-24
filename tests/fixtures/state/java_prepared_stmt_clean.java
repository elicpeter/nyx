import java.sql.*;

class Dao {
    void querySafe(Connection conn, String sql) {
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, "value");
        ResultSet rs = stmt.executeQuery();
        rs.close();
        stmt.close();
    }
}
