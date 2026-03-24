import java.sql.*;

public class DbConnectionLeak {
    public void queryData(String url) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT 1");
        // conn never closed
    }
}
