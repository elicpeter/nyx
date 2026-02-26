import java.sql.*;

public class DatabaseManager {
    public void queryAndLeak(String url) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT 1");
        // conn and stmt never closed
    }

    public void queryAndClose(String url) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        try {
            Statement stmt = conn.createStatement();
            try {
                stmt.executeQuery("SELECT 1");
            } finally {
                stmt.close();
            }
        } finally {
            conn.close();
        }
    }
}
