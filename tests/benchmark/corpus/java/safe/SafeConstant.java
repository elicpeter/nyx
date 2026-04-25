import java.sql.*;

public class SafeConstant {
    public void checkHealth() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT 1");
        stmt.close();
        conn.close();
    }
}
