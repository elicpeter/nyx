import java.sql.*;
import javax.servlet.http.*;

public class SqliConcat extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
