import java.sql.*;
import javax.servlet.http.*;

public class CastStillTainted extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Object input = req.getParameter("name");
        String name = (String) input;
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
