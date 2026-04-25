import java.sql.*;
import javax.servlet.http.*;

public class InstanceofWrongBranch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Object input = req.getParameter("id");
        if (input instanceof Integer) {
            // Safe branch — type narrowed here, but we're on the OTHER branch
        }
        // This is the continuation — input is NOT narrowed to Integer here
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);
    }
}
