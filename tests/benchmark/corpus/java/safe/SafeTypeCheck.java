import java.sql.*;
import javax.servlet.http.*;

public class SafeTypeCheck extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String input = req.getParameter("id");
        if (!(input instanceof String) || !input.matches("\\d+")) {
            resp.sendError(400);
            return;
        }
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);
    }
}
