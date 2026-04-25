import java.sql.*;
import javax.servlet.http.*;

public class InstanceofGuard extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Object input = req.getParameter("id");
        if (!(input instanceof Integer)) {
            resp.sendError(400);
            return;
        }
        Connection conn = DriverManager.getConnection("jdbc:sqlite:app.db");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);
    }
}
