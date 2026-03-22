import java.sql.*;
import javax.servlet.http.*;

public class UserLookup extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        // Vulnerable: raw string concatenation in SQL
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        response.getWriter().println(rs.getString("name"));
    }
}
