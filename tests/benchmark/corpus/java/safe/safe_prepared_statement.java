import java.sql.*;
import javax.servlet.http.*;

public class SafeUserLookup extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        // Safe: parameterized query via prepareStatement
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        response.getWriter().println(rs.getString("name"));
        rs.close();
        ps.close();
        conn.close();
    }
}
