import javax.servlet.http.*;
import java.sql.*;
import java.io.*;

public class SafeParameterizedQuery extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, SQLException {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:test.db");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, id);
        ResultSet rs = stmt.executeQuery();
        response.getWriter().println(rs.getString("name"));
    }
}
