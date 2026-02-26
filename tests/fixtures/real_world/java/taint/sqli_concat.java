import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class UserQuery extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, SQLException {
        String userId = request.getParameter("id");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        PrintWriter out = response.getWriter();
        while (rs.next()) {
            out.println(rs.getString("name"));
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, SQLException {
        String userId = request.getParameter("id");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        ResultSet rs = stmt.executeQuery();

        PrintWriter out = response.getWriter();
        while (rs.next()) {
            out.println(rs.getString("name"));
        }
    }
}
