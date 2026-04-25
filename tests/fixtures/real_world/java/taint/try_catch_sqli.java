import java.sql.*;
import javax.servlet.http.*;

public class TryCatchSqlHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userInput = request.getParameter("id");
        try {
            Statement stmt = connection.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
        } catch (SQLException e) {
            response.getWriter().println("Error: " + userInput);
        }
    }
}
