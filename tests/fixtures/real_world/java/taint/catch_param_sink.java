import java.sql.*;
import javax.servlet.http.*;

public class CatchParamHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        try {
            dangerousOperation();
        } catch (Exception e) {
            response.getWriter().println("Error: " + e);
        }
    }
}
