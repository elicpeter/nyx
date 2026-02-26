import java.io.*;
import javax.servlet.http.*;
import java.sql.*;

public class FullServlet extends HttpServlet {
    private Connection dbConn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, SQLException {
        String action = request.getParameter("action");
        String input = request.getParameter("input");

        if ("exec".equals(action)) {
            Runtime.getRuntime().exec(input);
        } else if ("query".equals(action)) {
            Statement stmt = dbConn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM data WHERE key = '" + input + "'");
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println(rs.getString(1));
            }
        } else if ("read".equals(action)) {
            FileInputStream fis = new FileInputStream(input);
            byte[] data = new byte[4096];
            fis.read(data);
            response.getWriter().println(new String(data));
            // fis leaked
        }
    }
}
