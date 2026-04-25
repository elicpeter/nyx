import javax.servlet.http.*;
import java.io.*;

public class SpringController extends HttpServlet {
    private Object jdbcTemplate;
    private Object entityManager;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        Object result = jdbcTemplate.query(query);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM accounts WHERE id = " + id;
        Object result = entityManager.createNativeQuery(sql);
    }
}
