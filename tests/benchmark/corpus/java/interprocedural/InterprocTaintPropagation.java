import javax.servlet.http.*;

public class InterprocTaintPropagation extends HttpServlet {
    private String buildQuery(String userFilter) {
        return "SELECT * FROM logs WHERE msg LIKE '%" + userFilter + "%'";
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String filter = req.getParameter("filter");
        String query = buildQuery(filter);
        java.sql.Connection conn = null;
        conn.createStatement().executeQuery(query);
    }
}
