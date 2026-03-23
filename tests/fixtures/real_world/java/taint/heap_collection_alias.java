import java.util.ArrayList;
import javax.servlet.http.*;
import java.sql.*;

public class HeapAlias extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ArrayList<String> a = new ArrayList<>();
        ArrayList<String> b = a;
        a.add(req.getParameter("input"));
        String val = b.get(0);
        Statement stmt = DriverManager.getConnection("jdbc:test").createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE x = '" + val + "'");
    }
}
