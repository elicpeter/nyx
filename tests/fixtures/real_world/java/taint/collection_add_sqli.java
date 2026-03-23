import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;
import java.sql.Statement;

public class CollectionHandler extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ArrayList<String> parts = new ArrayList<>();
        parts.add(req.getParameter("input"));
        String query = parts.get(0);
        Statement stmt = getConnection().createStatement();
        stmt.executeQuery(query);
    }
}
