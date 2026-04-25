import javax.servlet.http.*;
import java.util.Set;

public class SafeDominated extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("ls", "pwd");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        if (!ALLOWED.contains(cmd)) { resp.sendError(403); return; }
        Runtime.getRuntime().exec(cmd);
    }
}
