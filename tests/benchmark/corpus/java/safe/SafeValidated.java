import javax.servlet.http.*;
import java.util.Set;

public class SafeValidated extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("ls", "pwd", "whoami");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        if (!ALLOWED.contains(cmd)) { resp.sendError(400); return; }
        Runtime.getRuntime().exec(cmd);
    }
}
