import javax.servlet.http.*;
import java.util.logging.Logger;

public class SafeNonSecuritySink extends HttpServlet {
    private static final Logger log = Logger.getLogger("app");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        log.info("User requested: " + name);
        resp.setStatus(200);
    }
}
