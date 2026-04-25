// java-preauth-vuln-001: HTTP servlet without `@PreAuthorize` reads a
// user-supplied path without sanitisation.  `taint-unsanitised-flow`
// should fire on the FILE_IO sink and the missing auth annotation
// leaves the path-traversal flow exposed.
import java.io.*;
import javax.servlet.http.*;

public class VulnDownloadServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("file");
        try (BufferedReader r = new BufferedReader(new FileReader("/var/data/" + name))) {
            resp.getWriter().println(r.readLine());
        }
    }
}
