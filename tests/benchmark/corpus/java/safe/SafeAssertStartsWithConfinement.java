// Structural invariant for CVE-2021-21234: an assert-guard containment check
// `Assert.isTrue(<param-derived>.getCanonicalPath().startsWith(<fixed base>))`
// confines its path argument for FILE_IO — any normal return proves the file
// resolves under the trusted base, so the guarded (interprocedural) read is
// safe.  Mirrors the CVE's endpoint+provider shape: the sink lives in a helper
// (`read`) reached after the `confine` guard call.
import java.io.*;
import javax.servlet.http.*;
import org.springframework.util.Assert;

public class SafeAssertStartsWithConfinement extends HttpServlet {
    private String baseDir = "/var/data";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        confine(name);
        read(name, resp.getOutputStream());
    }

    private void confine(String name) throws IOException {
        String canonical = new File(baseDir, name).getCanonicalPath();
        String base = new File(baseDir).getCanonicalPath();
        Assert.isTrue(canonical.startsWith(base), "outside base path");
    }

    private void read(String name, OutputStream out) throws IOException {
        try (FileInputStream in = new FileInputStream(new File(baseDir, name))) {
            in.transferTo(out);
        }
    }
}
