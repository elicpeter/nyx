// Recall counterpart to SafeAssertStartsWithConfinement (CVE-2021-21234):
// a blocklist assertion `Assert.doesNotContain(name, "..")` is NOT a
// prefix-containment confinement — it is bypassable (absolute paths, encoded
// separators) — so the guarded (interprocedural) read must still fire.  Pins
// that the assert-guard confinement recogniser keys on `startsWith`/containment,
// not on any `Assert.*` call.  Same endpoint+helper shape as the safe fixture,
// differing only in the guard.
import java.io.*;
import javax.servlet.http.*;
import org.springframework.util.Assert;

public class AssertDoesNotContainInsufficient extends HttpServlet {
    private String baseDir = "/var/data";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        Assert.doesNotContain(name, "..");
        read(name, resp.getOutputStream());
    }

    private void read(String name, OutputStream out) throws IOException {
        try (FileInputStream in = new FileInputStream(new File(baseDir, name))) {
            in.transferTo(out);
        }
    }
}
