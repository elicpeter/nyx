import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.commons.validator.routines.UrlValidator;
import javax.servlet.http.HttpServletRequest;

// Synthetic regression fixture for CVE-2024-39954 (Apache EventMesh SSRF),
// precision side.  Pins the invariant: a negative-polarity validation
// predicate (`isInvalidUrl`, truthy => reject) gating the sink on its
// early-return path validates the URL on the surviving (false) branch, so the
// Apache HttpClient request constructor sink must NOT fire.
public class SafeNegativeUrlValidator {
    private static final UrlValidator URL_VALIDATOR = new UrlValidator(new String[]{"http", "https"});

    public void handle(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        String target = request.getParameter("target");
        if (isInvalidUrl(target)) {
            return;
        }
        HttpGet req = new HttpGet(target);
        client.execute(req);
    }

    private static boolean isInvalidUrl(String url) {
        return !URL_VALIDATOR.isValid(url);
    }
}
