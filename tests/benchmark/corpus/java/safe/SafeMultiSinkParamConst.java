import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import javax.servlet.http.HttpServletRequest;

// Precision counterpart to SsrfMultiSinkParam: the SAME multi-sink helper
// (`url` reaches both an SSRF and a HEADER_INJECTION sink) is called with a
// CONSTANT url, never with attacker input.  The per-cap de-masking split
// must not manufacture findings out of an untainted argument — neither
// `taint-unsanitised-flow` nor `taint-header-injection` may fire.
public class SafeMultiSinkParamConst {
    public void handle(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        // request param is read but NOT forwarded into the helper.
        String unused = request.getParameter("target");
        fetch(client, "https://api.internal.example/health");
    }

    static void fetch(CloseableHttpClient client, String url) throws Exception {
        HttpGet req = new HttpGet(url);
        req.addHeader("X-Forwarded-Url", url);
        client.execute(req);
    }
}
