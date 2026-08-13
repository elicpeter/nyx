import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import javax.servlet.http.HttpServletRequest;

// Multi-sink-per-param de-masking regression fixture.
//
// The helper param `url` is consumed by TWO distinct-capability sinks: an
// SSRF sink (`new HttpGet(url)`, routed to `taint-unsanitised-flow`) and a
// HEADER_INJECTION sink (`req.addHeader("X-Forwarded-Url", url)`, routed to
// `taint-header-injection`).  Before the fix, the cross-function summary
// unioned both caps into one event at the call site and the cap->rule
// routing in ast.rs collapsed the union to the single most-specific id
// (`taint-header-injection`), MASKING the SSRF flow.  After the per-cap
// split both classes must surface at the call site.
public class SsrfMultiSinkParam {
    public void handle(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        String target = request.getParameter("target");
        fetch(client, target);
    }

    static void fetch(CloseableHttpClient client, String url) throws Exception {
        HttpGet req = new HttpGet(url);
        req.addHeader("X-Forwarded-Url", url);
        client.execute(req);
    }
}
