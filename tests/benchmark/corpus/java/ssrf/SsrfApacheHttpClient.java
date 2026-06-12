import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import javax.servlet.http.HttpServletRequest;

// Synthetic regression fixture for CVE-2024-39954 (Apache EventMesh SSRF).
// Pins the structural invariant: a tainted URL flowing into an Apache
// HttpClient request constructor (`new HttpGet(url)`) and dispatched via
// `httpClient.execute(req)` is an SSRF sink, even across a helper boundary.
public class SsrfApacheHttpClient {
    public void handle(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        String target = request.getParameter("target");
        fetch(client, target);
    }

    static void fetch(CloseableHttpClient client, String url) throws Exception {
        HttpGet req = new HttpGet(url);
        client.execute(req);
    }
}
