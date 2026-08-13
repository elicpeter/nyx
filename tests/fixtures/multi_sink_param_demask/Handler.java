import org.apache.http.impl.client.CloseableHttpClient;
import javax.servlet.http.HttpServletRequest;

// Route handler that forwards attacker-controlled `target` into the
// cross-file multi-sink helper.  Both the SSRF and the HEADER_INJECTION
// flow originate here.
public class Handler {
    public void handle(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        String target = request.getParameter("target");
        Fetcher.fetch(client, target);
    }
}
