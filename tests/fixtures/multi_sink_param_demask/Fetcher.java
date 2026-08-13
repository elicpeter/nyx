import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

// Cross-file helper whose single `url` parameter is consumed by TWO
// distinct-capability sinks: an SSRF sink (`new HttpGet(url)`) and a
// HEADER_INJECTION sink (`req.addHeader("X-Forwarded-Url", url)`).  Pass-1
// SSA summary extraction records one SinkSite per cap in
// `param_to_sink_sites`.  Before the multi-sink-per-param de-masking fix
// the caller-side emission unioned both caps into one event and the
// cap->rule routing collapsed the union to the single most-specific id
// (`taint-header-injection`), MASKING the SSRF flow.  Both classes must
// surface, each attributed to its own deep sink line.
public class Fetcher {
    public static void fetch(CloseableHttpClient client, String url) throws Exception {
        HttpGet req = new HttpGet(url);
        req.addHeader("X-Forwarded-Url", url);
        client.execute(req);
    }
}
