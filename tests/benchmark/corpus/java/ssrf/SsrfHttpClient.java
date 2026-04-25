import java.net.http.*;
import java.net.URI;
import javax.servlet.http.*;

public class SsrfHttpClient extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("url");
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).build();
        client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
