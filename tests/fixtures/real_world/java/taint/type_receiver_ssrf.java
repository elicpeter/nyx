import javax.servlet.http.HttpServletRequest;

public class TypeReceiverSsrf {
    public void doGet(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
            .uri(java.net.URI.create(target)).build();
        client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
    }
}
