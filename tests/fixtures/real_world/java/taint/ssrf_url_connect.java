import java.net.URL;
import java.net.HttpURLConnection;
import javax.servlet.http.HttpServletRequest;

public class ProxyServlet {
    public void doGet(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.getInputStream();
    }
}
