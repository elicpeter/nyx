import java.net.*;
import java.io.*;
import javax.servlet.http.*;

public class SsrfRequest extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("url");
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.getInputStream();
    }
}
