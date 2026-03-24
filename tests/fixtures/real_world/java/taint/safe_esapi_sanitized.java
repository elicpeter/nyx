import javax.servlet.http.*;
import java.io.*;

public class SafeEsapiSanitized extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        String safe = Encoder.encodeForHTML(name);
        response.getWriter().println(safe);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String id = request.getParameter("id");
        String validated = Validator.getValidInput("id", id, "SafeString", 100, false);
        response.getWriter().println(validated);
    }
}
