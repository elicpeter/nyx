import javax.servlet.http.*;
import java.io.*;

public class MultiMethodXss extends HttpServlet {
    private String processInput(String raw) {
        return "<b>" + raw + "</b>";
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        String formatted = processInput(name);
        response.getWriter().println(formatted);
    }
}
