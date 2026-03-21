import java.io.*;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;

public class SafeSanitized extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        String safe = HtmlUtils.htmlEscape(name);
        resp.getWriter().println("<h1>" + safe + "</h1>");
    }
}
