import java.io.*;
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;

public class SafeInterprocedural extends HttpServlet {
    private String sanitize(String input) {
        return HtmlUtils.htmlEscape(input);
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        resp.getWriter().println("<h1>" + sanitize(name) + "</h1>");
    }
}
