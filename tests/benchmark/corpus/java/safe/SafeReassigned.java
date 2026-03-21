import java.io.*;
import javax.servlet.http.*;

public class SafeReassigned extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        name = "Guest";
        resp.getWriter().println("<h1>" + name + "</h1>");
    }
}
