import java.io.*;
import javax.servlet.http.*;

public class XssReflected extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + name + "</h1>");
    }
}
