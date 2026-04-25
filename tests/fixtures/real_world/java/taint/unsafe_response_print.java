import java.io.*;
import javax.servlet.http.*;

public class UnsafeResponsePrint extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + name + "</h1>");
    }
}
