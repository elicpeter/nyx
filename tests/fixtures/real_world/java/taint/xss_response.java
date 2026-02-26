import java.io.*;
import javax.servlet.http.*;

public class XssHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + name + "</h1>");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        String safe = name.replace("<", "&lt;").replace(">", "&gt;");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + safe + "</h1>");
    }
}
