import javax.naming.InitialContext;
import javax.servlet.http.*;
import java.io.*;

public class JndiServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String name = request.getParameter("resource");
        InitialContext ctx = new InitialContext();
        Object result = ctx.lookup(name);
    }
}
