import javax.servlet.http.*;

public class SafeReassignedConst extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        String cmd = request.getParameter("cmd");
        cmd = "safe";
        Runtime.getRuntime().exec(cmd);
    }
}
