import javax.servlet.http.*;

public class ReassignmentCompound extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        String cmd = request.getParameter("cmd");
        cmd = cmd + " safe";
        Runtime.getRuntime().exec(cmd);
    }
}
