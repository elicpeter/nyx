import javax.servlet.http.*;

public class CmdiDirect extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
