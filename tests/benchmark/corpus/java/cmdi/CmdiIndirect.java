import javax.servlet.http.*;

public class CmdiIndirect extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String host = req.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
