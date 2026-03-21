import javax.servlet.http.*;

public class CodeInjection extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cls = req.getParameter("class");
        Class.forName(cls).newInstance();
    }
}
