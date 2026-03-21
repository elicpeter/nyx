import java.io.*;
import javax.servlet.http.*;

public class PathTraversal extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String path = req.getParameter("path");
        FileInputStream fis = new FileInputStream(path);
        byte[] data = fis.readAllBytes();
        resp.getOutputStream().write(data);
    }
}
