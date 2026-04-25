import javax.servlet.http.*;
import java.io.*;

public class InfeasibleEquality extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String action = req.getParameter("action");
        if (action.equals("view")) {
            if (action.equals("delete")) {
                // Infeasible: action.equals("view") AND action.equals("delete")
                Runtime.getRuntime().exec(action);
            }
        }
        Runtime.getRuntime().exec(action);
    }
}
