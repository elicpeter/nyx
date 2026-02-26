import java.io.*;
import javax.servlet.http.*;

public class ReflectionHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String className = request.getParameter("class");
        Class<?> clazz = Class.forName(className);
        Object instance = clazz.getDeclaredConstructor().newInstance();

        PrintWriter out = response.getWriter();
        out.println("Created: " + instance.getClass().getName());
    }
}
