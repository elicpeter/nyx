import java.io.*;
import javax.servlet.http.*;

public class DeserCmdi extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        String command = (String) ois.readObject();
        Runtime.getRuntime().exec(command);

        response.getWriter().println("Done");
    }
}
