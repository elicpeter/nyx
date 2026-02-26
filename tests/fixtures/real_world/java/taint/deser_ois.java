import java.io.*;
import javax.servlet.http.*;

public class DeserHandler extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();

        PrintWriter out = response.getWriter();
        out.println("Deserialized: " + obj.toString());
    }
}
