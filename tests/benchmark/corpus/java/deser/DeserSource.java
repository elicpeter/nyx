import java.io.*;
import javax.servlet.http.*;

public class DeserSource extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object obj = ois.readObject();
        Runtime.getRuntime().exec(obj.toString());
    }
}
