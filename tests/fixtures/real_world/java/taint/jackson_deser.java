import javax.servlet.http.*;
import java.io.*;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JacksonDeser extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Object data = mapper.readValue(request.getInputStream(), Object.class);
        Runtime.getRuntime().exec(data.toString());
    }
}
