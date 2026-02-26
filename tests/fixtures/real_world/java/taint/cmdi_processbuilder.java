import java.io.*;
import javax.servlet.http.*;

public class ProcessHandler extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String program = request.getParameter("program");
        String arg = request.getParameter("arg");

        ProcessBuilder pb = new ProcessBuilder(program, arg);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }
}
