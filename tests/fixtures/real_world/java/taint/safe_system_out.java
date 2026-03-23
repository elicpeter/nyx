import javax.servlet.http.HttpServletRequest;

public class SystemOutSafe {
    public void doGet(HttpServletRequest request) {
        String name = request.getParameter("name");
        System.out.println(name);
        System.err.println(name);
    }
}
