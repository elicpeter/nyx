import javax.servlet.http.*;

public class LambdaTaint {
    public void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String input = req.getParameter("cmd");
        // Lambda should isolate taint — return inside lambda should NOT
        // kill the parent function's control flow
        java.util.Arrays.asList("a").forEach(x -> {
            if (x.equals("skip")) return; // lambda-local return
        });
        // This sink should still be reachable
        Runtime.getRuntime().exec(input);
    }
}
