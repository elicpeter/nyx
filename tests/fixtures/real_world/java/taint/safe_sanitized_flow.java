import org.springframework.web.util.HtmlUtils;

public class safe_sanitized_flow {
    public static void main(String[] args) {
        String name = System.getenv("USER_NAME");
        if (name != null) {
            String safe = HtmlUtils.htmlEscape(name);
            System.out.println("Hello, " + safe);
        }
    }
}
