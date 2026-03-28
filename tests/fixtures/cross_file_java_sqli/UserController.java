import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP controller layer.
 *
 * SOURCE: request.getParameter("name") returns user-controlled input.
 * The tainted value is forwarded to UserRepository.findByName(), which is
 * defined in UserRepository.java and contains the actual SQL sink.
 */
public class UserController {

    private final UserRepository repository = new UserRepository();

    public void search(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        // Taint source: arbitrary user-supplied HTTP parameter
        String name = request.getParameter("name");

        // Tainted value crosses file boundary into repository layer
        repository.findByName(name);
    }
}
