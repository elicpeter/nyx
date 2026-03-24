import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class UserController {
    public ResponseEntity<String> greet(HttpServletRequest request) {
        String name = request.getParameter("name");
        return new ResponseEntity<>(name, HttpStatus.OK);
    }
}
