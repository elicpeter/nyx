// java-preauth-001: Spring Security `@PreAuthorize` annotation gates
// the controller method.  Auth analysis must recognise the annotation
// as an authentication guard so neither `cfg-auth-gap` nor
// `state-unauthed-access` fires on the privileged FILE_IO sink.
import java.io.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeDownloadController {
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/download")
    public String handle(@RequestParam String name) throws IOException {
        if (name.contains("..") || name.startsWith("/") || name.startsWith("\\")) {
            return "denied";
        }
        try (BufferedReader r = new BufferedReader(new FileReader("/var/data/" + name))) {
            return r.readLine();
        }
    }
}
