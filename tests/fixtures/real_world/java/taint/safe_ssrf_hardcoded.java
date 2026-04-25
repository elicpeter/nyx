import java.net.URL;
import java.io.InputStream;

public class safe_ssrf_hardcoded {
    public static void main(String[] args) throws Exception {
        URL url = new URL("https://api.example.com/health");
        InputStream stream = url.openStream();
        stream.read();
        stream.close();
    }
}
