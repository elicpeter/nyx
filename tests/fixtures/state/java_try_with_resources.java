import java.io.*;

public class TwrTest {
    public void safeTwr(String path) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) {
            fis.read();
        }
    }

    public void unsafeManual(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        fis.read();
    }
}
