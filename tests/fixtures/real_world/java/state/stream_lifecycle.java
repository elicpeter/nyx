import java.io.*;

public class StreamManager {
    public String readAndLeak(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        return new String(data);
        // fis never closed
    }

    public String readAndClose(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        try {
            byte[] data = new byte[1024];
            fis.read(data);
            return new String(data);
        } finally {
            fis.close();
        }
    }
}
