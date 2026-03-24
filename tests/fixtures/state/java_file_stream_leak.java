import java.io.*;

public class FileStreamLeak {
    public String readData(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        return new String(data);
        // fis never closed
    }
}
