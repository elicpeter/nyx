import java.io.*;

public class FileStreamClean {
    public String readData(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        fis.close();
        return new String(data);
    }
}
