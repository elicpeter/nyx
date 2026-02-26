import java.io.*;

public class DoubleClose {
    public void doubleCloseStream(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        fis.close();
        fis.close();
    }

    public void useAfterClose(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        fis.close();
        byte[] data = new byte[1024];
        fis.read(data);
    }
}
