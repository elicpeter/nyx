import java.io.*;

public class JavaDoubleClose {
    public void doubleClose(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        fis.close();
        fis.close();
    }
}
