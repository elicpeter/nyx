import java.io.*;

public class FileProcessor {
    public void processWithFinally(String path) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(path);
            byte[] data = new byte[1024];
            fis.read(data);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    public void processLeaky(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[1024];
        fis.read(data);
        if (data[0] == 0) {
            throw new IOException("bad data");  // fis leaked
        }
        fis.close();
    }
}
