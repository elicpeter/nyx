import java.io.*;

public class BranchClose {
    public void conditionalClose(String path, boolean flag) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        if (flag) {
            byte[] data = new byte[1024];
            fis.read(data);
            fis.close();
        }
        // fis leaked if !flag
    }

    public void bothBranchesClose(String path, boolean flag) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        if (flag) {
            byte[] data = new byte[1024];
            fis.read(data);
            fis.close();
        } else {
            fis.close();
        }
    }
}
