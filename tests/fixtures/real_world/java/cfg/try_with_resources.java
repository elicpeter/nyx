import java.io.*;

public class ResourceHandler {
    public String readSafe(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        }
    }

    public String readUnsafe(String path) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String line = reader.readLine();
        if (line == null) {
            return "empty";  // reader leaked
        }
        reader.close();
        return line;
    }
}
