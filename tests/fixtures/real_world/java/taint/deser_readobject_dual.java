import java.io.*;
public class DeserDual {
    public void process(InputStream userStream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(userStream);
        Object obj = ois.readObject();
        Runtime.getRuntime().exec(obj.toString());
    }
}
