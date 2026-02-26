import java.io.*;

public class ActionHandler {
    public void handle(String action, String input) throws IOException {
        switch (action) {
            case "exec":
                Runtime.getRuntime().exec(input);
                break;
            case "write":
                FileWriter fw = new FileWriter(input);
                fw.write("data");
                fw.close();
                break;
            case "log":
                System.out.println(input);
                break;
        }
    }
}
