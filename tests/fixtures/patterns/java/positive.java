import java.io.*;
import java.util.Random;
import java.security.MessageDigest;
import org.yaml.snakeyaml.Yaml;
import org.apache.commons.text.StringSubstitutor;

class Positive {
    // java.deser.readobject
    void triggerDeser(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        Object obj = ois.readObject();
    }

    // java.cmdi.runtime_exec
    void triggerRuntimeExec(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    // java.reflection.class_forname
    void triggerClassForName(String name) throws Exception {
        Class.forName(name);
    }

    // java.reflection.method_invoke
    void triggerMethodInvoke(Object target) throws Exception {
        java.lang.reflect.Method m = target.getClass().getMethod("run");
        m.invoke(target);
    }

    // java.sqli.execute_concat
    void triggerSqlConcat(java.sql.Statement stmt, String user) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    // java.crypto.insecure_random
    void triggerInsecureRandom() {
        Random r = new Random();
        int token = r.nextInt();
    }

    // java.crypto.weak_digest
    void triggerWeakDigest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }

    // java.xss.getwriter_print
    void triggerGetWriterPrint(javax.servlet.http.HttpServletResponse resp) throws Exception {
        resp.getWriter().println("<html>" + "data" + "</html>");
    }

    // java.deser.snakeyaml_unsafe_constructor — CVE-2022-1471 regression guard.
    void triggerSnakeyamlUnsafeConstructor() throws Exception {
        Yaml yaml = new Yaml();
        Object data = yaml.load("payload");
    }

    // java.code_exec.text4shell_interpolator — CVE-2022-42889 regression guard.
    String triggerText4ShellInterpolator(String input) {
        StringSubstitutor s = StringSubstitutor.createInterpolator();
        return s.replace(input);
    }
}
