// URL encoding at SQL sink — wrong-type sanitizer.
//
// URLEncoder.encode is registered as Sanitizer(URL_ENCODE) in the taint
// engine, but executeQuery is a Sink(SQL_QUERY). URL encoding does NOT
// neutralise SQL injection, so the engine still emits a finding.
//
// Symex should classify URLEncoder.encode as TransformKind::UrlEncode,
// build a structured Encode node, and surface a renderable witness that
// names the transform — confirming the new Java transform classifier
// is wired through to witness rendering.

import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

public class SymexUrlEncoderJava extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String userInput = request.getParameter("q");
        String encoded = URLEncoder.encode(userInput, "UTF-8");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM items WHERE name = '" + encoded + "'");
    }
}
