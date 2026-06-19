import java.io.*;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public void handle(HttpServletRequest request) throws Exception {
        String file = request.getParameter("file");
        File f = new File("/var/data/" + file);
        FileInputStream in = new FileInputStream(f);
    }
}
