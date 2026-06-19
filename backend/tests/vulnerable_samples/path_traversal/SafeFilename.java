import java.io.*;
import org.apache.commons.io.FilenameUtils;
import javax.servlet.http.HttpServletRequest;

public class SafeFilename {
    public void handle(HttpServletRequest request) throws Exception {
        String raw = request.getParameter("file");
        String safe = FilenameUtils.getName(raw);
        File f = new File("/var/data/" + safe);
        FileInputStream in = new FileInputStream(f);
    }
}
