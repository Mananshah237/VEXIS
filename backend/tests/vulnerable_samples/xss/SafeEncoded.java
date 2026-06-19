import java.io.*;
import org.springframework.web.util.HtmlUtils;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeEncoded {
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("name");
        String safe = HtmlUtils.htmlEscape(raw);
        response.getWriter().println("<h1>Hello " + safe + "</h1>");
    }
}
