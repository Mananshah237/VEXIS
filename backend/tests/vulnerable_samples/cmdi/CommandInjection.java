import javax.servlet.http.HttpServletRequest;

public class CommandInjection {
    public void handle(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        String cmd = "ping -c 1 " + host;
        Runtime.getRuntime().exec(cmd);
    }
}
