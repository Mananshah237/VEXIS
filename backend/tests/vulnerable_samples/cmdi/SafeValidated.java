import javax.servlet.http.HttpServletRequest;

public class SafeValidated {
    public void handle(HttpServletRequest request) throws Exception {
        String raw = request.getParameter("count");
        int count = Integer.parseInt(raw);
        String cmd = "sleep " + count;
        Runtime.getRuntime().exec(cmd);
    }
}
