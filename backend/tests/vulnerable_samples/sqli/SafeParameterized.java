import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SafeParameterized {
    public void handle(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();
    }
}
