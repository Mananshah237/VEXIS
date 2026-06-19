import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SqlInjection {
    public void handle(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
}
