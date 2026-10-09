package demo;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

@RestController
public class UserController {
    private final UserRepository repository = new UserRepository();
    private Connection connection;

    @GetMapping("/user")
    public String user(@RequestParam("name") String name) throws Exception {
        repository.findByName(name);  // EXPECT sql-injection cross-file
        return "ok";
    }

    @GetMapping("/ping")
    public String ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);  // EXPECT command-injection direct
        return "ok";
    }

    @GetMapping("/count")
    public String count(@RequestParam("id") String id) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM users WHERE id = " + Integer.parseInt(id));
        return "ok";
    }
}
