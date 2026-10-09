package demo;

import java.sql.Connection;
import java.sql.Statement;

public class UserRepository {
    private Connection connection;

    public void findByName(String userName) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM users WHERE name = '" + userName + "'");
    }
}
