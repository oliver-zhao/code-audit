package com.example.shop;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.springframework.jdbc.core.JdbcTemplate;

public class SqlRepository {
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;

    public ResultSet byName(HttpServletRequest request) throws Exception {
        Statement statement = connection.createStatement();
        return statement.executeQuery("SELECT * FROM users WHERE name = '" + request.getParameter("name") + "'");
    }

    public void deleteOrder(String orderId) throws Exception {
        Statement stmt = connection.createStatement();
        stmt.executeUpdate("DELETE FROM orders WHERE id = " + orderId);
        stmt.addBatch("UPDATE orders SET state = 'x' WHERE owner = '" + orderId + "'");
    }

    public List<String> search(String term) {
        return jdbcTemplate.queryForList("SELECT name FROM products WHERE name LIKE '%" + term + "%'", String.class);
    }

    public int rename(String id, String name) {
        return jdbcTemplate.update(String.format("UPDATE products SET name = '%s' WHERE id = %s", name, id));
    }

    public List<?> jpql(String status) {
        return entityManager.createQuery("SELECT o FROM Order o WHERE o.status = '" + status + "'").getResultList();
    }

    public List<?> nativeSql(String column) {
        return entityManager.createNativeQuery("SELECT id FROM orders ORDER BY " + column).getResultList();
    }

    public String loginQuery(String user, String password) {
        String sql = "SELECT * FROM accounts WHERE user = '" + user + "' AND pass = '" + password + "'";
        return sql;
    }

    public String tableQuery(String tenant) {
        String sql = "SELECT count(*) FROM " + tenant + "_events";
        return sql;
    }

    public ResultSet run(String sql) throws Exception {
        return connection.prepareStatement(sql).executeQuery();
    }

    @Mapper
    public interface UserMapper {
        @Select("SELECT * FROM users WHERE name = '${name}'")
        List<Object> findByName(String name);

        @Update({"UPDATE users SET role = #{role} ORDER BY ${sort}"})
        int updateRole(String role, String sort);
    }
}
