package com.example.shop;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

public class SqlRepository {
    private static final String TABLE = "users";
    private static final Set<String> SORTABLE = Set.of("id", "created_at");
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private NamedParameterJdbcTemplate named;
    private EntityManager entityManager;

    public ResultSet byName(HttpServletRequest request) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, request.getParameter("name"));
        return ps.executeQuery();
    }

    public List<String> search(String term) {
        return jdbcTemplate.queryForList("SELECT name FROM products WHERE name LIKE ?", String.class, "%" + term + "%");
    }

    public int rename(String id, String name) {
        return named.update("UPDATE products SET name = :name WHERE id = :id", Map.of("name", name, "id", id));
    }

    public List<?> jpql(String status) {
        return entityManager.createQuery("SELECT o FROM Order o WHERE o.status = :status").setParameter("status", status).getResultList();
    }

    public List<?> sorted(String column) {
        String safe = SORTABLE.contains(column) ? column : "id";
        return entityManager.createNativeQuery("SELECT id FROM orders ORDER BY id").getResultList();
    }

    public int count() {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM " + TABLE, Integer.class);
    }

    @Mapper
    public interface UserMapper {
        @Select("SELECT * FROM users WHERE name = #{name}")
        List<Object> findByName(String name);
    }
}
