package com.example.web;

import java.io.File;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.Statement;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Request values that reach a sink through local variables and helper
// methods: invisible to one-line patterns, found by the Opengrep rules.
@RestController
public class RequestFlows {
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;
    private final ExpressionParser parser = new SpelExpressionParser();

    public void servlet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String sql = buildQuery(user);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);

        String[] command = {"nslookup", request.getHeader("X-Host")};
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.start();

        String next = request.getParameter("next");
        response.sendRedirect(next);
    }

    private String buildQuery(String name) {
        return "SELECT id FROM accounts WHERE owner = '" + name + "'";
    }

    @GetMapping("/reports/{name}")
    public byte[] report(@PathVariable("name") String name) throws Exception {
        String location = "/srv/reports/" + name;
        return java.nio.file.Files.readAllBytes(Paths.get(location));
    }

    @GetMapping("/orders")
    public Object orders(@RequestParam String status) {
        String jpql = "SELECT o FROM Order o WHERE o.status = '" + status + "'";
        return entityManager.createQuery(jpql).getResultList();
    }

    @GetMapping("/price")
    public Object price(@RequestHeader("X-Formula") String formula) {
        String expression = formula.trim();
        return parser.parseExpression(expression).getValue();
    }

    @GetMapping("/legacy")
    public Object legacy(@RequestParam("id") String id) {
        String query = "DELETE FROM sessions WHERE id = " + id;
        return jdbcTemplate.update(query);
    }

    @GetMapping("/open")
    public File open(@RequestParam("file") String file) {
        String target = file;
        return new File(target);
    }

    @GetMapping("/bulk")
    public File bulk(@RequestParam java.util.Map<String, String> params) {
        return new File(params.get("file"));
    }

    public void tool(HttpServletRequest request) throws Exception {
        String tool = request.getParameterMap().get("tool")[0];
        new ProcessBuilder(tool).start();
    }
}
