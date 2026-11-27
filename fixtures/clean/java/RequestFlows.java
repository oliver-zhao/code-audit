package com.example.web;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Map;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FilenameUtils;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// The same request values as in the vulnerable RequestFlows.java, bound as
// parameters, looked up in allowlists, parsed or reduced to a file name.
@RestController
public class RequestFlows {
    private static final Map<String, String> NEXT = Map.of("home", "/home", "cart", "/cart");
    private static final Map<String, String> FORMULAS = Map.of("net", "price * quantity");
    private static final Path REPORTS = Paths.get("/srv/reports");
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;
    private final ExpressionParser parser = new SpelExpressionParser();

    public void servlet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        PreparedStatement statement = connection.prepareStatement("SELECT id FROM accounts WHERE owner = ?");
        statement.setString(1, user);
        statement.executeQuery();

        String[] command = {"nslookup", "example.com"};
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.start();

        String next = NEXT.getOrDefault(request.getParameter("next"), "/home");
        response.sendRedirect(next);
    }

    @GetMapping("/reports/{name}")
    public byte[] report(@PathVariable("name") String name) throws Exception {
        String location = FilenameUtils.getName(name);
        return java.nio.file.Files.readAllBytes(REPORTS.resolve(location));
    }

    @GetMapping("/orders")
    public Object orders(@RequestParam String status) {
        return entityManager.createQuery("SELECT o FROM Order o WHERE o.status = :status").setParameter("status", status).getResultList();
    }

    @GetMapping("/price")
    public Object price(@RequestHeader("X-Formula") String formula) {
        String expression = FORMULAS.get(formula);
        return parser.parseExpression(expression).getValue();
    }

    @GetMapping("/legacy")
    public Object legacy(@RequestParam("id") String id) {
        long sessionId = Long.parseLong(id);
        String sql = "DELETE FROM sessions WHERE id = " + sessionId;
        return jdbcTemplate.update(sql);
    }

    @GetMapping("/open")
    public File open(@RequestParam("file") String file) {
        return new File("/srv/files", FilenameUtils.getName(file));
    }
}
