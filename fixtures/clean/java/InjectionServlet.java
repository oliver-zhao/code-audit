package com.example.web;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import org.owasp.encoder.Encode;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class InjectionServlet extends HttpServlet {
    private static final Map<String, String> TARGETS = Map.of("docs", "https://docs.example.com/");
    private static final Map<String, String> HOSTS = Map.of("primary", "db1.internal", "replica", "db2.internal");
    private static final Path ROOT = Paths.get("/var/data");
    private DirContext ctx;
    private XPath xpath;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = HOSTS.getOrDefault(request.getParameter("host"), "db1.internal");
        if (!host.matches("[a-z0-9.-]{1,253}")) {
            return;
        }
        new ProcessBuilder(List.of("ping", "-c", "1", host)).start();
        new ProcessBuilder("git", "status").start();

        Object total = new SpelExpressionParser().parseExpression("price * quantity").getValue();

        String target = TARGETS.getOrDefault(request.getParameter("site"), "https://example.com/");

        Path doc = ROOT.resolve("reports").normalize();
        Files.readAllBytes(doc);
        new File("/var/data/static.txt");

        response.sendRedirect(request.getContextPath() + "/home");
        response.getWriter().println("<p>Hello " + Encode.forHtml(request.getParameter("name")) + "</p>");
        response.getWriter().write("ok");

        ctx.search("ou=people,dc=example,dc=com", "(uid={0})", new Object[] {host}, null);
        xpath.evaluate("//user[@name=$name]/role", null);

        Pattern.compile(Pattern.quote(host));
        String clientIp = request.getRemoteAddr();
    }

    void unzip(ZipInputStream zip, Path destination) throws Exception {
        ZipEntry entry = zip.getNextEntry();
        Path out = destination.resolve(entry.getName()).normalize();
        if (!out.startsWith(destination)) {
            throw new SecurityException("entry outside target dir");
        }
    }
}
