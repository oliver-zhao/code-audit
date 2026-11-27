package com.example.web;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.naming.InitialContext;
import javax.naming.directory.DirContext;
import javax.script.ScriptEngine;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class InjectionServlet extends HttpServlet {
    private static final Logger LOG = LogManager.getLogger(InjectionServlet.class);
    private ScriptEngine engine;
    private DirContext ctx;
    private XPath xpath;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host"));
        new ProcessBuilder("sh", "-c", "nslookup " + host).start();
        new ProcessBuilder("cmd.exe", "/c", host).start();
        Runtime.getRuntime().exec(host);

        new SpelExpressionParser().parseExpression(request.getParameter("expr")).getValue();
        engine.eval(host);

        URL target = new URL(request.getParameter("url"));
        new URL(host).openConnection();

        new File("/var/data/" + request.getParameter("file"));
        Files.readAllBytes(Paths.get("/var/data", request.getParameter("doc")));
        new File(host);

        response.sendRedirect(request.getParameter("next"));
        response.sendRedirect(host);
        response.getWriter().println("<p>Hello " + request.getParameter("name") + "</p>");
        response.getWriter().write(host);

        ctx.search("ou=people,dc=example,dc=com", "(uid=" + host + ")", null);
        String filter = "(&(objectClass=person)(cn=" + host + "))";
        xpath.evaluate("//user[@name='" + host + "']/role", null);

        new InitialContext().lookup(request.getParameter("resource"));
        LOG.info("login attempt for " + request.getParameter("user"));
        Class.forName(request.getParameter("type"));
        Pattern.compile(request.getParameter("pattern"));
        String clientIp = request.getHeader("X-Forwarded-For");
    }

    void unzip(ZipInputStream zip, File destination) throws Exception {
        ZipEntry entry = zip.getNextEntry();
        File out = new File(destination, entry.getName());
    }
}
