import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.util.Random;
import javax.xml.parsers.DocumentBuilderFactory;

public class App {
    public static void main(String[] args, javax.servlet.http.HttpServletRequest request) throws Exception {
        String name = args[0];
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        Runtime.getRuntime().exec("ls " + name);
        new ObjectInputStream(new FileInputStream(name));
        new File("/data/" + request.getParameter("file"));
        MessageDigest.getInstance("MD5");
        new Random();
        DocumentBuilderFactory.newInstance();
    }
}
