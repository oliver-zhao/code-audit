import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.PreparedStatement;

public class App {
    public static void main(String[] args) throws Exception {
        String name = args.length > 0 ? args[0] : "guest";
        PreparedStatement st = null;
        st.setString(1, name);
        st.executeQuery();
        new File("/data/static.txt");
        MessageDigest.getInstance("SHA-256");
        new SecureRandom();
    }
}
