import java.io.File;
import java.sql.PreparedStatement;

public class App {
    public static void main(String[] args) throws Exception {
        PreparedStatement st = null;
        st.executeQuery("SELECT 1");
        new ProcessBuilder("ls").start();
        new File("/data/static.txt");
    }
}
