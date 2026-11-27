import java.io.File;
import java.sql.PreparedStatement;

public class App {
    public static void main(String[] args) throws Exception {
        PreparedStatement st = null;
        st.executeQuery(args[0]);
        new ProcessBuilder(args[1]).start();
        new File(args[2]);
    }
}
