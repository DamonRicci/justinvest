// SeedUsers.java
// Compile: javac Problem2c.java SeedUsers.java
// Run:     java SeedUsers
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Recreates passwd.txt and users.txt with sample users and roles.
 */
public class SeedUsers {
    public static void main(String[] args) throws Exception {
        Files.deleteIfExists(Path.of("passwd.txt"));
        Files.deleteIfExists(Path.of("users.txt"));

        // username -> role
        List<String[]> users = List.of(
            new String[]{"sasha.kim", "CLIENT"},
            new String[]{"emery.blake", "CLIENT"},
            new String[]{"noor.abbasi", "PREMIUM_CLIENT"},
            new String[]{"zuri.adebayo", "PREMIUM_CLIENT"},
            new String[]{"mikael.chen", "FINANCIAL_ADVISOR"},
            new String[]{"jordan.riley", "FINANCIAL_ADVISOR"},
            new String[]{"ellis.nakamura", "FINANCIAL_PLANNER"},
            new String[]{"harper.diaz", "FINANCIAL_PLANNER"},
            new String[]{"alex.hayes", "TELLER"},
            new String[]{"adair.patel", "TELLER"},
            new String[]{"admin", "ADMIN"}
        );

        // simple per-user passwords (policy compliant); change if you want
        Map<String,String> pw = Map.ofEntries(
            Map.entry("sasha.kim", "Sasha1!KimA2"),
            Map.entry("emery.blake", "Emery1@BlakE"),
            Map.entry("noor.abbasi", "Noor2#Abba1"),
            Map.entry("zuri.adebayo", "Zuri3$Adeb1"),
            Map.entry("mikael.chen", "Mikae4%Chen1"),
            Map.entry("jordan.riley", "Jord5*Rile1"),
            Map.entry("ellis.nakamura", "Elli6&Naka1"),
            Map.entry("harper.diaz", "Harp7!Diaz1"),
            Map.entry("alex.hayes", "Alex8@Hay1"),
            Map.entry("adair.patel", "Adai9#Pat1"),
            Map.entry("admin", "V7&kQ2!mZ5@p")
        );

        StringBuilder usersTxt = new StringBuilder();
        for (String[] u : users) {
            String username = u[0];
            String role = u[1];

            Problem2c.addUser(username, pw.get(username).toCharArray()); // creates passwd.txt record
            usersTxt.append(username).append(":").append(role).append(System.lineSeparator());
        }

        Files.writeString(Path.of("users.txt"), usersTxt.toString(), StandardCharsets.UTF_8);
        System.out.println("Seeded passwd.txt and users.txt");
    }
}
