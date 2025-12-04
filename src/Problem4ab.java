// Problem4ab.java
// Compile: javac Problem2c.java Problem4ab.java
// Run:     java Problem4ab
//
// Uses:
// - passwd.txt from Problem 2 (via Problem2c.getUserRecord())
// - users.txt from enrolment (username:ROLE per line)

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalTime;
import java.util.*;

/**
 * Authentication and authorization entry point with admin user management menu.
 */
public class Problem4ab {

    private static final String USERS_FILE = "users.txt";
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";
    private static final List<String> ASSIGNABLE_ROLES = List.of(
            "CLIENT", "PREMIUM_CLIENT", "TELLER", "FINANCIAL_ADVISOR", "FINANCIAL_PLANNER"
    );

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);

        System.out.println("justInvest System");
        System.out.println("------------------------------");
        System.out.println("Operations available on the system:");
        System.out.println("1. View account balance");
        System.out.println("2. View investment portfolio");
        System.out.println("3. Modify investment portfolio");
        System.out.println("4. View Financial Advisor contact info");
        System.out.println("5. View Financial Planner contact info");
        System.out.println("6. View money market instruments");
        System.out.println("7. View private consumer instruments");
        System.out.println();

        System.out.print("Enter username: ");
        String username = in.nextLine().trim();

        char[] password = readPassword("Enter password: ", in);

        // ---- Authenticate (Problem 4a) ----
        Problem2c.PasswordRecord rec = Problem2c.getUserRecord(username);
        if (rec == null) {
            deny();
            return;
        }
        if (!verifyPassword(password, rec)) {
            deny();
            return;
        }

        // ---- Determine privileges (Problem 4b) ----
        List<String> labels = getUserLabels(username);
        if (labels.isEmpty()) {
            deny();
            return;
        }

        if (hasManageUsersPermission(username, labels)) {
            handleUserManagement(in, username);
            return;
        }

        Set<Integer> ops = new TreeSet<>();
        for (String label : labels) {
            String role = normalizeRole(label);

            if (role.equals("TELLER") && !isBusinessHours()) {
                System.out.println();
                System.out.println("ACCESS DENIED!");
                System.out.println("Reason: Tellers can only access the system during business hours (9:00am to 5:00pm).");
                return;
            }

            ops.addAll(operationsForRole(role));
        }

        System.out.println();
        System.out.println("ACCESS GRANTED!");
        System.out.println("Authenticated user: " + username);
        System.out.println("Role/labels: " + String.join(", ", labels));
        System.out.println("Your authorized operations are: " + joinOps(ops));
        System.out.println();
        System.out.print("Which operation would you like to perform? ");

        String choice = in.nextLine().trim();
        if (choice.isEmpty()) return;

        int op;
        try {
            op = Integer.parseInt(choice);
        } catch (NumberFormatException e) {
            System.out.println("Invalid choice.");
            return;
        }

        if (!ops.contains(op)) {
            System.out.println("UNAUTHORIZED.");
            return;
        }

        System.out.println("Operation " + op + " selected (not implemented in prototype).");
    }

    private static void deny() {
        System.out.println();
        System.out.println("ACCESS DENIED!");
    }

    private static boolean verifyPassword(char[] password, Problem2c.PasswordRecord r) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, r.salt, r.iterations, r.hash.length * 8);
        byte[] cand = SecretKeyFactory.getInstance(KDF_ALG).generateSecret(spec).getEncoded();
        return MessageDigest.isEqual(cand, r.hash);
    }

    private static List<String> getUserLabels(String username) throws IOException {
        File f = new File(USERS_FILE);
        if (!f.exists()) return List.of();

        try (BufferedReader br = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;

                String[] parts = line.split(":", 2);
                if (parts.length != 2) continue;

                String u = parts[0].trim();
                if (!u.equals(username)) continue;

                // Allow backward compatibility but enforce single-role model by taking the first role only.
                String[] labels = parts[1].split(",");
                List<String> out = new ArrayList<>();
                for (String lab : labels) {
                    String s = lab.trim();
                    if (!s.isEmpty()) {
                        out.add(normalizeRole(s));
                        break;
                    }
                }
                return out;
            }
        }
        return List.of();
    }

    private static Set<Integer> operationsForRole(String role) {
        // Operations:
        // 1 balance, 2 portfolio, 3 modify, 4 FA contact, 5 FP contact, 6 money market, 7 private consumer
        Set<Integer> ops = new HashSet<>();

        switch (role) {
            case "CLIENT" -> {
                ops.add(1); ops.add(2); ops.add(4);
            }
            case "PREMIUM_CLIENT" -> {
                ops.add(1); ops.add(2); ops.add(3); ops.add(4); ops.add(5);
            }
            case "FINANCIAL_ADVISOR" -> {
                ops.add(1); ops.add(2); ops.add(3); ops.add(7);
            }
            case "FINANCIAL_PLANNER" -> {
                ops.add(1); ops.add(2); ops.add(3); ops.add(6); ops.add(7);
            }
            case "TELLER" -> {
                ops.add(1); ops.add(2);
            }
            default -> {
                // Unknown label -> no permissions
            }
        }
        return ops;
    }

    private static boolean isBusinessHours() {
        LocalTime now = LocalTime.now();
        LocalTime start = LocalTime.of(9, 0);
        LocalTime end = LocalTime.of(17, 0);
        return !now.isBefore(start) && now.isBefore(end);
    }

    private static String normalizeRole(String label) {
        String s = label.trim().toUpperCase(Locale.ROOT);
        s = s.replace('-', ' ').replace('_', ' ');
        s = s.replaceAll("\\s+", " ").trim();

        // normalize to the role tokens used in code
        return switch (s) {
            case "PREMIUM CLIENT" -> "PREMIUM_CLIENT";
            case "FINANCIAL ADVISOR" -> "FINANCIAL_ADVISOR";
            case "FINANCIAL PLANNER" -> "FINANCIAL_PLANNER";
            default -> s.replace(' ', '_');
        };
    }

    private static String joinOps(Set<Integer> ops) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (int op : ops) {
            if (!first) sb.append(",");
            sb.append(op);
            first = false;
        }
        return sb.toString();
    }

    private static boolean hasManageUsersPermission(String username, List<String> labels) {
        int hour = LocalTime.now().getHour();
        for (String label : labels) {
            if ("ADMIN".equals(normalizeRole(label))) {
                return AccessControl.hasPermission(
                        new User(username, Role.ADMIN),
                        Permission.MANAGE_USERS,
                        new ActionContext(username, hour));
            }
        }
        return false;
    }

    private static void handleUserManagement(Scanner in, String currentUser) throws Exception {
        while (true) {
            System.out.println();
            System.out.println("User Management Menu (ADMIN)");
            System.out.println("1. View users and roles");
            System.out.println("2. Assign role (replace existing role)");
            System.out.println("3. Exit");
            System.out.print("Enter choice: ");

            String choice = in.nextLine().trim();
            switch (choice) {
                case "1" -> listUsersAndRoles();
                case "2" -> assignRole(in);
                case "3" -> {
                    System.out.println("Exiting user management.");
                    return;
                }
                default -> System.out.println("Invalid choice.");
            }
        }
    }

    private static void listUsersAndRoles() throws Exception {
        Map<String, List<String>> roles = readAllUserRoles();
        if (roles.isEmpty()) {
            System.out.println("No users found in role registry.");
            return;
        }

        System.out.println();
        System.out.println("Users and roles:");
        for (var entry : roles.entrySet()) {
            String joined = String.join(", ", entry.getValue());
            System.out.println("- " + entry.getKey() + ": " + joined);
        }
    }

    private static void assignRole(Scanner in) throws Exception {
        Map<String, List<String>> roles = readAllUserRoles();
        String target = promptUsername(in);
        if (!userExists(target)) {
            System.out.println("ERROR: User does not exist in credential store.");
            return;
        }

        String role = promptRoleSelection(in);
        if (role == null) return;

        roles.put(target, new ArrayList<>(List.of(role)));
        persistUserRoles(roles);
        System.out.println("Updated roles for " + target + " -> " + role);
    }

    private static String promptUsername(Scanner in) {
        System.out.print("Enter target username: ");
        return in.nextLine().trim();
    }

    private static String promptRoleSelection(Scanner in) {
        System.out.println("Select role to assign/grant (ADMIN cannot be delegated):");
        for (int i = 0; i < ASSIGNABLE_ROLES.size(); i++) {
            System.out.println((i + 1) + ". " + ASSIGNABLE_ROLES.get(i));
        }
        System.out.print("Enter choice: ");
        String choice = in.nextLine().trim();
        int idx;
        try {
            idx = Integer.parseInt(choice) - 1;
        } catch (NumberFormatException e) {
            System.out.println("Invalid choice.");
            return null;
        }
        if (idx < 0 || idx >= ASSIGNABLE_ROLES.size()) {
            System.out.println("Invalid choice.");
            return null;
        }
        return ASSIGNABLE_ROLES.get(idx);
    }

    private static Map<String, List<String>> readAllUserRoles() throws Exception {
        Map<String, List<String>> roles = new LinkedHashMap<>();
        File f = new File(USERS_FILE);
        if (!f.exists()) return roles;

        try (BufferedReader br = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] parts = line.split(":", 2);
                if (parts.length != 2) continue;
                String user = parts[0].trim();
                String[] labs = parts[1].split(",");
                List<String> list = new ArrayList<>();
                for (String lab : labs) {
                    String l = normalizeRole(lab);
                    if (!l.isEmpty()) {
                        list.add(l);
                        break; // enforce single role per user
                    }
                }
                if (!user.isEmpty()) roles.put(user, list);
            }
        }
        return roles;
    }

    private static void persistUserRoles(Map<String, List<String>> roles) throws IOException {
        Path tmp = Path.of(USERS_FILE + ".tmp");
        try (BufferedWriter w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            for (var entry : roles.entrySet()) {
                String user = entry.getKey();
                List<String> labels = entry.getValue();
                if (user == null || user.isBlank() || labels == null || labels.isEmpty()) continue;
                String joined = String.join(",", labels);
                w.write(user);
                w.write(":");
                w.write(joined);
                w.newLine();
            }
        }

        try {
            Files.move(tmp, Path.of(USERS_FILE), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, Path.of(USERS_FILE), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static boolean userExists(String username) throws Exception {
        return Problem2c.getUserRecord(username) != null;
    }

    private static char[] readPassword(String prompt, Scanner fallback) throws IOException {
        Console c = System.console();
        if (c != null) {
            return c.readPassword(prompt);
        }
        System.out.print(prompt);
        return fallback.nextLine().toCharArray();
    }
}
