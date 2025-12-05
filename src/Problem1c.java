import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * basic permission tests across roles loaded from users.txt
 */
public class Problem1c {

        private static final String USERS_FILE = "users.txt";

        private static void check(String name, boolean condition) {
                System.out.println(name + ": " + (condition ? "PASS" : "FAIL"));
        }

        private static Map<String, User> loadUsers(String path) throws Exception {
                Map<String, User> users = new HashMap<>();

                try (BufferedReader br = new BufferedReader(new FileReader(path, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                                line = line.trim();
                                if (line.isEmpty() || line.startsWith("#"))
                                        continue;

                                String[] parts = line.split(":", 2);
                                if (parts.length != 2)
                                        continue;

                                String username = parts[0].trim();

                                // if there are multiple roles for some reason, take the first role as the one
                                // for permission (as mutiple roles is not a requirement)
                                String roleToken = parts[1].split(",", 2)[0].trim();

                                Role role = Role.valueOf(normalizeRole(roleToken));
                                users.put(username, new User(username, role));
                        }
                }

                return users;
        }

        private static String normalizeRole(String roleToken) {
                // Handles "Client", "Premium Client", "PREMIUM_CLIENT", "financial-advisor"
                String s = roleToken.trim().toUpperCase();
                s = s.replace('-', ' ').replace('_', ' ');
                s = s.replaceAll("\\s+", " ").trim();
                return s.replace(' ', '_');
        }

        private static User requireUser(Map<String, User> users, String username) {
                User u = users.get(username);
                if (u == null)
                        throw new IllegalStateException("Missing user in users.txt: " + username);
                return u;
        }

        public static void main(String[] args) throws Exception {
                Map<String, User> users = loadUsers(USERS_FILE);

                // pull users from users.txt for tests
                User client = requireUser(users, "sasha.kim");
                User premium = requireUser(users, "noor.abbasi");
                User teller = requireUser(users, "alex.hayes");
                User advisor = requireUser(users, "mikael.chen");
                User planner = requireUser(users, "ellis.nakamura");
                User admin = requireUser(users, "admin");

                // TEST 1: Clients / Premium clients
                check("Client view own balance",
                                AccessControl.hasPermission(
                                                client,
                                                Permission.VIEW_OWN_BALANCE,
                                                new ActionContext("sasha.kim", 10)));

                check("Client view other portfolio (should FAIL)",
                                !AccessControl.hasPermission(
                                                client,
                                                Permission.VIEW_OWN_PORTFOLIO,
                                                new ActionContext("noor.abbasi", 10)));

                check("Premium modify own portfolio",
                                AccessControl.hasPermission(
                                                premium,
                                                Permission.MODIFY_OWN_PORTFOLIO,
                                                new ActionContext("noor.abbasi", 11)));

                check("Premium modify other's portfolio (should FAIL)",
                                !AccessControl.hasPermission(
                                                premium,
                                                Permission.MODIFY_OWN_PORTFOLIO,
                                                new ActionContext("sasha.kim", 11)));

                check("Premium view outside hours (allowed)",
                                AccessControl.hasPermission(
                                                premium,
                                                Permission.VIEW_OWN_PORTFOLIO,
                                                new ActionContext("noor.abbasi", 20)));

                // TEST 2: Employees viewing accounts
                check("Advisor view any client",
                                AccessControl.hasPermission(
                                                advisor,
                                                Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                                                new ActionContext("sasha.kim", 10)));

                check("Planner view any client",
                                AccessControl.hasPermission(
                                                planner,
                                                Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                                                new ActionContext("noor.abbasi", 14)));

                check("Teller view any client inside hours",
                                AccessControl.hasPermission(
                                                teller,
                                                Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                                                new ActionContext("sasha.kim", 10)));

                check("Teller view any client outside hours (should FAIL)",
                                !AccessControl.hasPermission(
                                                teller,
                                                Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                                                new ActionContext("sasha.kim", 20)));

                check("Advisor view any client outside hours (allowed)",
                                AccessControl.hasPermission(
                                                advisor,
                                                Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                                                new ActionContext("sasha.kim", 20)));

                // TEST 3: Portfolio modification by employees
                check("Advisor modify any client portfolio",
                                AccessControl.hasPermission(
                                                advisor,
                                                Permission.MODIFY_ALL_PORTFOLIO,
                                                new ActionContext("sasha.kim", 10)));

                check("Planner modify any client portfolio",
                                AccessControl.hasPermission(
                                                planner,
                                                Permission.MODIFY_ALL_PORTFOLIO,
                                                new ActionContext("noor.abbasi", 10)));

                check("Teller modify any portfolio (should FAIL)",
                                !AccessControl.hasPermission(
                                                teller,
                                                Permission.MODIFY_ALL_PORTFOLIO,
                                                new ActionContext("sasha.kim", 10)));

                // TEST 4: Instrument visibility
                check("Advisor view private instruments",
                                AccessControl.hasPermission(
                                                advisor,
                                                Permission.VIEW_PRIVATE_INSTRUMENTS,
                                                new ActionContext("sasha.kim", 10)));

                check("Advisor view money market (should FAIL)",
                                !AccessControl.hasPermission(
                                                advisor,
                                                Permission.VIEW_MONEYMARKET_INSTR,
                                                new ActionContext("sasha.kim", 10)));

                check("Planner view private instruments",
                                AccessControl.hasPermission(
                                                planner,
                                                Permission.VIEW_PRIVATE_INSTRUMENTS,
                                                new ActionContext("sasha.kim", 10)));

                check("Planner view money market instruments",
                                AccessControl.hasPermission(
                                                planner,
                                                Permission.VIEW_MONEYMARKET_INSTR,
                                                new ActionContext("sasha.kim", 10)));

                // TEST 5: Admin-only operations
                check("Admin can manage users",
                                AccessControl.hasPermission(
                                                admin,
                                                Permission.MANAGE_USERS,
                                                new ActionContext("admin", 22)));

                check("Client cannot manage users (should FAIL)",
                                !AccessControl.hasPermission(
                                                client,
                                                Permission.MANAGE_USERS,
                                                new ActionContext("sasha.kim", 12)));
        }
}
