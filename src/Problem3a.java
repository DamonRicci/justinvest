// Problem3a.java
// Compile: javac Problem2c.java Problem3a.java
// Run:     java Problem3a
//
// NOTE: This calls Problem2c.addUser(...). If your password-file class is named differently,
// change that one line accordingly.

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Interactive enrolment flow that validates passwords and assigns the CLIENT role.
 */
public class Problem3a {
    private static final String USERS_FILE = "users.txt"; // stores username -> role label
    private static final String ROLE_CLIENT = "CLIENT";

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);

        System.out.println("justInvest System");
        System.out.println("------------------------------");
        System.out.println("Sign Up");
        System.out.println();

        String username = readUsername(in);
        while (usernameExists(username)) {
            System.out.println("ERROR: Username already exists. Please choose another.");
            System.out.println();
            username = readUsername(in);
        }
        char[] password = readPassword(in, username);
        char[] confirm  = readPasswordConfirm(in);

        if (!same(password, confirm)) {
            System.out.println();
            System.out.println("ERROR: Passwords do not match.");
            return;
        }

        String role = ROLE_CLIENT; // only CLIENT sign-ups allowed

        // Enrol: add to password file (Problem 2) + add to role file (for access control)
        try {
            // If Problem2c throws on duplicates, that's fine.
            Problem2c.addUser(username, password);

            // store role label for later login/access-control
            addUserRole(username, role);

            System.out.println();
            System.out.println("ENROLMENT SUCCESSFUL!");
            System.out.println("Username: " + username);
            System.out.println("Account type: " + role);
        } catch (IllegalArgumentException e) {
            System.out.println();
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    private static String readUsername(Scanner in) {
        while (true) {
            System.out.print("Enter username: ");
            String u = in.nextLine().trim();

            if (u.isEmpty()) {
                System.out.println("ERROR: Username cannot be empty.");
                continue;
            }
            if (u.contains(":")) {
                System.out.println("ERROR: Username cannot contain ':'");
                continue;
            }
            return u;
        }
    }

    private static char[] readPassword(Scanner in, String username) throws Exception {
        while (true) {
            System.out.print("Enter password: ");
            char[] pw = in.nextLine().toCharArray();

            String err = Problem3b.validate(username, pw);
            if (err == null) {
                return pw; // valid password
            }

            System.out.println("ERROR: " + err);
            System.out.println();
        }
    }


    private static char[] readPasswordConfirm(Scanner in) {
        System.out.print("Confirm password: ");
        return in.nextLine().toCharArray();
    }

    private static void addUserRole(String username, String role) throws IOException {
        File f = new File(USERS_FILE);
        f.createNewFile();

        // Format: <username>:<role>
        String line = username + ":" + role + System.lineSeparator();
        try (BufferedWriter w = new BufferedWriter(new FileWriter(f, StandardCharsets.UTF_8, true))) {
            w.write(line);
        }
    }

    private static boolean same(char[] a, char[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private static boolean usernameExists(String username) throws Exception {
        return Problem2c.getUserRecord(username) != null;
    }
}
