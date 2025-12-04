// Problem3b.java
// Proactive password checker for enrolment (used by Problem3a).
//
// Compile: javac Problem3b.java Problem3a.java Problem2c.java
// Run (optional self-test): java Problem3b
//
// Policy:
// - length 8..12
// - at least 1 upper, 1 lower, 1 digit, 1 special from ! @ # $ % * &
// - not equal to username
// - not in common weak password list (flexible via common_passwords.txt)

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * Password policy checker used during enrolment.
 */
public class Problem3b {
    private static final int MIN_LEN = 8;
    private static final int MAX_LEN = 12;
    private static final String ALLOWED_SPECIALS = "!@#$%*&";
    private static final String COMMON_LIST_FILE = "common_passwords.txt";

    /**
     * Validates a password against policy rules.
     *
     * @param username username to compare against
     * @param password password characters to evaluate
     * @return null if valid, otherwise an error message
     * @throws Exception if the common password list cannot be read
     */
    public static String validate(String username, char[] password) throws Exception {
        if (username == null) username = "";
        String u = username.trim();

        if (password == null) return "Password cannot be empty.";

        int len = password.length;
        if (len < MIN_LEN || len > MAX_LEN) {
            return "Password must be between 8 and 12 characters in length.";
        }

        // Prohibit exact match to username (case-sensitive per spec; make it case-insensitive to be safer)
        if (new String(password).equals(u)) {
            return "Password must not match the username.";
        }

        boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if (c >= 'A' && c <= 'Z') hasUpper = true;
            else if (c >= 'a' && c <= 'z') hasLower = true;
            else if (c >= '0' && c <= '9') hasDigit = true;
            else if (ALLOWED_SPECIALS.indexOf(c) >= 0) hasSpecial = true;
            // other characters are allowed by policy? Spec only requires "one special from set".
            // We'll allow other chars but they don't count as required special. If you want to prohibit them, enforce here.
        }

        if (!hasUpper)   return "Password must include at least one upper-case letter.";
        if (!hasLower)   return "Password must include at least one lower-case letter.";
        if (!hasDigit)   return "Password must include at least one numerical digit.";
        if (!hasSpecial) return "Password must include at least one special character from: !, @, #, $, %, *, &.";

        if (isCommonWeakPassword(password)) {
            return "Password is too common/weak and is prohibited.";
        }

        return null; // valid
    }

    private static boolean isCommonWeakPassword(char[] password) throws Exception {
        String p = new String(password);

        File f = new File(COMMON_LIST_FILE);
        if (!f.exists()) {
            // If file not present, still allow enrolment (or flip this to fail-closed if you prefer)
            return false;
        }

        // Load into a set each time to keep it simple and flexible.
        // If you want faster, cache it and reload when file timestamp changes.
        Set<String> common = new HashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("#")) continue; // comments
                common.add(line);
            }
        }
        return common.contains(p);
    }

    // Optional self-test
    public static void main(String[] args) throws Exception {
        System.out.println(validate("johnDoe", "johnDoe".toCharArray()));                 // should fail (username)
        System.out.println(validate("johnDoe", "short1!".toCharArray()));                  // fail (len)
        System.out.println(validate("johnDoe", "NoSpecial12".toCharArray()));              // fail (special)
        System.out.println(validate("johnDoe", "GoodPass1!".toCharArray()));               // maybe pass (unless common list)
    }
}
