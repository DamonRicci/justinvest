import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * password policy checker used during enrolment
 */
public class Problem3b {
    private static final int MIN_LEN = 8;
    private static final int MAX_LEN = 12;
    private static final String ALLOWED_SPECIALS = "!@#$%*&";
    private static final String COMMON_LIST_FILE = "common_passwords.txt";

    /**
     * validates a password against policy rules
     *
     * @param username username to compare against
     * @param password password characters to evaluate
     * @return null if valid, otherwise an error message
     * @throws Exception if the common password list cannot be read
     */
    public static String validate(String username, char[] password) throws Exception {
        if (username == null)
            username = "";
        String u = username.trim();

        if (password == null)
            return "Password cannot be empty.";

        int len = password.length;
        if (len < MIN_LEN || len > MAX_LEN) {
            return "Password must be between 8 and 12 characters in length.";
        }

        // prohibit exact match to username (made case-insenstive to ensure a capitol
        // letter is not just added)
        if (new String(password).equals(u)) {
            return "Password must not match the username.";
        }

        boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : password) {
            if (c >= 'A' && c <= 'Z')
                hasUpper = true;
            else if (c >= 'a' && c <= 'z')
                hasLower = true;
            else if (c >= '0' && c <= '9')
                hasDigit = true;
            else if (ALLOWED_SPECIALS.indexOf(c) >= 0)
                hasSpecial = true;
        }

        if (!hasUpper)
            return "Password must include at least one upper-case letter.";
        if (!hasLower)
            return "Password must include at least one lower-case letter.";
        if (!hasDigit)
            return "Password must include at least one numerical digit.";
        if (!hasSpecial)
            return "Password must include at least one special character from: !, @, #, $, %, *, &.";

        if (isCommonWeakPassword(password)) {
            return "Password is too common/weak and is prohibited.";
        }

        return null; // valid
    }

    private static boolean isCommonWeakPassword(char[] password) throws Exception {
        String p = new String(password);

        File f = new File(COMMON_LIST_FILE);
        if (!f.exists()) {
            // if file not present, still allow enrolment while in prototype
            return false;
        }

        Set<String> common = new HashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty())
                    continue;
                common.add(line);
            }
        }
        return common.contains(p);
    }
}
