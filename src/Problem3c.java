import java.nio.file.Files;
import java.nio.file.Path;

/**
 * tests for enrolment and password policy enforcement
 */
public class Problem3c {
    public static void main(String[] args) throws Exception {
        // start with a clean password file and users file
        Files.deleteIfExists(Path.of("passwd.txt"));
        Files.deleteIfExists(Path.of("users.txt"));

        // TEST 1: Valid password + enrolment succeeds
        String u1 = "alice";
        char[] p1 = "GoodPass1!".toCharArray(); // meets policy
        String err1 = Problem3b.validate(u1, p1);
        if (err1 == null) {
            Problem2c.addUser(u1, p1);
            System.out.println("TEST 1: enrolment for " + u1 + " succeeded (expected).");
        } else {
            System.out.println("TEST 1: FAILED, unexpected error: " + err1);
        }

        // TEST 2: Password too short is rejected by checker
        String u2 = "bob";
        char[] p2 = "Bb1!".toCharArray(); // too short
        String err2 = Problem3b.validate(u2, p2);
        if (err2 != null) {
            System.out.println("TEST 2: short password rejected (expected): " + err2);
        } else {
            System.out.println("TEST 2: FAILED, short password was accepted.");
        }

        // TEST 3: Password equal to username is rejected
        String u3 = "carol";
        char[] p3 = "carol".toCharArray(); // matches username
        String err3 = Problem3b.validate(u3, p3);
        if (err3 != null) {
            System.out.println("TEST 3: username-matching password rejected (expected): " + err3);
        } else {
            System.out.println("TEST 3: FAILED, username-matching password was accepted.");
        }

        // TEST 4: common password from list is rejected
        String u4 = "dave";
        char[] p4 = "password".toCharArray(); // password as password to test deny list.
        String err4 = Problem3b.validate(u4, p4);
        if (err4 != null) {
            System.out.println("TEST 4: common weak password rejected (expected): " + err4);
        } else {
            System.out.println("TEST 4: WARNING, 'password' was not rejected (check common_passwords.txt).");
        }
    }
}
