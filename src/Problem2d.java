import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * tests for Problem2c that back up passwd.txt before running to ensure account
 * already registered aren't deleted
 */
public class Problem2d {
    private static final Path PASSWD = Path.of("passwd.txt");
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";

    public static void main(String[] args) throws Exception {
        boolean hadPasswd = Files.exists(PASSWD);
        byte[] originalPasswd = hadPasswd ? Files.readAllBytes(PASSWD) : new byte[0];
        String testPrefix = "problem2d_" + Long.toHexString(System.nanoTime());
        Throwable failure = null;

        try {
            runTests(testPrefix);
            System.out.println("ALL TESTS PASSED");
        } catch (Throwable t) {
            failure = t;
            throw t;
        } finally {
            try {
                restorePasswd(hadPasswd, originalPasswd);
            } catch (Throwable restoreError) {
                if (failure != null) {
                    failure.addSuppressed(restoreError);
                } else {
                    throw restoreError;
                }
            }
        }
    }

    private static void runTests(String prefix) throws Exception {
        String alice = prefix + "_alice";
        String bob = prefix + "_bob";
        String carol = prefix + "_carol";
        String missing = prefix + "_missing";

        // TEST 1: enroll -> record exists + correct fields
        Problem2c.addUser(alice, "CorrectHorseBatteryStaple!".toCharArray());
        var a = Problem2c.getUserRecord(alice);
        t(a != null, "enroll creates retrievable record");
        t(alice.equals(a.username), "username stored");
        t("pbkdf2_hmac_sha256".equals(a.kdf), "kdf stored");
        t(a.iterations > 0 && a.salt.length > 0 && a.hash.length > 0, "params stored");

        // Test 2: correct password verifies; wrong password fails
        t(verify("CorrectHorseBatteryStaple!".toCharArray(), a), "correct password verifies");
        t(!verify("wrong-password".toCharArray(), a), "wrong password fails");

        // TEST 3: duplicate username rejected
        boolean dupRejected = false;
        try {
            Problem2c.addUser(alice, "AnotherPass123!".toCharArray());
        } catch (IllegalArgumentException e) {
            dupRejected = true;
        }
        t(dupRejected, "duplicate username rejected");

        // TESt 4: same password for different users => different salts/hashes
        Problem2c.addUser(bob, "SamePassword!".toCharArray());
        Problem2c.addUser(carol, "SamePassword!".toCharArray());
        var b = Problem2c.getUserRecord(bob);
        var c = Problem2c.getUserRecord(carol);
        t(b != null && c != null, "multiple users retrievable");
        t(!MessageDigest.isEqual(b.salt, c.salt), "salts differ");
        t(!MessageDigest.isEqual(b.hash, c.hash), "hashes differ");

        // TEST 5: missing user returns null
        t(Problem2c.getUserRecord(missing) == null, "missing user returns null");
    }

    private static void restorePasswd(boolean hadPasswd, byte[] original) throws IOException {
        if (hadPasswd) {
            Files.write(PASSWD, original, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
        } else {
            Files.deleteIfExists(PASSWD);
        }
    }

    private static boolean verify(char[] password, Problem2c.PasswordRecord r) throws Exception {
        KeySpec spec = new PBEKeySpec(password, r.salt, r.iterations, r.hash.length * 8);
        byte[] cand = SecretKeyFactory.getInstance(KDF_ALG).generateSecret(spec).getEncoded();
        return MessageDigest.isEqual(cand, r.hash);
    }

    private static void t(boolean ok, String msg) {
        if (!ok)
            throw new AssertionError("FAIL: " + msg);
        System.out.println("PASS: " + msg);
    }
}
