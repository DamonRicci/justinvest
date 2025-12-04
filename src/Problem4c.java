import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.KeySpec;

/**
 * Tests for authentication, MANAGE_USERS authorization, teller time gate, and a
 * scripted UI run
 */
public class Problem4c {
    private static final String ADMIN_USER = "admin";
    private static final char[] ADMIN_PW = "V7&kQ2!mZ5@p".toCharArray(); // uses pw randomly generated for admin account
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";

    public static void main(String[] args) throws Exception {
        var adminRec = Problem2c.getUserRecord(ADMIN_USER);
        t(adminRec != null, "admin record exists"); // admin exist
        t(verify(ADMIN_PW, adminRec), "admin password verifies"); // admin can auth
        t(!verify("wrong-pass".toCharArray(), adminRec), "incorrect password rejected"); // deny admin on wrong pw

        var ctx = new ActionContext(ADMIN_USER, 10); // in business hours
        t(AccessControl.hasPermission(new User(ADMIN_USER, Role.ADMIN), Permission.MANAGE_USERS, ctx),
                "ADMIN has MANAGE_USERS");
        t(!AccessControl.hasPermission(new User("sasha.kim", Role.CLIENT), Permission.MANAGE_USERS, ctx),
                "CLIENT does not have MANAGE_USERS");

        // Teller time restriction test: allowed in hours, denied outside hours.
        var teller = new User("alex.hayes", Role.TELLER);
        t(AccessControl.hasPermission(teller, Permission.VIEW_ALL_CLIENT_ACCOUNTS, new ActionContext("sasha.kim", 10)),
                "TELLER allowed during business hours");
        t(!AccessControl.hasPermission(teller, Permission.VIEW_ALL_CLIENT_ACCOUNTS, new ActionContext("sasha.kim", 20)),
                "TELLER denied outside business hours");

        // scripted UI flow: admin login then exit user-management menu.
        runUi();

        System.out.println("All tests passed.");
    }

    private static boolean verify(char[] password, Problem2c.PasswordRecord r) throws Exception {
        KeySpec spec = new PBEKeySpec(password, r.salt, r.iterations, r.hash.length * 8);
        byte[] cand = SecretKeyFactory.getInstance(KDF_ALG).generateSecret(spec).getEncoded();
        return MessageDigest.isEqual(cand, r.hash);
    }

    private static void runUi() throws Exception {
        String input = String.join(System.lineSeparator(),
                ADMIN_USER,
                new String(ADMIN_PW),
                "3" // exit user management menu
        ) + System.lineSeparator();

        var originalIn = System.in;
        var originalOut = System.out;

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setIn(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            Problem4ab.main(new String[0]);
        } finally {
            System.setIn(originalIn);
            System.setOut(originalOut);
        }

        String out = buf.toString(StandardCharsets.UTF_8);
        t(out.contains("User Management Menu"), "UI flow reached admin user management menu");
    }

    private static void t(boolean ok, String msg) {
        if (!ok)
            throw new AssertionError("FAIL: " + msg);
        System.out.println("PASS: " + msg);
    }
}
