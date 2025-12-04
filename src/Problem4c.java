// Problem4c.java
// Minimal smoke tests for authentication (Problem2c) and authorization (AccessControl).
// Reads existing passwd.txt/users.txt only; does not modify them.
// Coverage rationale:
//  - Verifies a known good credential succeeds and a bad password fails (core login paths).
//  - Confirms ADMIN retains MANAGE_USERS while a CLIENT is denied that permission (access control).

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.spec.KeySpec;

/**
 * Compact smoke tests for authentication and MANAGE_USERS authorization.
 */
public class Problem4c {
    private static final String ADMIN_USER = "admin";
    private static final char[] ADMIN_PW = "V7&kQ2!mZ5@p".toCharArray();
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";

    public static void main(String[] args) throws Exception {
        var adminRec = Problem2c.getUserRecord(ADMIN_USER);
        t(adminRec != null, "admin record exists");
        t(verify(ADMIN_PW, adminRec), "admin password verifies");
        t(!verify("wrong-pass".toCharArray(), adminRec), "incorrect password rejected");

        var ctx = new ActionContext(ADMIN_USER, 10); // business hours
        t(AccessControl.hasPermission(new User(ADMIN_USER, Role.ADMIN), Permission.MANAGE_USERS, ctx),
                "ADMIN has MANAGE_USERS");
        t(!AccessControl.hasPermission(new User("sasha.kim", Role.CLIENT), Permission.MANAGE_USERS, ctx),
                "CLIENT does not have MANAGE_USERS");

        System.out.println("All smoke tests passed.");
    }

    private static boolean verify(char[] password, Problem2c.PasswordRecord r) throws Exception {
        KeySpec spec = new PBEKeySpec(password, r.salt, r.iterations, r.hash.length * 8);
        byte[] cand = SecretKeyFactory.getInstance(KDF_ALG).generateSecret(spec).getEncoded();
        return MessageDigest.isEqual(cand, r.hash);
    }

    private static void t(boolean ok, String msg) {
        if (!ok) throw new AssertionError("FAIL: " + msg);
        System.out.println("PASS: " + msg);
    }
}
