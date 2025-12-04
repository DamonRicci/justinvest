import java.io.BufferedReader;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Minimal password file manager using PBKDF2 with per-user salt.
 */
public class Problem2c {
    private static final String PASSWD_FILE = "passwd.txt";
    private static final String KDF_NAME = "pbkdf2_hmac_sha256";
    private static final String KDF_ALG = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_LEN = 16;
    private static final int KEY_LEN_BYTES = 32;
    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Adds a user credential to the password file using PBKDF2.
     *
     * @param username unique username
     * @param password password characters to hash
     * @throws Exception if hashing fails or user already exists
     */
    public static void addUser(String username, char[] password) throws Exception {
        File file = new File(PASSWD_FILE);
        file.createNewFile(); // create if not exists

        // optional: prevent duplicate usernames
        if (getUserRecord(username) != null) {
            throw new IllegalArgumentException("User already exists: " + username);
        }

        byte[] salt = new byte[SALT_LEN];
        RNG.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LEN_BYTES * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(KDF_ALG);
        byte[] hash = skf.generateSecret(spec).getEncoded();
        Arrays.fill(password, '\0'); // clear password

        String saltB64 = Base64.getEncoder().encodeToString(salt);
        String hashB64 = Base64.getEncoder().encodeToString(hash);

        String record = username + ":" + KDF_NAME + ":" + ITERATIONS + ":"
                + saltB64 + ":" + hashB64 + System.lineSeparator();

        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(file, StandardCharsets.UTF_8, true))) {
            writer.write(record);
        }
    }

    /**
     * Looks up a stored credential record for a user.
     *
     * @param username username to find
     * @return password record or null if not present
     * @throws IOException if the file cannot be read
     */
    public static PasswordRecord getUserRecord(String username) throws IOException {
        File file = new File(PASSWD_FILE);
        if (!file.exists()) {
            return null;
        }

        try (BufferedReader reader = new BufferedReader(
                new FileReader(file, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                String[] parts = line.split(":", 5);
                if (parts.length != 5) continue;

                String user = parts[0];
                if (!user.equals(username)) continue;

                String kdf = parts[1];
                int iterations = Integer.parseInt(parts[2]);
                byte[] salt = Base64.getDecoder().decode(parts[3]);
                byte[] hash = Base64.getDecoder().decode(parts[4]);

                return new PasswordRecord(user, kdf, iterations, salt, hash);
            }
        }

        return null;
    }

    /**
     * Immutable representation of a password record stored on disk.
     */
    public static final class PasswordRecord {
        public final String username;
        public final String kdf;
        public final int iterations;
        public final byte[] salt;
        public final byte[] hash;

        public PasswordRecord(String username,
                              String kdf,
                              int iterations,
                              byte[] salt,
                              byte[] hash) {
            this.username = username;
            this.kdf = kdf;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }

    // legacy initial test

    /*
    public static void main(String[] args) throws Exception {
        addUser("sasha.kim", "ExamplePassw0rd!".toCharArray());
        PasswordRecord r = getUserRecord("sasha.kim");
        if (r != null) {
            String saltB64 = Base64.getEncoder().encodeToString(r.salt);
            String hashB64 = Base64.getEncoder().encodeToString(r.hash);
            System.out.println("Record line:");
            System.out.println(r.username + ":" + r.kdf + ":" + r.iterations
                    + ":" + saltB64 + ":" + hashB64);
        }
    } */
}
