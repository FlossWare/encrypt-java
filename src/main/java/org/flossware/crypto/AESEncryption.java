package org.flossware.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Provides AES-256-GCM encryption and decryption for sensitive data.
 * <p>
 * This class uses authenticated encryption (GCM mode) with a machine-specific
 * key derived from the hostname and user home directory. Each encryption
 * operation uses a random initialization vector (IV) to ensure that identical
 * plaintexts produce different ciphertexts.
 * </p>
 *
 * <h2>Security Properties:</h2>
 * <ul>
 *   <li><strong>Algorithm</strong>: AES-256-GCM (authenticated encryption)</li>
 *   <li><strong>Key Derivation</strong>: PBKDF2-HMAC-SHA256 with 100,000 iterations</li>
 *   <li><strong>Key Material</strong>: Derived from hostname + user.home system property</li>
 *   <li><strong>IV</strong>: 12-byte random IV per encryption (prepended to ciphertext)</li>
 *   <li><strong>Authentication Tag</strong>: 128-bit GCM tag (prevents tampering)</li>
 *   <li><strong>Encoding</strong>: Base64 for storage compatibility</li>
 * </ul>
 *
 * <h2>Machine-Specific Encryption:</h2>
 * <p>
 * The encryption key is derived from machine-specific data (hostname and user home directory).
 * This means:
 * </p>
 * <ul>
 *   <li>Encrypted data cannot be decrypted on a different machine</li>
 *   <li>Changing the hostname invalidates all encrypted data</li>
 *   <li>Changing the user home directory invalidates all encrypted data</li>
 *   <li>Credentials are tied to a specific machine and user</li>
 * </ul>
 *
 * <h2>Thread Safety:</h2>
 * <p>
 * This class is thread-safe. Multiple threads can safely call {@link #encrypt(String)}
 * and {@link #decrypt(String)} concurrently.
 * </p>
 *
 * <h2>Usage Example:</h2>
 * <pre>
 * // Create encryption instance
 * AESEncryption encryption = new AESEncryption();
 *
 * // Encrypt a secret
 * String plaintext = "my-secret-password";
 * String encrypted = encryption.encrypt(plaintext);
 * // Example output: "rMacs4ggVBlIl/GgjvMPIuFj22eQqYQPR1raXiMh3gXwKh6r"
 *
 * // Decrypt the secret
 * String decrypted = encryption.decrypt(encrypted);
 * // Output: "my-secret-password"
 *
 * // Check if a value is encrypted
 * boolean isEncrypted = AESEncryption.isEncrypted(encrypted);
 * // Output: true
 * </pre>
 *
 * <h2>Configuration Storage Example:</h2>
 * <pre>
 * Properties props = new Properties();
 * AESEncryption encryption = new AESEncryption();
 *
 * // Store encrypted password
 * String encryptedPassword = encryption.encrypt("secret123");
 * props.setProperty("db.password", encryptedPassword);
 *
 * // Load and decrypt password
 * String storedPassword = props.getProperty("db.password");
 * if (AESEncryption.isEncrypted(storedPassword)) {
 *     String password = encryption.decrypt(storedPassword);
 *     // Use password...
 * }
 * </pre>
 *
 * @author sfloess
 * @since 1.0
 */
public class AESEncryption {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12; // 96 bits recommended for GCM
    private static final int TAG_SIZE = 128; // 128 bits authentication tag
    private static final int PBKDF2_ITERATIONS = 100_000;

    private final SecretKey secretKey;
    private final SecureRandom secureRandom;

    /**
     * Creates a new AESEncryption instance with a machine-specific encryption key.
     * <p>
     * The encryption key is derived from the hostname and user home directory,
     * making the encrypted data specific to this machine and user.
     * </p>
     *
     * @throws IllegalStateException if encryption initialization fails (e.g., hostname unavailable)
     */
    public AESEncryption() {
        this.secureRandom = new SecureRandom();
        try {
            this.secretKey = generateMachineSpecificKey();
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Failed to initialize AES encryption: hostname unavailable", e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize AES encryption", e);
        }
    }

    /**
     * Encrypts plaintext using AES-256-GCM.
     * <p>
     * Generates a random 12-byte IV, encrypts the plaintext, and returns the
     * IV + ciphertext + authentication tag as a base64-encoded string.
     * </p>
     * <p>
     * Each call to this method with the same plaintext will produce a different
     * encrypted result due to the random IV.
     * </p>
     *
     * @param plaintext the value to encrypt (must not be null or empty)
     * @return base64-encoded IV + ciphertext + tag
     * @throws IllegalArgumentException if plaintext is null or empty
     * @throws IllegalStateException if encryption fails
     */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Cannot encrypt null or empty plaintext");
        }

        try {
            // Generate random IV
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            // Encrypt
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Combine IV + ciphertext
            byte[] combined = ByteBuffer.allocate(iv.length + ciphertext.length)
                .put(iv)
                .put(ciphertext)
                .array();

            // Base64 encode
            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /**
     * Decrypts a base64-encoded ciphertext using AES-256-GCM.
     * <p>
     * Extracts the IV from the beginning of the ciphertext, verifies the
     * authentication tag, and decrypts the data.
     * </p>
     *
     * @param encryptedValue base64-encoded IV + ciphertext + tag (must not be null or empty)
     * @return decrypted plaintext
     * @throws IllegalArgumentException if encryptedValue is null or empty
     * @throws IllegalStateException if decryption fails (corrupted data, wrong key, or tampered data)
     */
    public String decrypt(String encryptedValue) {
        if (encryptedValue == null || encryptedValue.isEmpty()) {
            throw new IllegalArgumentException("Cannot decrypt null or empty value");
        }

        try {
            // Base64 decode
            byte[] combined = Base64.getDecoder().decode(encryptedValue);

            // Extract IV
            ByteBuffer buffer = ByteBuffer.wrap(combined);
            byte[] iv = new byte[IV_SIZE];
            buffer.get(iv);

            // Extract ciphertext
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // Decrypt
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed - data may be corrupted, tampered with, or encrypted on a different machine", e);
        }
    }

    /**
     * Generates a machine-specific encryption key using PBKDF2.
     * <p>
     * Derives a 256-bit AES key from the hostname and user home directory path,
     * making the key unique to this machine and user.
     * </p>
     *
     * @return machine-specific secret key
     * @throws Exception if key generation fails
     */
    private SecretKey generateMachineSpecificKey() throws Exception {
        // Generate machine-specific salt from hostname and user.home
        String hostname = getHostname();
        String userHome = System.getProperty("user.home");
        String machineSalt = hostname + ":" + userHome;

        // Derive key using PBKDF2
        String password = "jencrypt-aes-encryption"; // Fixed password for key derivation
        KeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            machineSalt.getBytes(StandardCharsets.UTF_8),
            PBKDF2_ITERATIONS,
            KEY_SIZE
        );

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Gets the hostname for this machine.
     *
     * @return the hostname
     * @throws UnknownHostException if hostname cannot be determined
     */
    private String getHostname() throws UnknownHostException {
        return InetAddress.getLocalHost().getHostName();
    }

    /**
     * Checks if a value appears to be encrypted by this library.
     * <p>
     * This is a heuristic check based on:
     * </p>
     * <ul>
     *   <li>Value is valid base64</li>
     *   <li>Value is at least 32 characters (IV + tag + some ciphertext)</li>
     * </ul>
     * <p>
     * <strong>Note:</strong> This check is not foolproof - any base64 string longer
     * than 32 characters will pass. However, it's sufficient for distinguishing
     * encrypted values from typical plaintext passwords in configuration files.
     * </p>
     *
     * @param value the value to check
     * @return true if value appears to be encrypted, false otherwise
     */
    public static boolean isEncrypted(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        // Encrypted values are base64 and should be at least 32 characters
        // (12 byte IV + 16 byte tag + some ciphertext = ~40+ base64 chars)
        if (value.length() < 32) {
            return false;
        }

        // Check if valid base64
        try {
            Base64.getDecoder().decode(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
