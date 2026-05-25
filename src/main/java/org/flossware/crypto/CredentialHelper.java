package org.flossware.crypto;

import java.util.Properties;

/**
 * Convenience helper for storing and retrieving encrypted credentials in Properties files.
 * <p>
 * This class provides high-level methods for working with encrypted credentials
 * in {@link Properties} objects, automatically handling encryption/decryption
 * and backward compatibility with plaintext values.
 * </p>
 *
 * <h2>Features:</h2>
 * <ul>
 *   <li>Automatic encryption when saving credentials</li>
 *   <li>Automatic decryption when loading credentials</li>
 *   <li>Backward compatibility with plaintext values</li>
 *   <li>Detection of encrypted vs plaintext values</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>
 * Properties props = new Properties();
 * AESEncryption encryption = new AESEncryption();
 * CredentialHelper helper = new CredentialHelper(encryption);
 *
 * // Save encrypted credential
 * helper.saveCredential(props, "db.password", "secret123");
 *
 * // Load and decrypt credential
 * String password = helper.loadCredential(props, "db.password");
 * // Output: "secret123"
 *
 * // Check if encrypted
 * boolean encrypted = helper.isCredentialEncrypted(props, "db.password");
 * // Output: true
 * </pre>
 *
 * <h2>Backward Compatibility:</h2>
 * <pre>
 * Properties props = new Properties();
 * props.setProperty("old.password", "plaintext-password");
 *
 * CredentialHelper helper = new CredentialHelper(new AESEncryption());
 *
 * // Load works with both encrypted and plaintext
 * String password = helper.loadCredential(props, "old.password");
 * // Output: "plaintext-password"
 *
 * // Migrate to encrypted on save
 * helper.saveCredential(props, "old.password", password);
 * // Now encrypted!
 * </pre>
 *
 * @author sfloess
 * @since 1.0
 */
public class CredentialHelper {

    private final AESEncryption encryption;

    /**
     * Creates a new CredentialHelper with the specified encryption instance.
     *
     * @param encryption the AESEncryption instance to use for encryption/decryption
     * @throws IllegalArgumentException if encryption is null
     */
    public CredentialHelper(AESEncryption encryption) {
        if (encryption == null) {
            throw new IllegalArgumentException("Encryption instance cannot be null");
        }
        this.encryption = encryption;
    }

    /**
     * Saves a credential to a Properties object with encryption.
     * <p>
     * The credential is encrypted before being stored in the properties.
     * </p>
     *
     * @param properties the Properties object to store the credential in
     * @param key the property key
     * @param value the plaintext credential value to encrypt and store
     * @throws IllegalArgumentException if properties, key, or value is null
     */
    public void saveCredential(Properties properties, String key, String value) {
        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (value == null) {
            throw new IllegalArgumentException("Value cannot be null");
        }

        String encryptedValue = encryption.encrypt(value);
        properties.setProperty(key, encryptedValue);
    }

    /**
     * Loads a credential from a Properties object, decrypting if necessary.
     * <p>
     * If the stored value is encrypted (detected via {@link AESEncryption#isEncrypted(String)}),
     * it is decrypted. Otherwise, the plaintext value is returned as-is for backward compatibility.
     * </p>
     *
     * @param properties the Properties object to load from
     * @param key the property key
     * @return the decrypted credential value, or null if key doesn't exist
     * @throws IllegalArgumentException if properties or key is null
     * @throws IllegalStateException if decryption fails
     */
    public String loadCredential(Properties properties, String key) {
        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        String storedValue = properties.getProperty(key);
        if (storedValue == null) {
            return null;
        }

        // Check if encrypted
        if (AESEncryption.isEncrypted(storedValue)) {
            return encryption.decrypt(storedValue);
        } else {
            // Return plaintext as-is (backward compatibility)
            return storedValue;
        }
    }

    /**
     * Checks if a credential is stored in encrypted form.
     *
     * @param properties the Properties object to check
     * @param key the property key
     * @return true if the credential is encrypted, false if plaintext or doesn't exist
     * @throws IllegalArgumentException if properties or key is null
     */
    public boolean isCredentialEncrypted(Properties properties, String key) {
        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        String storedValue = properties.getProperty(key);
        if (storedValue == null) {
            return false;
        }

        return AESEncryption.isEncrypted(storedValue);
    }

    /**
     * Removes a credential from a Properties object.
     *
     * @param properties the Properties object to remove from
     * @param key the property key to remove
     * @throws IllegalArgumentException if properties or key is null
     */
    public void removeCredential(Properties properties, String key) {
        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        properties.remove(key);
    }

    /**
     * Migrates a plaintext credential to encrypted form.
     * <p>
     * If the credential is already encrypted, this is a no-op.
     * </p>
     *
     * @param properties the Properties object containing the credential
     * @param key the property key
     * @return true if migration occurred, false if already encrypted or key doesn't exist
     * @throws IllegalArgumentException if properties or key is null
     * @throws IllegalStateException if decryption fails during migration
     */
    public boolean migrateToEncrypted(Properties properties, String key) {
        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        String storedValue = properties.getProperty(key);
        if (storedValue == null) {
            return false; // Key doesn't exist
        }

        if (AESEncryption.isEncrypted(storedValue)) {
            return false; // Already encrypted
        }

        // Encrypt and save
        saveCredential(properties, key, storedValue);
        return true;
    }
}
