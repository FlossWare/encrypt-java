package org.flossware.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Comprehensive tests for CredentialHelper with 100% code coverage.
 */
class CredentialHelperTest {

    private AESEncryption encryption;
    private CredentialHelper helper;
    private Properties properties;

    @BeforeEach
    void setUp() {
        encryption = new AESEncryption();
        helper = new CredentialHelper(encryption);
        properties = new Properties();
    }

    // ========== Constructor Tests ==========

    @Test
    void testConstructorWithValidEncryption() {
        CredentialHelper h = new CredentialHelper(new AESEncryption());
        assertTrue(h != null);
    }

    @Test
    void testConstructorWithNullEncryptionThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            new CredentialHelper(null)
        );
        assertTrue(exception.getMessage().contains("cannot be null"));
    }

    // ========== saveCredential() Tests ==========

    @Test
    void testSaveCredential() {
        helper.saveCredential(properties, "db.password", "secret123");

        assertTrue(properties.containsKey("db.password"));
        String stored = properties.getProperty("db.password");
        assertTrue(AESEncryption.isEncrypted(stored));
    }

    @Test
    void testSaveCredentialWithNullPropertiesThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.saveCredential(null, "key", "value")
        );
        assertTrue(exception.getMessage().contains("Properties cannot be null"));
    }

    @Test
    void testSaveCredentialWithNullKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.saveCredential(properties, null, "value")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testSaveCredentialWithEmptyKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.saveCredential(properties, "", "value")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testSaveCredentialWithNullValueThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.saveCredential(properties, "key", null)
        );
        assertTrue(exception.getMessage().contains("Value cannot be null"));
    }

    // ========== loadCredential() Tests ==========

    @Test
    void testLoadCredentialEncrypted() {
        helper.saveCredential(properties, "db.password", "secret123");

        String loaded = helper.loadCredential(properties, "db.password");

        assertEquals("secret123", loaded);
    }

    @Test
    void testLoadCredentialPlaintext() {
        properties.setProperty("old.password", "plaintext-password");

        String loaded = helper.loadCredential(properties, "old.password");

        assertEquals("plaintext-password", loaded);
    }

    @Test
    void testLoadCredentialNonExistentReturnsNull() {
        String loaded = helper.loadCredential(properties, "nonexistent");

        assertNull(loaded);
    }

    @Test
    void testLoadCredentialWithNullPropertiesThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.loadCredential(null, "key")
        );
        assertTrue(exception.getMessage().contains("Properties cannot be null"));
    }

    @Test
    void testLoadCredentialWithNullKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.loadCredential(properties, null)
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testLoadCredentialWithEmptyKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.loadCredential(properties, "")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    // ========== isCredentialEncrypted() Tests ==========

    @Test
    void testIsCredentialEncryptedWithEncryptedValue() {
        helper.saveCredential(properties, "db.password", "secret123");

        assertTrue(helper.isCredentialEncrypted(properties, "db.password"));
    }

    @Test
    void testIsCredentialEncryptedWithPlaintextValue() {
        properties.setProperty("old.password", "plaintext");

        assertFalse(helper.isCredentialEncrypted(properties, "old.password"));
    }

    @Test
    void testIsCredentialEncryptedWithNonExistent() {
        assertFalse(helper.isCredentialEncrypted(properties, "nonexistent"));
    }

    @Test
    void testIsCredentialEncryptedWithNullPropertiesThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.isCredentialEncrypted(null, "key")
        );
        assertTrue(exception.getMessage().contains("Properties cannot be null"));
    }

    @Test
    void testIsCredentialEncryptedWithNullKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.isCredentialEncrypted(properties, null)
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testIsCredentialEncryptedWithEmptyKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.isCredentialEncrypted(properties, "")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    // ========== removeCredential() Tests ==========

    @Test
    void testRemoveCredential() {
        properties.setProperty("db.password", "secret");

        helper.removeCredential(properties, "db.password");

        assertFalse(properties.containsKey("db.password"));
    }

    @Test
    void testRemoveCredentialNonExistent() {
        helper.removeCredential(properties, "nonexistent");

        assertFalse(properties.containsKey("nonexistent"));
    }

    @Test
    void testRemoveCredentialWithNullPropertiesThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.removeCredential(null, "key")
        );
        assertTrue(exception.getMessage().contains("Properties cannot be null"));
    }

    @Test
    void testRemoveCredentialWithNullKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.removeCredential(properties, null)
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testRemoveCredentialWithEmptyKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.removeCredential(properties, "")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    // ========== migrateToEncrypted() Tests ==========

    @Test
    void testMigrateToEncryptedFromPlaintext() {
        properties.setProperty("old.password", "plaintext");

        boolean migrated = helper.migrateToEncrypted(properties, "old.password");

        assertTrue(migrated);
        assertTrue(helper.isCredentialEncrypted(properties, "old.password"));
        assertEquals("plaintext", helper.loadCredential(properties, "old.password"));
    }

    @Test
    void testMigrateToEncryptedAlreadyEncrypted() {
        helper.saveCredential(properties, "db.password", "secret123");

        boolean migrated = helper.migrateToEncrypted(properties, "db.password");

        assertFalse(migrated);
        assertTrue(helper.isCredentialEncrypted(properties, "db.password"));
    }

    @Test
    void testMigrateToEncryptedNonExistent() {
        boolean migrated = helper.migrateToEncrypted(properties, "nonexistent");

        assertFalse(migrated);
    }

    @Test
    void testMigrateToEncryptedWithNullPropertiesThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.migrateToEncrypted(null, "key")
        );
        assertTrue(exception.getMessage().contains("Properties cannot be null"));
    }

    @Test
    void testMigrateToEncryptedWithNullKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.migrateToEncrypted(properties, null)
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    @Test
    void testMigrateToEncryptedWithEmptyKeyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            helper.migrateToEncrypted(properties, "")
        );
        assertTrue(exception.getMessage().contains("Key cannot be null or empty"));
    }

    // ========== Integration Tests ==========

    @Test
    void testSaveLoadRoundTrip() {
        helper.saveCredential(properties, "api.key", "secret-api-key-123");
        String loaded = helper.loadCredential(properties, "api.key");

        assertEquals("secret-api-key-123", loaded);
    }

    @Test
    void testBackwardCompatibilityWithPlaintext() {
        properties.setProperty("legacy.password", "old-plaintext-password");

        String loaded = helper.loadCredential(properties, "legacy.password");

        assertEquals("old-plaintext-password", loaded);
    }

    @Test
    void testMigrateAndLoad() {
        properties.setProperty("db.password", "plaintext-password");

        helper.migrateToEncrypted(properties, "db.password");
        String loaded = helper.loadCredential(properties, "db.password");

        assertEquals("plaintext-password", loaded);
        assertTrue(helper.isCredentialEncrypted(properties, "db.password"));
    }

    @Test
    void testMultipleCredentials() {
        helper.saveCredential(properties, "db.password", "db-secret");
        helper.saveCredential(properties, "api.key", "api-secret");
        properties.setProperty("legacy.token", "plaintext-token");

        assertEquals("db-secret", helper.loadCredential(properties, "db.password"));
        assertEquals("api-secret", helper.loadCredential(properties, "api.key"));
        assertEquals("plaintext-token", helper.loadCredential(properties, "legacy.token"));

        assertTrue(helper.isCredentialEncrypted(properties, "db.password"));
        assertTrue(helper.isCredentialEncrypted(properties, "api.key"));
        assertFalse(helper.isCredentialEncrypted(properties, "legacy.token"));
    }

    @Test
    void testOverwriteCredential() {
        helper.saveCredential(properties, "db.password", "old-password");
        helper.saveCredential(properties, "db.password", "new-password");

        String loaded = helper.loadCredential(properties, "db.password");

        assertEquals("new-password", loaded);
    }

    @Test
    void testRemoveAndReAdd() {
        helper.saveCredential(properties, "db.password", "secret");
        helper.removeCredential(properties, "db.password");

        assertNull(helper.loadCredential(properties, "db.password"));

        helper.saveCredential(properties, "db.password", "new-secret");

        assertEquals("new-secret", helper.loadCredential(properties, "db.password"));
    }
}
