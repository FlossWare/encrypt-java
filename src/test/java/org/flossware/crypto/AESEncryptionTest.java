package org.flossware.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Comprehensive tests for AESEncryption with 100% code coverage.
 */
class AESEncryptionTest {

    private AESEncryption encryption;

    @BeforeEach
    void setUp() {
        encryption = new AESEncryption();
    }

    // ========== Constructor Tests ==========

    @Test
    void testConstructorSucceeds() {
        assertDoesNotThrow(() -> new AESEncryption());
    }

    // ========== Encryption/Decryption Tests ==========

    @Test
    void testEncryptDecryptRoundTrip() {
        String plaintext = "my-secret-password";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptedValueIsDifferent() {
        String plaintext = "my-secret-password";

        String encrypted = encryption.encrypt(plaintext);

        assertNotEquals(plaintext, encrypted);
    }

    @Test
    void testEncryptedValueIsBase64() {
        String plaintext = "test-password";

        String encrypted = encryption.encrypt(plaintext);

        assertDoesNotThrow(() -> Base64.getDecoder().decode(encrypted));
    }

    @Test
    void testEncryptedValueIsLongerThanPlaintext() {
        String plaintext = "short";

        String encrypted = encryption.encrypt(plaintext);

        assertTrue(encrypted.length() > 32);
    }

    @Test
    void testEncryptGeneratesDifferentIVs() {
        String plaintext = "same-password";

        String encrypted1 = encryption.encrypt(plaintext);
        String encrypted2 = encryption.encrypt(plaintext);

        assertNotEquals(encrypted1, encrypted2);

        assertEquals(plaintext, encryption.decrypt(encrypted1));
        assertEquals(plaintext, encryption.decrypt(encrypted2));
    }

    @Test
    void testEncryptSpecialCharacters() {
        String plaintext = "p@ss:w0rd!#$%^&*(){}[]|\\<>?/~`";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptUnicodeCharacters() {
        String plaintext = "パスワード-密码-مرور";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptLongPassword() {
        String plaintext = "a".repeat(1000);

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptWhitespace() {
        String plaintext = "  password with spaces  ";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptSingleCharacter() {
        String plaintext = "a";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptNumbersOnly() {
        String plaintext = "1234567890";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptNewlines() {
        String plaintext = "line1\nline2\nline3";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptTabsAndControlCharacters() {
        String plaintext = "test\t\r\n";

        String encrypted = encryption.encrypt(plaintext);
        String decrypted = encryption.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    // ========== Error Handling Tests ==========

    @Test
    void testEncryptNullThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.encrypt(null)
        );
        assertTrue(exception.getMessage().contains("null or empty"));
    }

    @Test
    void testEncryptEmptyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.encrypt("")
        );
        assertTrue(exception.getMessage().contains("null or empty"));
    }

    @Test
    void testDecryptNullThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.decrypt(null)
        );
        assertTrue(exception.getMessage().contains("null or empty"));
    }

    @Test
    void testDecryptEmptyThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.decrypt("")
        );
        assertTrue(exception.getMessage().contains("null or empty"));
    }

    @Test
    void testDecryptInvalidBase64Throws() {
        String invalidBase64 = "not-valid-base64!!!";

        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
            encryption.decrypt(invalidBase64)
        );
        assertTrue(exception.getMessage().contains("Decryption failed"));
    }

    @Test
    void testDecryptCorruptedCiphertextThrows() {
        String encrypted = encryption.encrypt("test");
        String corrupted = encrypted.substring(0, encrypted.length() - 5) + "XXXXX";

        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
            encryption.decrypt(corrupted)
        );
        assertTrue(exception.getMessage().contains("Decryption failed"));
    }

    @Test
    void testDecryptTooShortThrows() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[10]);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
            encryption.decrypt(tooShort)
        );
        assertTrue(exception.getMessage().contains("Decryption failed"));
    }

    // ========== isEncrypted() Tests ==========

    @Test
    void testIsEncryptedWithValidEncryptedValue() {
        String encrypted = encryption.encrypt("test-password");

        assertTrue(AESEncryption.isEncrypted(encrypted));
    }

    @Test
    void testIsEncryptedWithPlaintextPassword() {
        String plaintext = "my-plaintext-password";

        assertFalse(AESEncryption.isEncrypted(plaintext));
    }

    @Test
    void testIsEncryptedWithNull() {
        assertFalse(AESEncryption.isEncrypted(null));
    }

    @Test
    void testIsEncryptedWithEmpty() {
        assertFalse(AESEncryption.isEncrypted(""));
    }

    @Test
    void testIsEncryptedWithShortString() {
        String shortString = "abc123";

        assertFalse(AESEncryption.isEncrypted(shortString));
    }

    @Test
    void testIsEncryptedWithNonBase64() {
        String nonBase64 = "this-contains-invalid-base64-characters!!!";

        assertFalse(AESEncryption.isEncrypted(nonBase64));
    }

    @Test
    void testIsEncryptedWithValidBase64LongEnough() {
        byte[] randomData = new byte[40];
        Arrays.fill(randomData, (byte) 0xFF);
        String validBase64 = Base64.getEncoder().encodeToString(randomData);

        assertTrue(AESEncryption.isEncrypted(validBase64));
    }

    @Test
    void testIsEncryptedWithBase64TooShort() {
        byte[] shortData = new byte[20];
        String shortBase64 = Base64.getEncoder().encodeToString(shortData);

        assertFalse(AESEncryption.isEncrypted(shortBase64));
    }

    // ========== Machine-Specific Key Tests ==========

    @Test
    void testSameInstanceCanDecrypt() {
        AESEncryption enc = new AESEncryption();

        String plaintext = "test-password";
        String encrypted = enc.encrypt(plaintext);
        String decrypted = enc.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testDifferentInstanceSameMachineCanDecrypt() {
        AESEncryption enc1 = new AESEncryption();
        AESEncryption enc2 = new AESEncryption();

        String plaintext = "test-password";
        String encrypted = enc1.encrypt(plaintext);
        String decrypted = enc2.decrypt(encrypted);

        assertEquals(plaintext, decrypted);
    }

    // ========== Exception Message Coverage ==========

    @Test
    void testEncryptNullContainsRelevantMessage() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.encrypt(null)
        );
        assertTrue(exception.getMessage().contains("Cannot encrypt null or empty plaintext"));
    }

    @Test
    void testDecryptNullContainsRelevantMessage() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
            encryption.decrypt(null)
        );
        assertTrue(exception.getMessage().contains("Cannot decrypt null or empty value"));
    }

    @Test
    void testDecryptFailureContainsRelevantMessage() {
        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
            encryption.decrypt("invalid")
        );
        assertTrue(exception.getMessage().contains("corrupted") ||
                   exception.getMessage().contains("tampered") ||
                   exception.getMessage().contains("different machine"));
    }

    // ========== Exception Coverage Tests ==========

    @Test
    void testEncryptFailureWhenKeyIsCorrupted() throws Exception {
        AESEncryption enc = new AESEncryption();

        // Use reflection to corrupt the secret key field
        var keyField = AESEncryption.class.getDeclaredField("secretKey");
        keyField.setAccessible(true);
        keyField.set(enc, null);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
            enc.encrypt("test")
        );
        assertTrue(exception.getMessage().contains("Encryption failed"));
    }
}
