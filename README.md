# JEncrypt

General-purpose AES-256-GCM encryption library for Java with machine-specific key derivation.

## Features

- **AES-256-GCM Encryption**: Authenticated encryption with Galois/Counter Mode
- **Machine-Specific Keys**: Keys derived from hostname + user.home (PBKDF2-HMAC-SHA256)
- **Zero Dependencies**: Pure JDK implementation (Java 21)
- **Thread-Safe**: Safe for concurrent use
- **Backward Compatible**: Automatic plaintext detection and migration
- **Properties Integration**: Convenient helper for encrypted credentials in Properties files

## Maven Dependency

```xml
<dependency>
    <groupId>org.flossware</groupId>
    <artifactId>jencrypt</artifactId>
    <version>1.0</version>
</dependency>
```

### Repository Configuration

```xml
<repositories>
    <repository>
        <id>packagecloud-flossware</id>
        <name>packagecloud-flossware</name>
        <url>https://packagecloud.io/flossware/java/maven2/</url>
    </repository>
</repositories>
```

## Quick Start

### Basic Encryption

```java
AESEncryption encryption = new AESEncryption();

// Encrypt
String plaintext = "my-secret-password";
String encrypted = encryption.encrypt(plaintext);

// Decrypt
String decrypted = encryption.decrypt(encrypted);

// Check if encrypted
boolean isEncrypted = AESEncryption.isEncrypted(encrypted);
```

### Properties File Integration

```java
Properties props = new Properties();
AESEncryption encryption = new AESEncryption();
CredentialHelper helper = new CredentialHelper(encryption);

// Save encrypted credential
helper.saveCredential(props, "db.password", "secret123");

// Load and decrypt
String password = helper.loadCredential(props, "db.password");

// Check encryption status
boolean encrypted = helper.isCredentialEncrypted(props, "db.password");

// Migrate plaintext to encrypted
boolean migrated = helper.migrateToEncrypted(props, "old.password");
```

## Security

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Key Material**: Hostname + user.home system property
- **IV**: 12-byte random IV per encryption (prepended to ciphertext)
- **Authentication Tag**: 128-bit GCM tag prevents tampering
- **Encoding**: Base64 for storage compatibility

### Machine-Specific Encryption

Encrypted data cannot be decrypted on a different machine or user account:
- Keys are derived from hostname and user home directory
- Changing hostname invalidates all encrypted data
- Changing user account invalidates all encrypted data
- Credentials are tied to specific machine + user

## API Documentation

### AESEncryption

**Constructor:**
- `AESEncryption()` - Creates instance with machine-specific key

**Methods:**
- `String encrypt(String plaintext)` - Encrypts plaintext (returns Base64)
- `String decrypt(String encrypted)` - Decrypts ciphertext
- `static boolean isEncrypted(String value)` - Checks if value appears encrypted

**Thread Safety:** All methods are thread-safe.

### CredentialHelper

**Constructor:**
- `CredentialHelper(AESEncryption encryption)` - Creates helper with encryption instance

**Methods:**
- `void saveCredential(Properties props, String key, String value)` - Saves encrypted credential
- `String loadCredential(Properties props, String key)` - Loads and decrypts credential
- `boolean isCredentialEncrypted(Properties props, String key)` - Checks if credential is encrypted
- `void removeCredential(Properties props, String key)` - Removes credential
- `boolean migrateToEncrypted(Properties props, String key)` - Migrates plaintext to encrypted

**Backward Compatibility:** Automatically detects and handles plaintext values.

## Building from Source

```bash
# Clone repository
git clone https://github.com/FlossWare/jencrypt.git
cd jencrypt

# Build and test
mvn clean package

# Run tests with coverage
mvn test

# View coverage report
open target/site/jacoco/index.html
```

## Testing

- **Unit Tests**: 71 tests with 96% code coverage
- **Coverage Enforcement**: JaCoCo enforces minimum 96% coverage
- **Test Framework**: JUnit 5

```bash
mvn test
```

## Requirements

- Java 21+
- Maven 3.6+ (for building)

## License

See LICENSE file for details.

## Security Considerations

- Store encrypted files with appropriate file permissions (chmod 600)
- Use environment variables for most secure credential storage
- Machine-specific encryption is NOT suitable for:
  - Credentials that need to be shared across machines
  - Credentials in version control
  - Credentials that need to survive hostname changes
- This library is designed for local credential storage, not data-at-rest encryption for databases or files

## Version History

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Support

- Issues: https://github.com/FlossWare/jencrypt/issues
- Documentation: https://github.com/FlossWare/jencrypt
