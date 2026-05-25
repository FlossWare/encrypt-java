# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0] - 2026-05-24

### Added
- Initial release of JEncrypt library
- AESEncryption class for general-purpose AES-256-GCM encryption
- CredentialHelper class for Properties file integration
- Machine-specific key derivation (hostname + user.home)
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
- 12-byte random IV per encryption
- 128-bit GCM authentication tag
- Base64 encoding for storage compatibility
- Thread-safe encryption/decryption
- Backward compatibility with plaintext values
- Automatic plaintext migration support
- 71 comprehensive unit tests
- 96% code coverage enforcement via JaCoCo
- X.Y version format enforcement via maven-enforcer-plugin
- Zero runtime dependencies (pure JDK)

### Security
- AES-256-GCM authenticated encryption prevents tampering
- Machine-specific keys prevent cross-machine decryption
- Random IV ensures different ciphertexts for same plaintext
- PBKDF2 key derivation adds computational cost to brute-force attacks

### Documentation
- Comprehensive README with usage examples
- Javadoc for all public API methods
- Security considerations and limitations
- Building and testing instructions
