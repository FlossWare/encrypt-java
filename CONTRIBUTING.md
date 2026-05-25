# Contributing to JEncrypt

Thank you for your interest in contributing to JEncrypt! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the project and community

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/FlossWare/jencrypt/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce the problem
   - Expected vs actual behavior
   - Java version and platform (OS)
   - Code samples if applicable

### Suggesting Enhancements

1. Check if the enhancement has already been suggested
2. Create a new issue with:
   - Clear description of the enhancement
   - Use cases and benefits
   - Potential implementation approach (optional)

### Pull Requests

1. **Fork the repository** and create a branch from `main`
2. **Write code** following our coding standards (see below)
3. **Write tests** - all new code must have tests with 96%+ coverage
4. **Run tests** - ensure all tests pass: `mvn test`
5. **Update documentation** - update README.md if changing public APIs
6. **Commit** - write clear, descriptive commit messages
7. **Submit PR** - provide a clear description of changes

## Coding Standards

### Code Quality Requirements

**CRITICAL - These are enforced by Maven and will fail the build:**

1. **No Wildcard Imports**
   ```java
   // ✅ Good
   import java.util.Properties;
   import java.util.List;
   
   // ❌ Bad - will fail build
   import java.util.*;
   ```

2. **96% Code Coverage Minimum**
   - All new code must be tested
   - Run `mvn test` to check coverage
   - View report: `target/site/jacoco/index.html`

3. **X.Y Version Format Only**
   - Versions must be `X.Y` format (e.g., 1.0, 1.1, 2.0)
   - No `-SNAPSHOT` or other suffixes
   - Enforced by maven-enforcer-plugin

### Java Conventions

- **Java Version**: Java 21
- **Naming**:
  - Classes: PascalCase
  - Methods: camelCase
  - Constants: UPPER_SNAKE_CASE
  - Packages: lowercase
- **Formatting**:
  - 4 spaces for indentation (no tabs)
  - Max line length: 120 characters
  - Opening braces on same line
- **Javadoc**:
  - All public classes and methods must have Javadoc
  - Include `@param`, `@return`, `@throws` as applicable
  - Provide usage examples for public APIs

### Example Code Style

```java
/**
 * Encrypts plaintext using AES-256-GCM.
 * <p>
 * Each call generates a random IV, ensuring different ciphertexts
 * for identical plaintexts.
 * </p>
 *
 * @param plaintext the value to encrypt (must not be null or empty)
 * @return base64-encoded IV + ciphertext + authentication tag
 * @throws IllegalArgumentException if plaintext is null or empty
 * @throws IllegalStateException if encryption fails
 */
public String encrypt(String plaintext) {
    if (plaintext == null || plaintext.isEmpty()) {
        throw new IllegalArgumentException("Cannot encrypt null or empty plaintext");
    }
    // ... implementation
}
```

## Testing Guidelines

### Test Requirements

1. **Unit Tests**: All methods must have unit tests
2. **Edge Cases**: Test null, empty, boundary values
3. **Error Cases**: Test all exception paths
4. **Integration**: Test interaction between components
5. **Thread Safety**: Test concurrent access where applicable

### Test Naming

```java
@Test
void testMethodName_whenCondition_thenExpectedBehavior() {
    // Arrange
    AESEncryption encryption = new AESEncryption();
    
    // Act
    String result = encryption.encrypt("test");
    
    // Assert
    assertTrue(AESEncryption.isEncrypted(result));
}
```

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=AESEncryptionTest

# Run with coverage report
mvn clean test
open target/site/jacoco/index.html
```

## Security Considerations

- **Never commit secrets**: No passwords, API keys, or tokens in code
- **Validate inputs**: Always validate method parameters
- **Document security implications**: Note machine-specific encryption behavior
- **Use secure defaults**: AES-256-GCM, PBKDF2 with 100K iterations

## Documentation

- **README.md**: Update for new features or API changes
- **CHANGELOG.md**: Document all changes (Added/Changed/Removed/Fixed)
- **Javadoc**: Keep in sync with code
- **Code comments**: Only when WHY is non-obvious (not WHAT)

## Build and Release Process

### Local Build

```bash
mvn clean package
```

### Local Install

```bash
mvn clean install
```

### Version Management

- Versions are auto-incremented by CI/CD on merge to main
- Format: X.Y (e.g., 1.0 → 1.1 → 1.2)
- No manual version changes needed

### CI/CD Pipeline

On push to `main`:
1. Build and test
2. Check coverage (must be ≥96%)
3. Package JAR
4. Deploy to packagecloud.io
5. Auto-increment version (Y++)
6. Commit version bump with `[ci skip]`

## Questions?

- Open an issue for questions about contributing
- Check existing issues and PRs for similar discussions
- Review code and tests for examples

## License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v3.0.
