# Crypto

## Overview

Crypto provides a robust and secure way to handle cryptographic operations in your PHP applications. It includes a `CryptoModel` class that offers methods for encryption, decryption, token generation, and password hashing. This package is designed to be easy to use while ensuring high security standards.

## Features

- **Encryption and Decryption**: Securely encrypt and decrypt data using industry-standard algorithms.
- **Token Generation**: Generate secure tokens for session management or API authentication.
- **Password Hashing**: Hash passwords securely and verify them with ease.
- **Custom Exception Handling**: Utilize the `CryptoException` class for handling cryptographic errors.

## Installation

You can install the package via Composer. Run the following command in your terminal:

```
composer require creative-world/crypto
```

## Usage

### Basic Example

```php
use CreativeWorld\Crypto\CryptoModel;

$crypto = new CryptoModel();

// Encrypt data
$encryptedData = $crypto->encrypt('Sensitive Data', 'your-key');

// Decrypt data
$decryptedData = $crypto->decrypt($encryptedData, 'your-key');

// Generate a secure token
$token = $crypto->generateToken();

// Hash a password
$hashedPassword = $crypto->hashPassword('your-password');

// Verify a password
$isPasswordValid = $crypto->verifyPassword('your-password', $hashedPassword);
```

## Testing

To run the tests for this package, ensure you have PHPUnit installed. You can run the tests using the following command:

```
vendor/bin/phpunit
```

## License

This package is licensed under the MIT License. See the LICENSE file for more details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.