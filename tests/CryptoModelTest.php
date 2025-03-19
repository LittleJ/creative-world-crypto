<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use CreativeWorld\Crypto\CryptoModel;
use CreativeWorld\Crypto\Exceptions\CryptoException;

class CryptoModelTest extends TestCase
{
    protected $cryptoModel;

    protected function setUp(): void
    {
        $this->cryptoModel = new CryptoModel();
    }

    public function testEncrypt()
    {
        $plaintext = "Hello, World!";
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($plaintext, $key);
        $this->assertNotEquals($plaintext, $encrypted);
    }

    public function testDecrypt()
    {
        $plaintext = "Hello, World!";
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($plaintext, $key);
        $decrypted = $this->cryptoModel->decrypt($encrypted, $key);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptWithEmptyKey()
    {
        $this->expectException(CryptoException::class);
        $this->cryptoModel->encrypt("Hello, World!", "");
    }
    
    public function testDecryptWithEmptyKey()
    {
        $this->expectException(CryptoException::class);
        $this->cryptoModel->decrypt("encryptedData", "");
    }
    
    public function testDecryptWithEmptyData()
    {
        $this->expectException(CryptoException::class);
        $this->cryptoModel->decrypt("", "securekey");
    }

    public function testGenerateToken()
    {
        $token = $this->cryptoModel->generateToken();
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testGenerateTokenWithLength()
    {
        $length = 64;
        $token = $this->cryptoModel->generateToken($length);
        $this->assertIsString($token);
        $this->assertEquals($length, strlen($token));
    }

    public function testGenerateTokenWithSpecialChars()
    {
        $token = $this->cryptoModel->generateToken(32, true);
        $this->assertMatchesRegularExpression('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/', $token);
    }

    public function testGenerateTokenWithoutSpecialChars()
    {
        $token = $this->cryptoModel->generateToken(32, false);
        $this->assertDoesNotMatchRegularExpression('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/', $token);
    }

    public function testHashPassword()
    {
        $password = "securepassword";
        $hashed = $this->cryptoModel->hashPassword($password);
        $this->assertNotEquals($password, $hashed);
    }

    public function testVerifyPassword()
    {
        $password = "securepassword";
        $hashed = $this->cryptoModel->hashPassword($password);
        $this->assertTrue($this->cryptoModel->verifyPassword($password, $hashed));
        $this->assertFalse($this->cryptoModel->verifyPassword("wrongpassword", $hashed));
    }

    public function testEncryptDecryptWithArray()
    {
        $data = ["key" => "value"];
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($data, $key);
        $decrypted = $this->cryptoModel->decrypt($encrypted, $key);
        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptDecryptWithObject()
    {
        $data = (object)["key" => "value"];
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($data, $key);
        $decrypted = $this->cryptoModel->decrypt($encrypted, $key);
        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptDecryptWithInvalidKey()
    {
        $this->expectException(CryptoException::class);
        $plaintext = "Hello, World!";
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($plaintext, $key);
        $this->cryptoModel->decrypt($encrypted, "wrongkey");
    }

    public function testDecryptWithCorruptedData()
    {
        $this->expectException(CryptoException::class);
        $plaintext = "Hello, World!";
        $key = "securekey";
        $encrypted = $this->cryptoModel->encrypt($plaintext, $key);
        $corruptedEncrypted = $encrypted . "corruption";
        $this->cryptoModel->decrypt($corruptedEncrypted, $key);
    }

    public function testGenerateTokenWithShortLength()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->cryptoModel->generateToken(8);
    }
}