<?php

declare(strict_types=1);

namespace CreativeWorld\Crypto;

use CreativeWorld\Crypto\Exceptions\CryptoException;
use CreativeWorld\Crypto\Interfaces\CryptoInterface;
use SodiumException;
use RuntimeException;
use InvalidArgumentException;
use Throwable;

class CryptoModel implements CryptoInterface
{
    private const KEY_LENGTH = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;
    private const NONCE_LENGTH = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
    private const MIN_LIBSODIUM_VERSION = '1.0.18';
    private const FORMAT_VERSION = 1;
    private const PWHASH_OPSLIMIT = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
    private const PWHASH_MEMLIMIT = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
    
    private array $sensitiveVars = [];
    private array $keyCache = [];

    public function __construct()
    {
        if (!extension_loaded('sodium')) {
            throw new CryptoException('Sodium extension is not loaded');
        }
        
        if (version_compare(SODIUM_LIBRARY_VERSION, self::MIN_LIBSODIUM_VERSION, '<')) {
            throw new CryptoException('Outdated libsodium version. Update to ' . self::MIN_LIBSODIUM_VERSION . ' or newer');
        }
    }

    public function encrypt(mixed $data, string $key): string
    {
        try {
            if (empty($key)) {
                throw new InvalidArgumentException('Encryption key cannot be empty');
            }

            $serialized = false;
            if (!is_string($data)) {
                $data = serialize($data);
                $serialized = true;
            }

            $keyId = $this->getKeyId($key);
            $derivedKey = $this->deriveKey($key);

            $nonce = random_bytes(self::NONCE_LENGTH);
            $this->trackVar($nonce);

            $dataToEncrypt = ($serialized ? '1:' : '0:') . $data;

            $encrypted = sodium_crypto_secretbox($dataToEncrypt, $nonce, $derivedKey);
            $this->trackVar($encrypted);

            $salt = $this->getKeySalt($keyId);
            $result = pack('C', self::FORMAT_VERSION) . $salt . $nonce . $encrypted;

            return sodium_bin2base64($result, SODIUM_BASE64_VARIANT_ORIGINAL);
        } catch (InvalidArgumentException $e) {
            throw new CryptoException('Encryption error: ' . $e->getMessage(), 0, $e);
        } catch (Throwable $e) {
            $this->cleanSensitiveVars();
            throw new CryptoException('Encryption error: ' . $e->getMessage(), 0, $e);
        }
    }

    public function decrypt(string $encryptedData, string $key): mixed
    {
        try {
            if (empty($key) || empty($encryptedData)) {
                throw new InvalidArgumentException('Key and encrypted data cannot be empty');
            }

            $decoded = sodium_base642bin($encryptedData, SODIUM_BASE64_VARIANT_ORIGINAL, '');
            $this->trackVar($decoded);

            $version = ord($decoded[0]);
            if ($version !== self::FORMAT_VERSION) {
                throw new CryptoException("Unsupported encrypted data format version: $version");
            }
            
            $salt = substr($decoded, 1, SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $nonce = substr($decoded, 1 + SODIUM_CRYPTO_PWHASH_SALTBYTES, self::NONCE_LENGTH);
            $ciphertext = substr($decoded, 1 + SODIUM_CRYPTO_PWHASH_SALTBYTES + self::NONCE_LENGTH);
            
            $this->trackVar($salt);
            $this->trackVar($nonce);
            $this->trackVar($ciphertext);

            $derivedKey = $this->deriveKeyWithSalt($key, $salt);
            $this->trackVar($derivedKey);

            $decrypted = sodium_crypto_secretbox_open($ciphertext, $nonce, $derivedKey);
            if ($decrypted === false) {
                throw new CryptoException('Decryption failed. Invalid key or corrupted data.');
            }
            $this->trackVar($decrypted);

            if (strlen($decrypted) > 2 && in_array($decrypted[0], ['0', '1']) && $decrypted[1] === ':') {
                $isSerialized = ($decrypted[0] === '1');
                $decrypted = substr($decrypted, 2);
                
                if ($isSerialized) {
                    return unserialize($decrypted, ['allowed_classes' => true]);
                }
            }

            return $decrypted;
        } catch (InvalidArgumentException $e) {
            throw new CryptoException('Decryption error: ' . $e->getMessage(), 0, $e);
        } catch (Throwable $e) {
            $this->cleanSensitiveVars();
            throw new CryptoException('Decryption error: ' . $e->getMessage(), 0, $e);
        }
    }

    public function generateToken(int $length = 32, bool $includeSpecialChars = true): string
    {
        if ($length < 16) {
            throw new InvalidArgumentException('Token length must be at least 16 characters for security');
        }
        
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        if ($includeSpecialChars) {
            $chars .= '!@#$%^&*()-_=+[]{}|;:,.<>?';
        }
        
        try {
            $randomBytes = random_bytes($length);
            $this->trackVar($randomBytes);
            
            $token = '';
            $charCount = strlen($chars);
            for ($i = 0; $i < $length; $i++) {
                $randomValue = ord($randomBytes[$i]);
                $token .= $chars[$randomValue % $charCount];
            }
            
            $this->trackVar($token);
            return $token;
        } catch (Throwable $e) {
            $this->cleanSensitiveVars();
            throw new CryptoException('Token generation error: ' . $e->getMessage(), 0, $e);
        }
    }

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 1,
        ]);
    }

    public function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    private function getKeyId(string $key): string
    {
        return sodium_crypto_generichash($key, '', 16);
    }
    
    private function getKeySalt(string $keyId): string
    {
        if (!isset($this->keyCache[$keyId]['salt'])) {
            $this->keyCache[$keyId]['salt'] = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        }
        return $this->keyCache[$keyId]['salt'];
    }
    
    private function deriveKey(string $key): string
    {
        $keyId = $this->getKeyId($key);
        
        if (!isset($this->keyCache[$keyId]['key'])) {
            $salt = $this->getKeySalt($keyId);
            $this->keyCache[$keyId]['key'] = $this->deriveKeyWithSalt($key, $salt);
        }
        
        return $this->keyCache[$keyId]['key'];
    }
    
    private function deriveKeyWithSalt(string $key, string $salt): string
    {
        $derivedKey = sodium_crypto_pwhash(
            self::KEY_LENGTH,
            $key,
            $salt,
            self::PWHASH_OPSLIMIT,
            self::PWHASH_MEMLIMIT
        );
        $this->trackVar($derivedKey);
        return $derivedKey;
    }

    private function isSerialized(string $data): bool
    {
        return $data === 'N;' || preg_match('/^[aOisbdNCv]:[0-9]+:/s', $data);
    }
    
    private function trackVar(&$var): void
    {
        $this->sensitiveVars[] = &$var;
    }
    
    private function cleanSensitiveVars(): void
    {
        foreach ($this->sensitiveVars as &$var) {
            if (is_string($var)) {
                sodium_memzero($var);
            }
        }
        $this->sensitiveVars = [];
    }

    public function __destruct()
    {
        foreach ($this->keyCache as &$item) {
            if (isset($item['key'])) {
                sodium_memzero($item['key']);
            }
        }
        
        $this->cleanSensitiveVars();
    }
}