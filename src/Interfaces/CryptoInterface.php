<?php

namespace CreativeWorld\Crypto\Interfaces;

interface CryptoInterface
{
    public function encrypt(mixed $data, string $key): string;

    public function decrypt(string $data, string $key): mixed;

    public function generateToken(int $length = 32, bool $includeSpecialChars = true): string;

    public function hashPassword(string $password): string;

    public function verifyPassword(string $password, string $hashedPassword): bool;
}