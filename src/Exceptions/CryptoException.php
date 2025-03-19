<?php

declare(strict_types=1);

namespace CreativeWorld\Crypto\Exceptions;

class CryptoException extends \Exception
{
    public function __construct($message = "Cryptographic operation failed", $code = 0, ?\Throwable $previous = null) {
        parent::__construct($message, $code, $previous);
        $this->logError($message);
    }

    private function logError(string $message): void
    {
        // Log the error message to a file or monitoring system
        $logDir = dirname(__DIR__, 3) . '/logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        error_log(date('[Y-m-d H:i:s] ') . $message . PHP_EOL, 3, $logDir . '/crypto_errors.log');
    }
}