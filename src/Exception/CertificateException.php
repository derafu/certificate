<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate\Exception;

use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\Exception\Core\TranslatableException as Exception;
use Throwable;

/**
 * Custom exception for digital certificate errors.
 *
 * It is a translatable exception like any other: what it says is its message.
 * The errors that explain it (the ones of OpenSSL) are data that it carries.
 */
class CertificateException extends Exception
{
    /**
     * Errors of OpenSSL that are known, translated to a message that a human
     * understands.
     *
     * NOTE: The messages end without a period on purpose because the error
     * code is added between parentheses at the end, and then the period.
     */
    private const array OPENSSL_ERRORS = [
        '0308010C' => 'Unsupported encryption algorithm or method',
        '11800071' => 'MAC verification failed in PKCS12, certificate or password is incorrect',
        '0906D06C' => 'Failed to load X.509 certificate',
        '0B080074' => 'Invalid PEM format',
        '0A000086' => 'Key length not allowed',
        '06065064' => 'Private key error: incorrect password',
        '14094418' => 'SSL layer error: invalid certificate or CA not known',
        '14090086' => 'SSL configuration error: certificate or key problem',
        '0907B068' => 'Error in reading a certificate file',
        '1403100E' => 'SSL error: incompatible protocol',
    ];

    /**
     * Constructor of the exception.
     *
     * @param string|array<int|string, mixed>|TranslatableInterface $message The
     * exception message, as it is given to a translatable exception.
     * @param int $code The exception code (optional).
     * @param Throwable|null $previous The previous exception (optional).
     * @param list<string> $errors The errors that explain the exception, as
     * text (optional). If they are not given, the pending errors of OpenSSL are
     * taken.
     */
    public function __construct(
        string|array|TranslatableInterface $message,
        int $code = 0,
        ?Throwable $previous = null,
        private array $errors = []
    ) {
        if ($this->errors === []) {
            $this->errors = self::opensslErrors();
        }

        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the errors that explain the exception.
     *
     * @return list<string> The errors, as text.
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Takes the pending errors of OpenSSL.
     *
     * The known ones are translated to a message that a human understands,
     * followed by the code of the error.
     *
     * @return list<string> The errors, as text.
     */
    public static function opensslErrors(): array
    {
        $errors = [];
        while (($error = openssl_error_string()) !== false) {
            foreach (self::OPENSSL_ERRORS as $code => $text) {
                if (str_contains($error, 'error:' . $code)) {
                    $error = sprintf('%s (Error #%s).', $text, $code);
                }
            }
            $errors[] = $error;
        }

        return $errors;
    }
}
