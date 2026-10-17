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
 * The errors that explain it (the ones of OpenSSL) are data that it carries,
 * and are the ones that it receives: it does not read them from anywhere,
 * because the queue of errors of OpenSSL belongs to the process and not to the
 * exception (see `Derafu\Certificate\Service\OpenSsl`).
 */
class CertificateException extends Exception
{
    /**
     * Constructor of the exception.
     *
     * @param string|array<int|string, mixed>|TranslatableInterface $message The
     * exception message, as it is given to a translatable exception.
     * @param int $code The exception code (optional).
     * @param Throwable|null $previous The previous exception (optional).
     * @param list<TranslatableInterface> $errors The errors that explain the
     * exception (optional). Each one is a translatable message: it is text in
     * English as it is, and in the language of a translator with `trans()`.
     */
    public function __construct(
        string|array|TranslatableInterface $message,
        int $code = 0,
        ?Throwable $previous = null,
        private readonly array $errors = []
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Gets the errors that explain the exception.
     *
     * @return list<TranslatableInterface> The errors, as translatable messages
     * (`(string)` gives them in English, `trans()` in the language of a
     * translator).
     */
    public function getErrors(): array
    {
        return $this->errors;
    }
}
