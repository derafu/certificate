<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate\Service;

use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\TranslatableMessage;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * Service that calls OpenSSL.
 *
 * It is the only place of this package that calls the functions of OpenSSL (a
 * test checks it).
 *
 * The queue of errors of OpenSSL belongs to the process, not to the call:
 * another call, of this process, can leave errors in it, even a call that did
 * not fail (a signature that is not valid is a result, and leaves errors). So
 * each call is done in its own scope: the queue is emptied before, the warnings
 * of PHP are taken, and the queue is emptied after. What is in the errors of an
 * exception is what its call left.
 */
final class OpenSsl implements OpenSslInterface
{
    /**
     * {@inheritDoc}
     */
    public function pkeyNew(?array $options = null): OpenSSLAsymmetricKey
    {
        $errors = [];
        $key = $this->scope(static fn () => openssl_pkey_new($options), $errors);

        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new CertificateException('OpenSSL could not generate the private key.', errors: $errors);
        }

        return $key;
    }

    /**
     * {@inheritDoc}
     */
    public function pkeyGetPrivate(string $privateKey, ?string $passphrase = null): OpenSSLAsymmetricKey
    {
        $errors = [];
        $key = $this->scope(
            static fn () => openssl_pkey_get_private($privateKey, $passphrase),
            $errors
        );

        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new CertificateException('OpenSSL could not read the private key.', errors: $errors);
        }

        return $key;
    }

    /**
     * {@inheritDoc}
     */
    public function pkeyGetPublic(string $certificate): OpenSSLAsymmetricKey
    {
        $errors = [];
        $key = $this->scope(static fn () => openssl_pkey_get_public($certificate), $errors);

        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new CertificateException('OpenSSL could not read the public key.', errors: $errors);
        }

        return $key;
    }

    /**
     * {@inheritDoc}
     */
    public function pkeyGetDetails(OpenSSLAsymmetricKey $key): array
    {
        $errors = [];
        $details = $this->scope(static fn () => openssl_pkey_get_details($key), $errors);

        if ($details === false) {
            throw new CertificateException('OpenSSL could not read the details of the key.', errors: $errors);
        }

        /** @var array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int} */
        return $details;
    }

    /**
     * {@inheritDoc}
     */
    public function x509Parse(string $certificate): array
    {
        $errors = [];
        $data = $this->scope(static fn () => openssl_x509_parse($certificate), $errors);

        if ($data === false) {
            throw new CertificateException('OpenSSL could not read the data of the certificate.', errors: $errors);
        }

        /** @var array{name: string, subject: array<string, string|list<string>>, hash: string, issuer: array<string, string|list<string>>, version: int, serialNumber: string, serialNumberHex: string, validFrom: string, validTo: string, validFrom_time_t: int, validTo_time_t: int, signatureTypeSN: string, signatureTypeLN: string, signatureTypeNID: int, purposes: array<int, array{bool, bool, string}>, extensions?: array<string, string>} */
        return $data;
    }

    /**
     * {@inheritDoc}
     */
    public function csrNew(array $subject, OpenSSLAsymmetricKey $privateKey): OpenSSLCertificateSigningRequest
    {
        $errors = [];
        $csr = $this->scope(static fn () => openssl_csr_new($subject, $privateKey), $errors);

        if (!$csr instanceof OpenSSLCertificateSigningRequest) {
            throw new CertificateException(
                'OpenSSL could not generate the certificate signing request.',
                errors: $errors
            );
        }

        return $csr;
    }

    /**
     * {@inheritDoc}
     */
    public function csrSign(
        OpenSSLCertificateSigningRequest $csr,
        ?OpenSSLCertificate $caCertificate,
        OpenSSLAsymmetricKey $privateKey,
        int $days,
        array $options = [],
        int $serial = 0
    ): OpenSSLCertificate {
        $errors = [];
        $certificate = $this->scope(
            static fn () => openssl_csr_sign($csr, $caCertificate, $privateKey, $days, $options, $serial),
            $errors
        );

        if (!$certificate instanceof OpenSSLCertificate) {
            throw new CertificateException(
                'OpenSSL could not sign the certificate signing request.',
                errors: $errors
            );
        }

        return $certificate;
    }

    /**
     * {@inheritDoc}
     */
    public function pkcs12Read(string $data, string $password): array
    {
        $certificates = [];
        $errors = [];
        $result = $this->scope(
            static function () use ($data, &$certificates, $password) {
                return openssl_pkcs12_read($data, $certificates, $password);
            },
            $errors
        );

        if ($result === false) {
            throw new CertificateException('OpenSSL could not read the PKCS#12.', errors: $errors);
        }

        /** @var array{cert: string, pkey: string, extracerts?: list<string>} */
        return $certificates;
    }

    /**
     * {@inheritDoc}
     */
    public function pkcs12Export(
        OpenSSLCertificate|string $certificate,
        OpenSSLAsymmetricKey|string $privateKey,
        string $password,
        array $options = []
    ): string {
        $output = '';
        $errors = [];
        $result = $this->scope(
            static function () use ($certificate, &$output, $privateKey, $password, $options) {
                return openssl_pkcs12_export($certificate, $output, $privateKey, $password, $options);
            },
            $errors
        );

        if ($result === false) {
            throw new CertificateException('OpenSSL could not export the PKCS#12.', errors: $errors);
        }

        return $output;
    }

    /**
     * {@inheritDoc}
     */
    public function sign(string $data, string $privateKey, string|int $algorithm): string
    {
        $signature = '';
        $errors = [];
        $result = $this->scope(
            static function () use ($data, &$signature, $privateKey, $algorithm) {
                return openssl_sign($data, $signature, $privateKey, $algorithm);
            },
            $errors
        );

        if ($result === false) {
            throw new CertificateException('OpenSSL could not sign the data.', errors: $errors);
        }

        return $signature;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $data, string $signature, string $certificate, string|int $algorithm): bool
    {
        $errors = [];
        $result = $this->scope(
            static fn () => openssl_verify($data, $signature, $certificate, $algorithm),
            $errors
        );

        // `1` is a signature that is correct, `0` one that is not (both are
        // results), and `-1` or `false` is that the verification failed.
        if ($result === false || $result === -1) {
            throw new CertificateException('OpenSSL could not verify the signature.', errors: $errors);
        }

        return $result === 1;
    }

    /**
     * Does a call to OpenSSL in its own scope.
     *
     * The queue of errors is emptied before the call, the warnings of PHP are
     * taken (they are not emitted) and the queue is emptied after the call,
     * also when the call did not fail.
     *
     * @template T
     * @param callable(): T $call The call to OpenSSL.
     * @param array<array-key, mixed> $errors The errors of this call, the
     * warnings of PHP and the errors of OpenSSL.
     * @param-out list<TranslatableInterface> $errors
     * @return T The result of the call.
     */
    private function scope(callable $call, array &$errors): mixed
    {
        $this->takeErrors();

        $warnings = [];
        set_error_handler(function (int $number, string $message) use (&$warnings): bool {
            $warnings[] = $this->untranslated($message);

            return true;
        });

        try {
            $result = $call();
        } finally {
            restore_error_handler();
            $errors = [...$warnings, ...$this->takeErrors()];
        }

        return $result;
    }

    /**
     * Takes the errors that are in the queue of OpenSSL, emptying it.
     *
     * @return list<TranslatableInterface>
     */
    private function takeErrors(): array
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $this->explain($error);
        }

        return $errors;
    }

    /**
     * Explains an error of OpenSSL, if it is a known one.
     *
     * An error that is known is a message of the catalogue, translatable, with
     * the code of the error. Any other is the text of OpenSSL as it is: it has
     * no translation.
     *
     * Each known error is written here, as a message, and not in a list of
     * texts, so the audit of the translations reads them: that every one has its
     * translation, and that none is left over, is checked.
     */
    private function explain(string $error): TranslatableInterface
    {
        if (preg_match('/error:([0-9A-Fa-f]{8}):/', $error, $matches) !== 1) {
            return $this->untranslated($error);
        }

        $code = strtoupper($matches[1]);

        return match ($code) {
            '0308010C' => new TranslatableMessage(
                'Unsupported encryption algorithm or method (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '11800071' => new TranslatableMessage(
                'MAC verification failed in PKCS12, certificate or password is incorrect (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '0906D06C' => new TranslatableMessage(
                'Failed to load X.509 certificate (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '0B080074' => new TranslatableMessage(
                'Invalid PEM format (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '0A000086' => new TranslatableMessage(
                'Key length not allowed (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '06065064' => new TranslatableMessage(
                'Private key error: incorrect password (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '14094418' => new TranslatableMessage(
                'SSL layer error: invalid certificate or CA not known (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '14090086' => new TranslatableMessage(
                'SSL configuration error: certificate or key problem (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '0907B068' => new TranslatableMessage(
                'Error in reading a certificate file (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            '1403100E' => new TranslatableMessage(
                'SSL error: incompatible protocol (Error #{code}).',
                ['code' => $code],
                domain: 'errors'
            ),
            default => $this->untranslated($error),
        };
    }

    /**
     * A text of OpenSSL or of PHP that has no translation, as it is.
     *
     * The text is a parameter and never the pattern of the message: it can have
     * braces or quotes that ICU would take as part of a pattern.
     */
    private function untranslated(string $text): TranslatableInterface
    {
        return new TranslatableMessage('OpenSSL: {text}', ['text' => $text], domain: 'errors');
    }
}
