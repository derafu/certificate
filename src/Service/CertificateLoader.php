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

use Derafu\Certificate\Certificate;
use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Contract\CertificateLoaderInterface;
use Derafu\Certificate\Exception\CertificateException;

/**
 * Class that handles the configuration and loading of digital certificates.
 */
final class CertificateLoader implements CertificateLoaderInterface
{
    /**
     * {@inheritDoc}
     */
    public function loadFromFile(
        string $filepath,
        string $password
    ): CertificateInterface {
        if (!is_readable($filepath)) {
            throw new CertificateException([
                'It was not possible to read the digital certificate file from {path}',
                'path' => $filepath,
            ]);
        }

        $data = file_get_contents($filepath);
        if ($data === false) {
            throw new CertificateException([
                'It was not possible to read the digital certificate file from {path}',
                'path' => $filepath,
            ]);
        }

        return self::loadFromData($data, $password);
    }

    /**
     * {@inheritDoc}
     */
    public function loadFromData(
        string $data,
        string $password
    ): CertificateInterface {
        $certs = [];

        if (openssl_pkcs12_read($data, $certs, $password) === false) {
            $errors = CertificateException::opensslErrors();

            throw new CertificateException(
                $errors === []
                    ? 'It was not possible to read the digital certificate data.'
                    : ['It was not possible to read the digital certificate data. {errors}', 'errors' => implode(' ', $errors)],
                errors: $errors
            );
        }

        return self::loadFromKeys(
            $certs['cert'],
            $certs['pkey'],
            $certs['extracerts'] ?? []
        );
    }

    /**
     * {@inheritDoc}
     */
    public function loadFromArray(array $data): CertificateInterface
    {
        $certificate = $data['cert'] ?? $data['certificate'] ?? null;
        $privateKey = $data['pkey'] ?? $data['privateKey'] ?? null;
        $chain = $data['chain'] ?? $data['extracerts'] ?? [];

        if ($certificate === null) {
            throw new CertificateException(
                'The certificate was not found.'
            );
        }

        if ($privateKey === null) {
            throw new CertificateException(
                'The private key of the certificate was not found.'
            );
        }

        if (!is_string($certificate)) {
            throw new CertificateException(
                'The certificate must be a text.'
            );
        }

        if (!is_string($privateKey)) {
            throw new CertificateException(
                'The private key of the certificate must be a text.'
            );
        }

        if (!is_array($chain) || array_filter($chain, is_string(...)) !== $chain) {
            throw new CertificateException(
                'The chain of the certificate must contain only texts.'
            );
        }

        return self::loadFromKeys($certificate, $privateKey, $chain);
    }

    /**
     * {@inheritDoc}
     */
    public function loadFromKeys(
        string $certificate,
        string $privateKey,
        array $chain = []
    ): CertificateInterface {
        return new Certificate($certificate, $privateKey, $chain);
    }

    /**
     * {@inheritDoc}
     */
    public function loadFromCertificate(
        string $certificate,
        array $chain = []
    ): CertificateInterface {
        return new Certificate($certificate, null, $chain);
    }
}
