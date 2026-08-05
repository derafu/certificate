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
 * Class that handles the configuration and loading of digital certificates for
 * electronic signatures.
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
            throw new CertificateException(sprintf(
                'It was not possible to read the digital certificate file from %s',
                $filepath
            ));
        }

        $data = file_get_contents($filepath);

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
            throw new CertificateException(sprintf(
                'It was not possible to read the digital certificate data.',
            ));
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
