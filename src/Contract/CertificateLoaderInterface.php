<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate\Contract;

use Derafu\Certificate\Exception\CertificateException;

/**
 * Interface for the certificate loader.
 */
interface CertificateLoaderInterface
{
    /**
     * Creates a Certificate instance from a file that contains the digital
     * certificate in PKCS#12 format.
     *
     * @param string $filepath Path to the file that contains the certificate in
     * PKCS#12 format.
     * @param string $password Password to access the certificate content.
     * @return CertificateInterface Instance of the Certificate class that
     * contains the private key and the public certificate.
     * @throws CertificateException If the file cannot be read or the
     * certificate cannot be loaded.
     */
    public function loadFromFile(
        string $filepath,
        string $password
    ): CertificateInterface;

    /**
     * Creates a Certificate instance from a string that contains the digital
     * certificate in PKCS#12 format.
     *
     * If the PKCS#12 data bundles intermediate CA certificates (the
     * `extracerts` index of `openssl_pkcs12_read()`), they are preserved as
     * the trust chain of the resulting Certificate (see
     * `CertificateInterface::getCertificateChain()`).
     *
     * @param string $data String that contains the certificate data in PKCS#12
     * format.
     * @param string $password Password to access the certificate content.
     * @return CertificateInterface Instance of the Certificate class that
     * contains the private key, the certificate and, if present, its trust
     * chain.
     * @throws CertificateException If the certificate cannot be loaded
     */
    public function loadFromData(
        string $data,
        string $password
    ): CertificateInterface;

    /**
     * Creates a Certificate instance from an array that contains the
     * certificate, the private key and, optionally, the trust chain.
     *
     * @param array<string, mixed> $data Array that contains the keys 'cert' (or
     * 'certificate'), 'pkey' (or 'privateKey') and, optionally, 'chain' (or
     * 'extracerts') with the intermediate CA certificates.
     * @return CertificateInterface Instance of the Certificate class that
     * contains the private key, the certificate and, if present, its trust
     * chain.
     */
    public function loadFromArray(array $data): CertificateInterface;

    /**
     * Creates a Certificate instance from a certificate and a private key.
     *
     * @param string $certificate The X.509 certificate of the holder.
     * @param string $privateKey Private key associated with the certificate.
     * @param string[] $chain Intermediate CA certificates that complete the
     * trust chain of the certificate.
     * @return CertificateInterface Instance of the Certificate class that
     * contains the private key, the certificate and, if provided, its trust
     * chain.
     */
    public function loadFromKeys(
        string $certificate,
        string $privateKey,
        array $chain = []
    ): CertificateInterface;

    /**
     * Creates a Certificate instance from a certificate only, without a
     * private key.
     *
     * Useful for verification-only scenarios, for example when validating a
     * signature made with a certificate that is not owned by the current
     * application.
     *
     * @param string $certificate The X.509 certificate of the holder.
     * @param string[] $chain Intermediate CA certificates that complete the
     * trust chain of the certificate.
     * @return CertificateInterface Instance of the Certificate class that
     * contains only the certificate and, if provided, its trust chain (no
     * private key).
     */
    public function loadFromCertificate(
        string $certificate,
        array $chain = []
    ): CertificateInterface;
}
