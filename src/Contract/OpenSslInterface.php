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
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * Interface for the service that offers the functions of OpenSSL that the
 * package uses.
 *
 * Each method is the function of OpenSSL of the same name, without the
 * `openssl_` prefix.
 *
 * A call that fails (`false`, or `-1` when verifying) MUST be reported with a
 * `CertificateException`, and MUST NOT be returned as a value: what the methods
 * return is never a failure.
 */
interface OpenSslInterface
{
    /**
     * Generates a new private key (`openssl_pkey_new()`).
     *
     * @param array<string, mixed>|null $options Options of the key.
     * @throws CertificateException If the key can not be generated.
     */
    public function pkeyNew(?array $options = null): OpenSSLAsymmetricKey;

    /**
     * Reads a private key (`openssl_pkey_get_private()`).
     *
     * @param string $privateKey Private key, in PEM.
     * @param string|null $passphrase Passphrase of the key, if it has one.
     * @throws CertificateException If the key can not be read.
     */
    public function pkeyGetPrivate(string $privateKey, ?string $passphrase = null): OpenSSLAsymmetricKey;

    /**
     * Reads the public key of a certificate or a public key
     * (`openssl_pkey_get_public()`).
     *
     * @param string $certificate Certificate or public key, in PEM.
     * @throws CertificateException If the key can not be read.
     */
    public function pkeyGetPublic(string $certificate): OpenSSLAsymmetricKey;

    /**
     * Gets the details of a key (`openssl_pkey_get_details()`).
     *
     * @return array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int}
     * @throws CertificateException If the details can not be read.
     */
    public function pkeyGetDetails(OpenSSLAsymmetricKey $key): array;

    /**
     * Reads the data of a certificate (`openssl_x509_parse()`).
     *
     * @param string $certificate Certificate, in PEM.
     * @return array{name: string, subject: array<string, string|list<string>>, hash: string, issuer: array<string, string|list<string>>, version: int, serialNumber: string, serialNumberHex: string, validFrom: string, validTo: string, validFrom_time_t: int, validTo_time_t: int, signatureTypeSN: string, signatureTypeLN: string, signatureTypeNID: int, purposes: array<int, array{bool, bool, string}>, extensions?: array<string, string>}
     * @throws CertificateException If the certificate can not be read.
     */
    public function x509Parse(string $certificate): array;

    /**
     * Generates a certificate signing request (`openssl_csr_new()`).
     *
     * @param array<string, string> $subject Distinguished name.
     * @throws CertificateException If the request can not be generated.
     */
    public function csrNew(array $subject, OpenSSLAsymmetricKey $privateKey): OpenSSLCertificateSigningRequest;

    /**
     * Signs a certificate signing request (`openssl_csr_sign()`).
     *
     * @param OpenSSLCertificate|null $caCertificate Certificate of the signer,
     * `null` if the request is signed by its own key (self-signed).
     * @param int $days Days that the certificate is valid.
     * @param array<string, mixed> $options Options of the signature.
     * @param int $serial Serial number of the certificate.
     * @throws CertificateException If the request can not be signed.
     */
    public function csrSign(
        OpenSSLCertificateSigningRequest $csr,
        ?OpenSSLCertificate $caCertificate,
        OpenSSLAsymmetricKey $privateKey,
        int $days,
        array $options = [],
        int $serial = 0
    ): OpenSSLCertificate;

    /**
     * Reads a PKCS#12 (`openssl_pkcs12_read()`).
     *
     * @param string $data Content of the PKCS#12.
     * @param string $password Password of the PKCS#12.
     * @return array{cert: string, pkey: string, extracerts?: list<string>}
     * @throws CertificateException If the PKCS#12 can not be read.
     */
    public function pkcs12Read(string $data, string $password): array;

    /**
     * Exports a certificate and its private key as a PKCS#12
     * (`openssl_pkcs12_export()`).
     *
     * @param OpenSSLCertificate|string $certificate Certificate.
     * @param OpenSSLAsymmetricKey|string $privateKey Private key.
     * @param string $password Password to protect the PKCS#12.
     * @param array<string, mixed> $options Options (`extracerts`...).
     * @return string Content of the PKCS#12.
     * @throws CertificateException If the PKCS#12 can not be exported.
     */
    public function pkcs12Export(
        OpenSSLCertificate|string $certificate,
        OpenSSLAsymmetricKey|string $privateKey,
        string $password,
        array $options = []
    ): string;

    /**
     * Signs data (`openssl_sign()`).
     *
     * @param string $data Data to sign.
     * @param string $privateKey Private key, in PEM.
     * @param string|int $algorithm Algorithm of the signature.
     * @return string The signature (binary, not in base64).
     * @throws CertificateException If the data can not be signed.
     */
    public function sign(string $data, string $privateKey, string|int $algorithm): string;

    /**
     * Verifies the signature of data (`openssl_verify()`).
     *
     * @param string $data Data that was signed.
     * @param string $signature The signature (binary, not in base64).
     * @param string $certificate Certificate of the signer, in PEM.
     * @param string|int $algorithm Algorithm of the signature.
     * @return bool `true` if the signature is correct, `false` if it is not.
     * @throws CertificateException If the verification itself fails.
     */
    public function verify(string $data, string $signature, string $certificate, string|int $algorithm): bool;
}
