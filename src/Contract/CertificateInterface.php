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

use JsonSerializable;

/**
 * Interface for the certificate entity.
 */
interface CertificateInterface extends JsonSerializable
{
    /**
     * Returns the certificate, the trust chain and the private key.
     *
     * @param boolean $clean If the certificate content is cleaned.
     * @return array Array with the indices: `cert`, `chain` and `pkey`.
     * `pkey` will be `null` if the certificate has no private key
     * associated.
     */
    public function getKeys(bool $clean = false): array;

    /**
     * Returns the X.509 certificate of the holder (the "leaf" certificate).
     *
     * This is NOT the trust chain and NOT the raw public key, it is the
     * certificate: the public key plus the identity data signed by a
     * Certificate Authority. Use `getCertificateChain()` for the
     * intermediate CA certificates, `getCertificateBundle()` for this
     * certificate concatenated with the chain, and `getPublicKey()` for the
     * raw public key extracted from this certificate.
     *
     * @param bool $clean If the certificate content is cleaned (headers and
     * footers removed).
     * @return string Certificate content, in base64 (PEM without headers if
     * `$clean` is `true`).
     */
    public function getCertificate(bool $clean = false): string;

    /**
     * Returns the intermediate CA certificates that complete the trust chain
     * of the holder's certificate.
     *
     * These are the certificates a TLS client (or any other relying party
     * that does not already trust the issuing CA directly) needs in order to
     * build the path from this certificate up to a trusted root. They come,
     * for example, from the `extracerts` index of `openssl_pkcs12_read()`
     * when the PKCS#12 file bundles them. If the PKCS#12/certificate did not
     * include them, this returns an empty array.
     *
     * @param bool $clean If the certificate content is cleaned (headers and
     * footers removed) for each certificate in the chain.
     * @return string[] Intermediate CA certificates, in the order provided
     * (subject's issuer first), empty if there is no chain.
     */
    public function getCertificateChain(bool $clean = false): array;

    /**
     * Returns this certificate concatenated with its trust chain, as a
     * single PEM bundle (leaf certificate first, then the intermediate CA
     * certificates in order).
     *
     * This is the value that must be presented, for example, as the client
     * certificate in a mutual TLS handshake when the issuing CA is not
     * trusted directly by the remote party (only sending `getCertificate()`
     * would make the handshake fail with a `unknown ca` alert in that case).
     *
     * @return string PEM bundle. Always includes the PEM headers/footers of
     * every certificate, since that is required to tell them apart.
     */
    public function getCertificateBundle(): string;

    /**
     * Returns the raw public key extracted from the certificate.
     *
     * This is NOT the certificate: it is only the public key material (e.g.
     * the RSA modulus and exponent) that the certificate certifies belongs
     * to its subject, without the identity data or the CA's signature. Use
     * `getCertificate()` when what is needed is the certificate itself.
     *
     * @param bool $clean If the public key content is cleaned (headers and
     * footers removed).
     * @return string Public key content, in base64 (PEM without headers if
     * `$clean` is `true`).
     */
    public function getPublicKey(bool $clean = false): string;

    /**
     * Returns the private key.
     *
     * @param bool $clean If the private key content is cleaned.
     * @return string Private key content, in base64.
     */
    public function getPrivateKey(bool $clean = false): string;

    /**
     * Returns the private key details.
     *
     * @return array
     */
    public function getPrivateKeyDetails(): array;

    /**
     * Returns the public key details, extracted from the certificate.
     *
     * Unlike `getPrivateKeyDetails()`, this is available even when the
     * certificate has no private key associated (e.g. when it was loaded
     * with `loadFromCertificate()`), since the public key is always part of
     * the certificate itself.
     *
     * @return array
     */
    public function getPublicKeyDetails(): array;

    /**
     * Returns the certificate data as an array.
     *
     * Alias of getCertX509().
     *
     * @return array Array with all the certificate data.
     */
    public function getData(): array;

    /**
     * Returns the certificate data as a string in PKCS #12 format.
     *
     * @param string $password
     * @return string
     */
    public function getPkcs12(string $password): string;

    /**
     * Returns the ID associated with the certificate.
     *
     * The ID is the RUN that must be in an extension, this is the standard.
     * Also, it could be in the `serialNumber` field, some providers place it in
     * this field, it is also easier for tests.
     *
     * @param bool $forceUpper If uppercase is forced.
     * @return string ID associated with the certificate in the format:
     * 11222333-4.
     */
    public function getId(bool $forceUpper = true): string;

    /**
     * Returns the CN of the subject.
     *
     * @return string CN of the subject.
     */
    public function getName(): string;

    /**
     * Returns the email address of the subject.
     *
     * @return string Email address of the subject.
     */
    public function getEmail(): string;

    /**
     * Returns from when the signature is valid.
     *
     * @return string Date and time from when the signature is valid.
     */
    public function getFrom(): string;

    /**
     * Returns until when the signature is valid.
     *
     * @return string Date and time until when the signature is valid.
     */
    public function getTo(): string;

    /**
     * Returns the total days that the signature is valid.
     *
     * @return int Total days that the signature is valid.
     */
    public function getTotalDays(): int;

    /**
     * Returns the days that are left to expire the signature.
     *
     * @param string|null $from Date from which the calculation is made.
     * @return int Days that are left to expire the signature.
     */
    public function getExpirationDays(?string $from = null): int;

    /**
     * Indicates if the signature is active or expired.
     *
     * NOTE: This method will also validate that the signature is not active in
     * the future. That is, the date from when it is active must be in the past.
     *
     * @param string|null $when Date from which the validation is made.
     * @return bool `true` if the signature is active, `false` if it is expired.
     */
    public function isActive(?string $when = null): bool;

    /**
     * Returns the name of the issuer of the signature.
     *
     * @return string CN of the issuer.
     */
    public function getIssuer(): string;

    /**
     * Returns the modulus of the certificate's public key.
     *
     * @return string Modulus in base64.
     */
    public function getModulus(int $wordwrap = 64): string;

    /**
     * Returns the public exponent of the certificate's public key.
     *
     * @return string Public exponent in base64.
     */
    public function getExponent(int $wordwrap = 64): string;

    /**
     * Returns the certificate data as an array.
     *
     * @return array Array with all the certificate data, including the
     * indices `cert`, `chain` and `pkey` (see `getKeys()`).
     */
    public function toArray(): array;
}
