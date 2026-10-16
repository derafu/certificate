<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate;

use DateTime;
use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Exception\CertificateException;
use phpseclib3\File\X509;

/**
 * Class that represents a digital certificate.
 */
final class Certificate implements CertificateInterface
{
    /**
     * The X.509 certificate of the holder (the "leaf" certificate).
     *
     * @var string
     */
    private string $certificate;

    /**
     * Intermediate CA certificates that complete the trust chain of the
     * holder's certificate, in the order they were provided (subject's
     * issuer first).
     *
     * @var string[]
     */
    private array $chain = [];

    /**
     * Private key.
     *
     * @var string|null
     */
    private ?string $privateKey = null;

    /**
     * Private key details.
     *
     * @var array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int}
     */
    private array $privateKeyDetails;

    /**
     * Public key details (extracted from the certificate).
     *
     * @var array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int}
     */
    private array $publicKeyDetails;

    /**
     * Parsed X509 certificate data.
     *
     * @var array{name: string, subject: array<string, string|list<string>>, hash: string, issuer: array<string, string|list<string>>, version: int, serialNumber: string, serialNumberHex: string, validFrom: string, validTo: string, validFrom_time_t: int, validTo_time_t: int, signatureTypeSN: string, signatureTypeLN: string, signatureTypeNID: int, purposes: array<int, array{bool, bool, string}>, extensions?: array<string, string>}
     */
    private array $data;

    /**
     * Constructor of the digital certificate.
     *
     * @param string $certificate The X.509 certificate of the holder.
     * @param string|null $privateKey Private key associated with the
     * certificate.
     * @param string[] $chain Intermediate CA certificates that complete the
     * trust chain of the certificate (as returned, for example, by
     * `openssl_pkcs12_read()` in the `extracerts` index).
     */
    public function __construct(
        string $certificate,
        ?string $privateKey = null,
        array $chain = []
    ) {
        $this->certificate = AsymmetricKeyHelper::normalizeCertificate(
            $certificate
        );

        if ($privateKey !== null) {
            $this->privateKey = AsymmetricKeyHelper::normalizePrivateKey(
                $privateKey
            );
        }

        foreach ($chain as $chainCertificate) {
            $this->chain[] = AsymmetricKeyHelper::normalizeCertificate(
                $chainCertificate
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getKeys(bool $clean = false): array
    {
        return [
            'cert' => $this->getCertificate($clean),
            'pkey' => $this->privateKey !== null
                ? $this->getPrivateKey($clean)
                : null
            ,
            'chain' => $this->getCertificateChain($clean),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function getCertificate(bool $clean = false): string
    {
        return $clean
            ? self::stripPem($this->certificate, 'CERTIFICATE')
            : $this->certificate
        ;
    }

    /**
     * {@inheritDoc}
     */
    public function getCertificateChain(bool $clean = false): array
    {
        if (!$clean) {
            return $this->chain;
        }

        return array_map(
            fn (string $certificate) => self::stripPem(
                $certificate,
                'CERTIFICATE'
            ),
            $this->chain
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getCertificateBundle(): string
    {
        return implode('', [$this->certificate, ...$this->chain]);
    }

    /**
     * {@inheritDoc}
     */
    public function getPublicKey(bool $clean = false): string
    {
        $publicKey = $this->getPublicKeyDetails()['key'];

        return $clean ? self::stripPem($publicKey, 'PUBLIC KEY') : $publicKey;
    }

    /**
     * {@inheritDoc}
     */
    public function getPrivateKey(bool $clean = false): string
    {
        if ($this->privateKey === null) {
            throw new CertificateException(
                'The private key is not available in the certificate.'
            );
        }

        return $clean
            ? self::stripPem($this->privateKey, 'PRIVATE KEY')
            : $this->privateKey
        ;
    }

    /**
     * {@inheritDoc}
     */
    public function getPrivateKeyDetails(): array
    {
        if (!isset($this->privateKeyDetails)) {
            $key = openssl_pkey_get_private($this->getPrivateKey());
            $details = $key !== false ? openssl_pkey_get_details($key) : false;
            if ($details === false) {
                throw new CertificateException(
                    'It was not possible to read the private key of the certificate.'
                );
            }
            /** @var array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int} $details */
            $this->privateKeyDetails = $details;
        }

        return $this->privateKeyDetails;
    }

    /**
     * {@inheritDoc}
     */
    public function getPublicKeyDetails(): array
    {
        if (!isset($this->publicKeyDetails)) {
            $key = openssl_pkey_get_public($this->certificate);
            $details = $key !== false ? openssl_pkey_get_details($key) : false;
            if ($details === false) {
                throw new CertificateException(
                    'It was not possible to read the public key of the certificate.'
                );
            }
            /** @var array{bits: int, key: string, rsa?: array<string, string>, dsa?: array<string, string>, dh?: array<string, string>, ec?: array<string, mixed>, type: int} $details */
            $this->publicKeyDetails = $details;
        }

        return $this->publicKeyDetails;
    }

    /**
     * {@inheritDoc}
     */
    public function getData(): array
    {
        if (!isset($this->data)) {
            $data = openssl_x509_parse($this->certificate);
            if ($data === false) {
                throw new CertificateException(
                    'It was not possible to read the data of the certificate.'
                );
            }
            /** @var array{name: string, subject: array<string, string|list<string>>, hash: string, issuer: array<string, string|list<string>>, version: int, serialNumber: string, serialNumberHex: string, validFrom: string, validTo: string, validFrom_time_t: int, validTo_time_t: int, signatureTypeSN: string, signatureTypeLN: string, signatureTypeNID: int, purposes: array<int, array{bool, bool, string}>, extensions?: array<string, string>} $data */
            $this->data = $data;
        }

        return $this->data;
    }

    /**
     * {@inheritDoc}
     */
    public function getPkcs12(string $password): string
    {
        // Export the final certificate in PKCS#12 format, including the
        // trust chain (if any) so it can be recovered on a later load.
        openssl_pkcs12_export(
            $this->getCertificate(),
            $data,
            $this->getPrivateKey(),
            $password,
            $this->chain !== [] ? ['extracerts' => $this->chain] : []
        );

        // Return the digital certificate data.
        return $data;
    }

    /**
     * {@inheritDoc}
     *
     * If the certificate has several IDs, the first one is returned. Use
     * `getIds()` to get all of them.
     */
    public function getId(bool $forceUpper = true): string
    {
        $id = $this->getIds($forceUpper)[0] ?? null;
        if ($id === null) {
            throw new CertificateException(
                'Cannot get the ID of the digital certificate. It is recommended to verify the format and password of the certificate.'
            );
        }

        return $id;
    }

    /**
     * {@inheritDoc}
     */
    public function getIds(bool $forceUpper = true): array
    {
        // The serialNumber fields in the subject of the certificate.
        $ids = array_map(
            fn (string $serialNumber): string => ltrim(trim($serialNumber), '0'),
            $this->getValues($this->getData()['subject'], 'serialNumber')
        );

        // If there are none, the ID of the subject alternative name extension.
        if ($ids === []) {
            $x509 = new X509();
            $id = $this->getIdFromExtensions($x509->loadX509($this->certificate));
            $ids = $id !== null ? [$id] : [];
        }

        return $forceUpper ? array_map('strtoupper', $ids) : $ids;
    }

    /**
     * Gets all the values of a field of the subject or the issuer.
     *
     * A field that appears more than once in a distinguished name is a list
     * for OpenSSL, and a string when it appears once.
     *
     * @param array<string, string|list<string>> $fields
     * @return list<string>
     */
    private function getValues(array $fields, string $name): array
    {
        $values = $fields[$name] ?? [];

        return is_array($values) ? $values : [$values];
    }

    /**
     * Gets the ID from the subject alternative name extension of a parsed X.509
     * certificate.
     *
     * @param mixed $cert The certificate as phpseclib parses it.
     * @return string|null The ID, without the leading zeros, or `null` if the
     * certificate has no ID in that extension.
     */
    private function getIdFromExtensions(mixed $cert): ?string
    {
        $tbsCertificate = is_array($cert) ? ($cert['tbsCertificate'] ?? null) : null;
        $extensions = is_array($tbsCertificate) ? ($tbsCertificate['extensions'] ?? null) : null;
        if (!is_array($extensions)) {
            return null;
        }

        foreach ($extensions as $extension) {
            if (!is_array($extension) || ($extension['extnId'] ?? null) !== 'id-ce-subjectAltName') {
                continue;
            }

            $names = $extension['extnValue'] ?? null;
            $name = is_array($names) ? ($names[0] ?? null) : null;
            $otherName = is_array($name) ? ($name['otherName'] ?? null) : null;
            $value = is_array($otherName) ? ($otherName['value'] ?? null) : null;
            $ia5String = is_array($value) ? ($value['ia5String'] ?? null) : null;

            if (is_string($ia5String)) {
                return ltrim(trim($ia5String), '0');
            }
        }

        return null;
    }

    /**
     * {@inheritDoc}
     *
     * If the subject has several CN, the first one is returned. Use
     * `getNames()` to get all of them.
     */
    public function getName(): string
    {
        return $this->getNames()[0] ?? throw new CertificateException(
            'Cannot get the name of the digital certificate.'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getNames(): array
    {
        return $this->getValues($this->getData()['subject'], 'CN');
    }

    /**
     * {@inheritDoc}
     *
     * If the subject has several email addresses, the first one is returned.
     * Use `getEmails()` to get all of them.
     */
    public function getEmail(): string
    {
        return $this->getEmails()[0] ?? throw new CertificateException(
            'Cannot get the email of the digital certificate.'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getEmails(): array
    {
        return $this->getValues($this->getData()['subject'], 'emailAddress');
    }

    /**
     * {@inheritDoc}
     */
    public function getFrom(): string
    {
        return date('Y-m-d\TH:i:s', $this->getData()['validFrom_time_t']);
    }

    /**
     * {@inheritDoc}
     */
    public function getTo(): string
    {
        return date('Y-m-d\TH:i:s', $this->getData()['validTo_time_t']);
    }

    /**
     * {@inheritDoc}
     */
    public function getTotalDays(): int
    {
        $start = new DateTime($this->getFrom());
        $end = new DateTime($this->getTo());
        $diff = $start->diff($end);
        return (int) $diff->format('%a');
    }

    /**
     * {@inheritDoc}
     */
    public function getExpirationDays(?string $from = null): int
    {
        if ($from === null) {
            $from = date('Y-m-d\TH:i:s');
        }
        $start = new DateTime($from);
        $end = new DateTime($this->getTo());
        $diff = $start->diff($end);
        return (int) $diff->format('%a');
    }

    /**
     * {@inheritDoc}
     */
    public function isActive(?string $when = null): bool
    {
        if ($when === null) {
            $when = date('Y-m-d');
        }

        if (!isset($when[10])) {
            $when .= 'T23:59:59';
        }

        return $when >= $this->getFrom() && $when <= $this->getTo();
    }

    /**
     * {@inheritDoc}
     *
     * If the issuer has several CN, the first one is returned. Use
     * `getIssuers()` to get all of them.
     */
    public function getIssuer(): string
    {
        return $this->getIssuers()[0] ?? throw new CertificateException(
            'Cannot get the issuer of the digital certificate.'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getIssuers(): array
    {
        return $this->getValues($this->getData()['issuer'], 'CN');
    }

    /**
     * {@inheritDoc}
     */
    public function getModulus(int $wordwrap = 64): string
    {
        $modulus = $this->getPublicKeyDetails()['rsa']['n'] ?? null;

        if ($modulus === null) {
            throw new CertificateException(
                'Cannot get the modulus of the certificate.'
            );
        }

        return wordwrap(base64_encode($modulus), $wordwrap, "\n", true);
    }

    /**
     * {@inheritDoc}
     */
    public function getExponent(int $wordwrap = 64): string
    {
        $exponent = $this->getPublicKeyDetails()['rsa']['e'] ?? null;

        if ($exponent === null) {
            throw new CertificateException(
                'Cannot get the exponent of the certificate.'
            );
        }

        return wordwrap(base64_encode($exponent), $wordwrap, "\n", true);
    }

    /**
     * {@inheritDoc}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->getId(),
            'name' => $this->getName(),
            'email' => $this->getEmail(),
            'from' => $this->getFrom(),
            'to' => $this->getTo(),
            'totalDays' => $this->getTotalDays(),
            'expirationDays' => $this->getExpirationDays(),
            'isActive' => $this->isActive(),
            'issuer' => $this->getIssuer(),
            'modulus' => $this->getModulus(),
            'exponent' => $this->getExponent(),
            'cert' => $this->getCertificate(),
            'chain' => $this->getCertificateChain(),
            'pkey' => $this->privateKey !== null
                ? $this->getPrivateKey()
                : null
            ,
        ];
    }

    /**
     * {@inheritDoc}
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Removes the header and footer of a PEM encoded block, leaving only the
     * base64 body.
     *
     * @param string $pem PEM encoded block (certificate, public key or
     * private key).
     * @param string $type PEM header/footer label (e.g. `CERTIFICATE`,
     * `PUBLIC KEY`, `PRIVATE KEY`).
     * @return string The base64 body, without headers, footers or
     * surrounding whitespace.
     */
    private static function stripPem(string $pem, string $type): string
    {
        return trim(str_replace(
            ["-----BEGIN {$type}-----", "-----END {$type}-----"],
            '',
            $pem
        ));
    }
}
