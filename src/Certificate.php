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
     * @var array
     */
    private array $privateKeyDetails;

    /**
     * Public key details (extracted from the certificate).
     *
     * @var array
     */
    private array $publicKeyDetails;

    /**
     * Parsed X509 certificate data.
     *
     * @var array
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
        $publicKey = $this->getPublicKeyDetails()['key'] ?? null;

        if ($publicKey === null) {
            throw new CertificateException(
                'Cannot get the public key from the certificate.'
            );
        }

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
            $this->privateKeyDetails = openssl_pkey_get_details(
                openssl_pkey_get_private($this->getPrivateKey())
            );
        }

        return $this->privateKeyDetails;
    }

    /**
     * {@inheritDoc}
     */
    public function getPublicKeyDetails(): array
    {
        if (!isset($this->publicKeyDetails)) {
            $this->publicKeyDetails = openssl_pkey_get_details(
                openssl_pkey_get_public($this->certificate)
            );
        }

        return $this->publicKeyDetails;
    }

    /**
     * {@inheritDoc}
     */
    public function getData(): array
    {
        if (!isset($this->data)) {
            $this->data = openssl_x509_parse($this->certificate);
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
     */
    public function getId(bool $forceUpper = true): string
    {
        // Verify the serialNumber in the subject of the certificate.
        $serialNumber = $this->getData()['subject']['serialNumber'] ?? null;
        if ($serialNumber !== null) {
            $serialNumber = ltrim(trim($serialNumber), '0');
            return $forceUpper ? strtoupper($serialNumber) : $serialNumber;
        }

        // Get the extensions of the certificate.
        $x509 = new X509();
        $cert = $x509->loadX509($this->certificate);
        if (isset($cert['tbsCertificate']['extensions'])) {
            foreach ($cert['tbsCertificate']['extensions'] as $extension) {
                if (
                    $extension['extnId'] === 'id-ce-subjectAltName'
                    && isset($extension['extnValue'][0]['otherName']['value']['ia5String'])
                ) {
                    $id = ltrim(
                        trim($extension['extnValue'][0]['otherName']['value']['ia5String']),
                        '0'
                    );
                    return $forceUpper ? strtoupper($id) : $id;
                }
            }
        }

        // The ID was not found, throw an exception.
        throw new CertificateException(
            'Cannot get the ID of the digital certificate (electronic signature). It is recommended to verify the format and password of the certificate.'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        $name = $this->getData()['subject']['CN'] ?? null;
        if ($name === null) {
            throw new CertificateException(
                'Cannot get the name of the digital certificate (electronic signature).'
            );
        }

        return $name;
    }

    /**
     * {@inheritDoc}
     */
    public function getEmail(): string
    {
        $email = $this->getData()['subject']['emailAddress'] ?? null;
        if ($email === null) {
            throw new CertificateException(
                'Cannot get the email of the digital certificate (electronic signature).'
            );
        }

        return $email;
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
     */
    public function getIssuer(): string
    {
        return $this->getData()['issuer']['CN'];
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
