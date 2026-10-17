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

use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\OpenSsl;

/**
 * Class that generates self-signed certificates and returns them as a string of
 * data (PKCS#12) or as an array.
 */
final class SelfSignedCertificate
{
    /**
     * Subject data of the certificate.
     *
     * @var array<string, string>
     */
    private array $subject;

    /**
     * Issuer data of the certificate.
     *
     * @var array<string, string>
     */
    private array $issuer;

    /**
     * Validity of the certificate, in days.
     *
     * @var array{days: int}
     */
    private array $validity;

    /**
     * Password to protect the private key in the certificate.
     *
     * @var string
     */
    private string $password;

    /**
     * Constructor that assigns the default values.
     *
     * @param OpenSslInterface $openSsl Service that calls OpenSSL.
     */
    public function __construct(
        private readonly OpenSslInterface $openSsl = new OpenSsl()
    ) {
        $this->setSubject();
        $this->setIssuer();
        $this->setValidity();
        $this->setPassword();
    }

    /**
     * Configures the subject data of the certificate.
     *
     * @param string $C Country of the subject.
     * @param string $ST State or province of the subject.
     * @param string $L City of the subject.
     * @param string $O Organization of the subject.
     * @param string $OU Organizational unit of the subject.
     * @param string $CN Common name of the subject.
     * @param string $emailAddress Email address of the subject.
     * @param string $serialNumber Serial number of the subject.
     * @param string $title Title of the subject.
     * @return static
     */
    public function setSubject(
        string $C = 'CL',
        string $ST = 'Colchagua',
        string $L = 'Santa Cruz',
        string $O = 'Intergalactic Robots Organization',
        string $OU = 'Technology',
        string $CN = 'Daniel Bot',
        string $emailAddress = 'daniel.bot@example.com',
        string $serialNumber = '11222333-9',
        string $title = 'Bot',
    ): static {
        if (empty($CN) || empty($emailAddress) || empty($serialNumber)) {
            throw new CertificateException(
                'The CN, emailAddress and serialNumber are required.'
            );
        }

        $this->subject = [
            'C' => $C,
            'ST' => $ST,
            'L' => $L,
            'O' => $O,
            'OU' => $OU,
            'CN' => $CN,
            'emailAddress' => $emailAddress,
            'serialNumber' => strtoupper($serialNumber),
            'title' => $title,
        ];

        return $this;
    }

    /**
     * Configures the issuer data of the certificate.
     *
     * @param string $C Country of the issuer.
     * @param string $ST State or province of the issuer.
     * @param string $L City of the issuer.
     * @param string $O Organization of the issuer.
     * @param string $OU Organizational unit of the issuer.
     * @param string $CN Common name of the issuer.
     * @param string $emailAddress Email address of the issuer.
     * @param string $serialNumber Serial number of the issuer.
     * @return static
     */
    public function setIssuer(
        string $C = 'CL',
        string $ST = 'Colchagua',
        string $L = 'Santa Cruz',
        string $O = 'Derafu',
        string $OU = 'Technology',
        string $CN = 'Derafu Test Certificate Authority',
        string $emailAddress = 'fakes-certificates@derafu.org',
        string $serialNumber = '76192083-9',
    ): static {
        $this->issuer = [
            'C' => $C,
            'ST' => $ST,
            'L' => $L,
            'O' => $O,
            'OU' => $OU,
            'CN' => $CN,
            'emailAddress' => $emailAddress,
            'serialNumber' => strtoupper($serialNumber),
        ];

        return $this;
    }

    /**
     * Configures the validity of the certificate.
     *
     * @param int $days Days that the certificate will be valid from the current
     * date. If not provided, it will have a validity of 365 days.
     * @return static
     */
    public function setValidity(int $days = 365): static
    {
        $this->validity = [
            'days' => $days,
        ];

        return $this;
    }

    /**
     * Configures the password to protect the private key.
     *
     * @param string $password Password to protect the private key.
     * @return void
     */
    public function setPassword(string $password = 'i_love_derafu')
    {
        $this->password = $password;
    }

    /**
     * Generates a digital certificate in PKCS#12 format and returns it as a
     * string.
     *
     * @return string Digital certificate in PKCS#12 format.
     */
    public function toPkcs12(): string
    {
        // Days of validity of the certificate (issuer and subject).
        $days = $this->validity['days'];

        // Create private key and CSR for the issuer.
        $issuerPrivateKey = $this->openSsl->pkeyNew();
        $issuerCsr = $this->openSsl->csrNew($this->issuer, $issuerPrivateKey);

        // Create self-signed certificate for the issuer (CA).
        $issuerCert = $this->openSsl->csrSign(
            $issuerCsr,         // CSR of the issuer.
            null,               // Issuer certificate (null indicates that it is self-signed).
            $issuerPrivateKey,  // Private key of the issuer.
            $days,              // Validity days (same as subject).
            [],                 // Additional options.
            666                 // Serial number of the certificate.
        );

        // Create private key and CSR for the subject.
        $subjectPrivateKey = $this->openSsl->pkeyNew();
        $subjectCsr = $this->openSsl->csrNew($this->subject, $subjectPrivateKey);

        // Use the issuer certificate to sign the subject CSR.
        $subjectCert = $this->openSsl->csrSign(
            $subjectCsr,        // The subject CSR.
            $issuerCert,        // Issuer certificate.
            $issuerPrivateKey,  // Private key of the issuer.
            $days,              // Validity days.
            [],                 // Additional options.
            69                  // Serial number of the certificate.
        );

        // Export the final certificate in PKCS#12 format, bundling the
        // issuer certificate (CA) as the trust chain. This mirrors what a
        // real accredited certification authority does when the issuer is
        // not a root CA trusted directly by every relying party.
        return $this->openSsl->pkcs12Export(
            $subjectCert,
            $subjectPrivateKey,
            $this->password,
            ['extracerts' => [$issuerCert]]
        );
    }

    /**
     * Generates a digital certificate in PKCS#12 format and returns it as an
     * array.
     *
     * @return array<string, mixed> Digital certificate in PKCS#12 format.
     */
    public function toArray(): array
    {
        return $this->openSsl->pkcs12Read($this->toPkcs12(), $this->password);
    }
}
