<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsCertificate;

use Derafu\Certificate\AsymmetricKeyHelper;
use Derafu\Certificate\Certificate;
use Derafu\Certificate\Contract\CertificateFakerInterface;
use Derafu\Certificate\Contract\CertificateLoaderInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\SelfSignedCertificate;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Certificate::class)]
#[CoversClass(CertificateException::class)]
#[CoversClass(CertificateFaker::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(AsymmetricKeyHelper::class)]
#[CoversClass(SelfSignedCertificate::class)]
final class CertificateTest extends TestCase
{
    private CertificateFakerInterface $faker;

    private CertificateLoaderInterface $loader;

    protected function setUp(): void
    {
        $this->loader = new CertificateLoader();
        $this->faker = new CertificateFaker($this->loader);
    }

    public function testCertificateDefaultData(): void
    {
        $certificate = $this->faker->createFake();
        $expected = [
            'getID' => '11222333-9',
            'getName' => 'Daniel Bot',
            'getEmail' => 'daniel.bot@example.com',
            'isActive' => true,
            'getIssuer' => 'Derafu Test Certificate Authority',
        ];
        $actual = [
            'getID' => $certificate->getID(),
            'getName' => $certificate->getName(),
            'getEmail' => $certificate->getEmail(),
            'isActive' => $certificate->isActive(),
            'getIssuer' => $certificate->getIssuer(),
        ];
        $this->assertSame($expected, $actual);
    }

    public function testCertificateCreationWithValidSerialNumber(): void
    {
        $certificate = $this->faker->createFake(id: '1-9');
        $this->assertSame('1-9', $certificate->getId());
    }

    public function testCertificateCreationWithInvalidSerialNumber(): void
    {
        $certificate = $this->faker->createFake(id: '1-2');
        $this->assertNotSame('1-9', $certificate->getID());
    }

    public function testCertificateCreationWithKSerialNumber(): void
    {
        $certificate = $this->faker->createFake(id: '10-k');
        $this->assertSame('10-K', $certificate->getID());
    }

    public function testGetModulus(): void
    {
        $certificate = $this->faker->createFake();
        $modulus = $certificate->getModulus();

        $this->assertNotEmpty($modulus);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\/+=\n]+$/', $modulus);
    }

    public function testGetExponent(): void
    {
        $certificate = $this->faker->createFake();
        $exponent = $certificate->getExponent();

        $this->assertNotEmpty($exponent);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\/+=]+$/', $exponent);
    }

    public function testGetNameThrowsExceptionForInvalidCertificate(): void
    {
        $this->expectException(CertificateException::class);

        $certificate = $this->faker->createFake(name: '');
        $certificate->getName();
    }

    public function testGetEmailThrowsExceptionForInvalidCertificate(): void
    {
        $this->expectException(CertificateException::class);

        $certificate = $this->faker->createFake(email: '');
        $certificate->getEmail();
    }

    public function testIsActiveForExpiredCertificate(): void
    {
        $certificate = $this->faker->createFake();

        $when = date('Y-m-d', strtotime('+10 year'));
        $this->assertFalse($certificate->isActive($when));
    }

    public function testGetExpirationDays(): void
    {
        $certificate = $this->faker->createFake();
        $days = $certificate->getExpirationDays();

        $this->assertGreaterThan(0, $days);
        $this->assertLessThanOrEqual(365, $days);
    }

    public function testGetDataReturnsParsedCertificateData(): void
    {
        $certificate = $this->faker->createFake();
        $data = $certificate->getData();

        $this->assertArrayHasKey('subject', $data);
        $this->assertArrayHasKey('issuer', $data);
    }

    /**
     * Ensures that `getPublicKey()` returns the raw public key, not the
     * certificate: it must be a different PEM block than `getCertificate()`.
     */
    public function testGetPublicKeyReturnsRawPublicKeyNotCertificate(): void
    {
        $certificate = $this->faker->createFake();

        $publicKey = $certificate->getPublicKey();
        $x509Certificate = $certificate->getCertificate();

        $this->assertNotSame($x509Certificate, $publicKey);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $publicKey);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $x509Certificate);
    }

    /**
     * Ensures that the intermediate CA certificate is available through
     * `getCertificateChain()` and is not silently discarded.
     */
    public function testGetCertificateChainReturnsIntermediateCertificate(): void
    {
        $certificate = $this->faker->createFake();

        $chain = $certificate->getCertificateChain();

        $this->assertCount(1, $chain);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $chain[0]);
    }

    /**
     * Ensures that `getCertificateBundle()` concatenates the certificate and
     * its trust chain, in that order, with PEM headers preserved.
     */
    public function testGetCertificateBundleIncludesCertificateAndChain(): void
    {
        $certificate = $this->faker->createFake();

        $bundle = $certificate->getCertificateBundle();

        $this->assertSame(2, substr_count($bundle, '-----BEGIN CERTIFICATE-----'));
        $this->assertStringStartsWith($certificate->getCertificate(), $bundle);
        $this->assertStringEndsWith($certificate->getCertificateChain()[0], $bundle);
    }

    /**
     * Ensures that the modulus and exponent are derived from the
     * certificate's public key, so they remain available even when the
     * certificate has no private key associated (e.g. when it was loaded
     * with `loadFromCertificate()` for verification-only purposes).
     */
    public function testGetModulusAndExponentDoNotRequireAPrivateKey(): void
    {
        $original = $this->faker->createFake();
        $certificate = $this->loader->loadFromCertificate(
            $original->getCertificate()
        );

        $this->assertSame($original->getModulus(), $certificate->getModulus());
        $this->assertSame($original->getExponent(), $certificate->getExponent());
    }
}
