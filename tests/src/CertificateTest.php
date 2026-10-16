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
use Derafu\Certificate\Contract\CertificateInterface;
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
        $leaf = $certificate->getCertificate();
        $chain = $certificate->getCertificateChain()[0];

        if ($leaf === '' || $chain === '') {
            $this->fail('The certificate and its chain must not be empty.');
        }
        $this->assertSame(2, substr_count($bundle, '-----BEGIN CERTIFICATE-----'));
        $this->assertStringStartsWith($leaf, $bundle);
        $this->assertStringEndsWith($chain, $bundle);
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

    /**
     * The fixture has repeated `CN`, `emailAddress` and `serialNumber` in the
     * subject (and the same ones in the issuer), as the standard allows.
     */
    private function loadRepeatedFieldsCertificate(): CertificateInterface
    {
        return $this->loadFixture('repeated-fields');
    }

    /**
     * Loads a certificate of `tests/fixtures/` (`<name>.cert.pem` and
     * `<name>.key.pem`).
     */
    private function loadFixture(string $name): CertificateInterface
    {
        $dir = __DIR__ . '/../fixtures';

        return $this->loader->loadFromKeys(
            (string) file_get_contents($dir . '/' . $name . '.cert.pem'),
            (string) file_get_contents($dir . '/' . $name . '.key.pem')
        );
    }

    public function testPluralGettersReturnAllTheRepeatedValues(): void
    {
        $certificate = $this->loadRepeatedFieldsCertificate();

        $this->assertSame(['11222333-9', '44555666-7'], $certificate->getIds());
        $this->assertSame(['Ana Perez', 'Ana P.'], $certificate->getNames());
        $this->assertSame(
            ['ana@example.com', 'ana.p@example.com'],
            $certificate->getEmails()
        );
        $this->assertSame(['Ana Perez', 'Ana P.'], $certificate->getIssuers());
    }

    public function testSingularGettersReturnTheFirstRepeatedValue(): void
    {
        $certificate = $this->loadRepeatedFieldsCertificate();

        $this->assertSame('11222333-9', $certificate->getId());
        $this->assertSame('Ana Perez', $certificate->getName());
        $this->assertSame('ana@example.com', $certificate->getEmail());
        $this->assertSame('Ana Perez', $certificate->getIssuer());
    }

    public function testPluralGettersReturnAListEvenWithASingleValue(): void
    {
        $certificate = $this->faker->createFake();

        $this->assertSame(['11222333-9'], $certificate->getIds());
        $this->assertSame(['Daniel Bot'], $certificate->getNames());
        $this->assertSame(['daniel.bot@example.com'], $certificate->getEmails());
        $this->assertSame(
            ['Derafu Test Certificate Authority'],
            $certificate->getIssuers()
        );
    }

    public function testGetDataThrowsExceptionForInvalidCertificate(): void
    {
        $certificate = $this->loader->loadFromKeys('invalid', 'invalid');

        $this->expectException(CertificateException::class);
        $certificate->getData();
    }

    public function testGetPublicKeyDetailsThrowsExceptionForInvalidCertificate(): void
    {
        $certificate = $this->loader->loadFromKeys('invalid', 'invalid');

        $this->expectException(CertificateException::class);
        $certificate->getPublicKeyDetails();
    }

    public function testGetPrivateKeyDetailsThrowsExceptionForInvalidPrivateKey(): void
    {
        $certificate = $this->loader->loadFromKeys('invalid', 'invalid');

        $this->expectException(CertificateException::class);
        $certificate->getPrivateKeyDetails();
    }

    public function testSelfSignedCertificateThrowsExceptionForInvalidIssuer(): void
    {
        $selfSigned = (new SelfSignedCertificate())->setIssuer(C: 'CLX');

        // OpenSSL also emits a PHP warning for the invalid country.
        set_error_handler(static fn (): bool => true);
        try {
            $this->expectException(CertificateException::class);
            $selfSigned->toPkcs12();
        } finally {
            restore_error_handler();
        }
    }

    public function testSelfSignedCertificateThrowsExceptionForInvalidSubject(): void
    {
        $selfSigned = (new SelfSignedCertificate())->setSubject(C: 'CLX');

        // OpenSSL also emits a PHP warning for the invalid country.
        set_error_handler(static fn (): bool => true);
        try {
            $this->expectException(CertificateException::class);
            $selfSigned->toPkcs12();
        } finally {
            restore_error_handler();
        }
    }

    public function testGetIdFromTheSubjectAlternativeNameExtension(): void
    {
        // The certificate has no serialNumber, the ID is in the extension.
        $certificate = $this->loadFixture('san-id');

        $this->assertSame(['11222333-9'], $certificate->getIds());
        $this->assertSame('11222333-9', $certificate->getId());
    }

    public function testGetIdThrowsExceptionWhenTheCertificateHasNoId(): void
    {
        $certificate = $this->loadFixture('ec-no-id');

        $this->assertSame([], $certificate->getIds());
        $this->expectException(CertificateException::class);
        $certificate->getId();
    }

    public function testGetModulusThrowsExceptionForAKeyThatIsNotRsa(): void
    {
        $certificate = $this->loadFixture('ec-no-id');

        $this->expectException(CertificateException::class);
        $certificate->getModulus();
    }

    public function testGetExponentThrowsExceptionForAKeyThatIsNotRsa(): void
    {
        $certificate = $this->loadFixture('ec-no-id');

        $this->expectException(CertificateException::class);
        $certificate->getExponent();
    }

    public function testGetPrivateKeyThrowsExceptionWithoutPrivateKey(): void
    {
        $certificate = $this->loader->loadFromCertificate(
            $this->faker->createFake()->getCertificate()
        );

        $this->expectException(CertificateException::class);
        $certificate->getPrivateKey();
    }

    public function testTheCleanKeysHaveNoPemHeadersAndFooters(): void
    {
        $certificate = $this->loader->loadFromCertificate(
            $this->faker->createFake()->getCertificate(),
            [$this->faker->createFake()->getCertificate()]
        );
        $keys = $this->faker->createFake()->getKeys(true);

        $this->assertStringNotContainsString('-----', $keys['cert']);
        $this->assertStringNotContainsString('-----', (string) $keys['pkey']);
        $this->assertStringNotContainsString('-----', $keys['chain'][0] ?? '');
        $this->assertStringNotContainsString('-----', $certificate->getPublicKey(true));
        $this->assertStringContainsString('-----BEGIN', $certificate->getPublicKey());
        $this->assertStringNotContainsString('-----', $certificate->getCertificateChain(true)[0]);
    }

    public function testToArrayAndJsonSerializeHaveTheDataOfTheCertificate(): void
    {
        $certificate = $this->faker->createFake();

        $array = $certificate->toArray();
        $this->assertSame('11222333-9', $array['id']);
        $this->assertSame('Daniel Bot', $array['name']);
        $this->assertSame('daniel.bot@example.com', $array['email']);
        $this->assertSame('Derafu Test Certificate Authority', $array['issuer']);
        $this->assertTrue($array['isActive']);
        $this->assertSame($certificate->getModulus(), $array['modulus']);
        $this->assertSame($certificate->getExponent(), $array['exponent']);
        $this->assertSame($certificate->getPrivateKey(), $array['pkey']);

        $this->assertSame($array, $certificate->jsonSerialize());
        $this->assertSame($array, json_decode((string) json_encode($certificate), true));
    }

    public function testToArrayOfACertificateWithoutPrivateKeyHasNoPrivateKey(): void
    {
        $certificate = $this->loader->loadFromCertificate(
            $this->faker->createFake()->getCertificate()
        );

        $this->assertNull($certificate->toArray()['pkey']);
        $this->assertNull($certificate->getKeys()['pkey']);
    }

    public function testACertificateWithPasswordCanBeCreated(): void
    {
        $certificate = $this->faker->createFake(password: 'another password');

        $this->assertSame('11222333-9', $certificate->getId());
    }

    public function testACertificateWithoutExtensionsAndWithoutSerialNumberHasNoId(): void
    {
        $certificate = $this->loadFixture('no-extensions');

        $this->assertSame([], $certificate->getIds());
    }

    public function testGetPrivateKeyDetails(): void
    {
        $details = $this->faker->createFake()->getPrivateKeyDetails();

        $this->assertGreaterThan(0, $details['bits']);
        $this->assertArrayHasKey('rsa', $details);
    }

    public function testSelfSignedCertificateThrowsExceptionForAnInvalidValidity(): void
    {
        $selfSigned = (new SelfSignedCertificate())->setValidity(-5);

        // PHP also emits a warning: the days must be between 0 and a maximum.
        set_error_handler(static fn (): bool => true);
        try {
            $this->expectException(CertificateException::class);
            $selfSigned->toPkcs12();
        } finally {
            restore_error_handler();
        }
    }
}
