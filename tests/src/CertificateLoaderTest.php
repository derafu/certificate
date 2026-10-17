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
use Derafu\Certificate\Service\OpenSsl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpenSsl::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(CertificateException::class)]
#[CoversClass(CertificateFaker::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(AsymmetricKeyHelper::class)]
#[CoversClass(SelfSignedCertificate::class)]
final class CertificateLoaderTest extends TestCase
{
    private CertificateLoaderInterface $loader;

    private CertificateFakerInterface $faker;

    protected function setUp(): void
    {
        $this->loader = new CertificateLoader();
        $this->faker = new CertificateFaker($this->loader);
    }

    public function testCreateFromFile(): void
    {
        $password = 'hola_mundo';

        $data = $this->faker->createFake()->getPkcs12($password);
        $tempFile = tempnam(sys_get_temp_dir(), 'cert');
        file_put_contents($tempFile, $data);

        $certificate = $this->loader->loadFromFile($tempFile, $password);

        $this->assertInstanceOf(CertificateInterface::class, $certificate);
        unlink($tempFile);
    }

    public function testCreateFromData(): void
    {
        $password = 'hola_mundo';

        $data = $this->faker->createFake()->getPkcs12($password);
        $certificate = $this->loader->loadFromData($data, $password);

        $this->assertInstanceOf(CertificateInterface::class, $certificate);
    }

    /**
     * Ensures that the intermediate CA certificate bundled in the PKCS#12
     * data (its additional certificates) is preserved as the trust chain of
     * the loaded certificate, instead of being silently discarded.
     */
    public function testCreateFromDataPreservesCertificateChain(): void
    {
        $password = 'hola_mundo';

        $data = $this->faker->createFake()->getPkcs12($password);
        $certificate = $this->loader->loadFromData($data, $password);

        $chain = $certificate->getCertificateChain();
        $this->assertCount(1, $chain);
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $chain[0]);
    }

    public function testCreateFromArray(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certificate = $this->loader->loadFromArray($certs);
        $this->assertInstanceOf(CertificateInterface::class, $certificate);
    }

    /**
     * Ensures that the chain produced by `getKeys()` round-trips through
     * `loadFromArray()`.
     */
    public function testCreateFromArrayPreservesCertificateChain(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $this->assertCount(1, $certs['chain']);

        $certificate = $this->loader->loadFromArray($certs);
        $this->assertCount(1, $certificate->getCertificateChain());
    }

    /**
     * Ensures that a Certificate can be loaded from a certificate only
     * (no private key), for verification-only scenarios.
     */
    public function testLoadFromCertificate(): void
    {
        $original = $this->faker->createFake();

        $certificate = $this->loader->loadFromCertificate(
            $original->getCertificate()
        );

        $this->assertInstanceOf(CertificateInterface::class, $certificate);
        $this->assertSame($original->getId(), $certificate->getId());

        $this->expectException(CertificateException::class);
        $certificate->getPrivateKey();
    }

    /**
     * Ensures that the trust chain can be provided explicitly to
     * `loadFromCertificate()`.
     */
    public function testLoadFromCertificateWithChain(): void
    {
        $original = $this->faker->createFake();

        $certificate = $this->loader->loadFromCertificate(
            $original->getCertificate(),
            $original->getCertificateChain()
        );

        $this->assertCount(1, $certificate->getCertificateChain());
    }

    /**
     * Ensures that the trust chain can be provided explicitly to
     * `loadFromKeys()`.
     */
    public function testLoadFromKeysWithChain(): void
    {
        $original = $this->faker->createFake();

        $certificate = $this->loader->loadFromKeys(
            $original->getCertificate(),
            $original->getPrivateKey(),
            $original->getCertificateChain()
        );

        $this->assertCount(1, $certificate->getCertificateChain());
    }

    /**
     * Ensures that an exception is thrown when trying to load a certificate
     * file that is not readable.
     */
    public function testCreateFromFileThrowsExceptionForUnreadableFile(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('It was not possible to read the digital certificate file from');
        $this->loader->loadFromFile('/path/no/existe/cert.p12', 'testpass');
    }

    /**
     * Ensures that an exception is thrown when trying to load a certificate
     * from corrupted or invalid data.
     */
    public function testCreateFromDataThrowsExceptionForInvalidData(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('It was not possible to read the digital certificate data.');
        $invalidData = 'datos_corruptos';
        $this->loader->loadFromData($invalidData, 'testpass');
    }

    /**
     * Ensures that an exception is thrown when the array does not contain a
     * certificate.
     */
    public function testCreateFromArrayThrowsExceptionForMissingCertificate(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The certificate was not found.');
        $certs = $this->faker->createFake()->getKeys();
        unset($certs['cert']); // Delete the certificate to simulate an invalid array.
        $this->loader->loadFromArray($certs);
    }

    /**
     * Ensures that an exception is thrown when the array does not contain a
     * private key.
     */
    public function testCreateFromArrayThrowsExceptionForMissingPrivateKey(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The private key of the certificate was not found.');
        $certs = $this->faker->createFake()->getKeys();
        unset($certs['pkey']); // Delete the private key to simulate an invalid array.
        $this->loader->loadFromArray($certs);
    }

    public function testCreateFromArrayThrowsExceptionForACertificateThatIsNotText(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certs['cert'] = 123;

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The certificate must be a text.');
        $this->loader->loadFromArray($certs);
    }

    public function testCreateFromArrayThrowsExceptionForAPrivateKeyThatIsNotText(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certs['pkey'] = ['not', 'text'];

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The private key of the certificate must be a text.');
        $this->loader->loadFromArray($certs);
    }

    public function testCreateFromArrayThrowsExceptionForAChainThatIsNotOnlyText(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certs['chain'] = ['text', 123];

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The chain of the certificate must contain only texts.');
        $this->loader->loadFromArray($certs);
    }

    public function testCreateFromArrayThrowsExceptionForAChainThatIsNotAnArray(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certs['chain'] = 'text';

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The chain of the certificate must contain only texts.');
        $this->loader->loadFromArray($certs);
    }

    public function testCreateFromArrayAcceptsAChainWithTextKeys(): void
    {
        $certs = $this->faker->createFake()->getKeys();
        $certs['chain'] = ['ca' => $certs['cert']];

        $certificate = $this->loader->loadFromArray($certs);

        $this->assertCount(1, $certificate->getCertificateChain());
    }

    /**
     * With empty data OpenSSL fails without leaving an error of its own, so
     * the exception has the message and no errors.
     */
    public function testCreateFromDataThrowsExceptionForEmptyData(): void
    {
        try {
            $this->loader->loadFromData('', 'password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertSame('It was not possible to read the digital certificate data.', $e->getMessage());
            $this->assertSame([], $e->getErrors());
        }
    }
}
