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
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\SelfSignedCertificate;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Certificate\Service\CertificateService;
use Derafu\Certificate\Service\CertificateValidator;
use Derafu\Certificate\Service\OpenSsl;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The service delegates in the faker, the loader and the validator.
 */
#[CoversClass(OpenSsl::class)]
#[CoversClass(CertificateService::class)]
#[CoversClass(AsymmetricKeyHelper::class)]
#[CoversClass(CertificateFaker::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(CertificateValidator::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(SelfSignedCertificate::class)]
#[CoversClass(CertificateException::class)]
final class CertificateServiceTest extends TestCase
{
    private CertificateService $service;

    protected function setUp(): void
    {
        $loader = new CertificateLoader();
        $this->service = new CertificateService(
            new CertificateFaker($loader),
            $loader,
            new CertificateValidator('/^\\d+-[\\dK]$/')
        );
    }

    public function testCreateFake(): void
    {
        $certificate = $this->service->createFake('1-9', 'Ana', 'ana@example.com');

        $this->assertSame('1-9', $certificate->getId());
        $this->assertSame('Ana', $certificate->getName());
        $this->assertSame('ana@example.com', $certificate->getEmail());
    }

    public function testCreateFakeWithPassword(): void
    {
        $certificate = $this->service->createFake(password: 'another password');

        $this->assertSame('11222333-9', $certificate->getId());
    }

    public function testTheLoadMethodsGiveTheSameCertificate(): void
    {
        $original = $this->service->createFake();
        $keys = $original->getKeys();
        $password = 'secret';
        $pkcs12 = $original->getPkcs12($password);
        $file = tempnam(sys_get_temp_dir(), 'cert');
        file_put_contents((string) $file, $pkcs12);

        try {
            $loaded = [
                $this->service->loadFromFile((string) $file, $password),
                $this->service->loadFromData($pkcs12, $password),
                $this->service->loadFromArray($keys),
                $this->service->loadFromKeys($keys['cert'], (string) $keys['pkey']),
            ];
        } finally {
            unlink((string) $file);
        }

        foreach ($loaded as $certificate) {
            $this->assertSame($original->getId(), $certificate->getId());
            $this->assertSame($original->getModulus(), $certificate->getModulus());
        }

        $certificate = $this->service->loadFromCertificate($keys['cert']);
        $this->assertSame($original->getId(), $certificate->getId());
        $this->assertNull($certificate->getKeys()['pkey']);
    }

    public function testValidate(): void
    {
        $this->service->validate($this->service->createFake());

        $this->expectException(CertificateException::class);
        $this->service->validate($this->service->createFake('123'));
    }
}
