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
use Derafu\Certificate\Contract\CertificateValidatorInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\SelfSignedCertificate;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Certificate\Service\CertificateValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(CertificateValidator::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(CertificateException::class)]
#[CoversClass(SelfSignedCertificate::class)]
#[CoversClass(CertificateFaker::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(AsymmetricKeyHelper::class)]
final class CertificateValidatorTest extends TestCase
{
    private const CHILEAN_ID_FORMAT = '/^\\d+-[\\dK]$/';

    private CertificateFakerInterface $faker;

    private CertificateValidatorInterface $validator;

    protected function setUp(): void
    {
        $loader = new CertificateLoader();
        $this->faker = new CertificateFaker($loader);
        $this->validator = new CertificateValidator();
    }

    public function testValidCertificate(): void
    {
        $certificate = $this->faker->createFake();
        $this->validator->validate($certificate);
        $this->assertTrue($certificate->isActive());
    }

    public function testWithoutFormatAnyIdIsValid(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->validate($this->faker->createFake(id: '123'));
        $this->validator->validate($this->faker->createFake(id: 'any id'));
    }

    /**
     * The format of the ID is the one of the national ID of Chile (RUN): digits,
     * a dash and a check character that is a digit or an uppercase "K".
     */
    #[DataProvider('validIdsProvider')]
    public function testAnIdThatMatchesTheFormatIsValid(string $id): void
    {
        $this->expectNotToPerformAssertions();

        $validator = new CertificateValidator(self::CHILEAN_ID_FORMAT);
        $validator->validate($this->faker->createFake(id: $id));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validIdsProvider(): array
    {
        return [
            'with a digit' => ['11222333-9'],
            'with an uppercase K' => ['10-K'],
            'short' => ['1-9'],
        ];
    }

    #[DataProvider('invalidIdsProvider')]
    public function testAnIdThatDoesNotMatchTheFormatIsNotValid(string $id): void
    {
        $certificate = $this->createStub(CertificateInterface::class);
        $certificate->method('getId')->willReturn($id);
        $validator = new CertificateValidator(self::CHILEAN_ID_FORMAT);

        try {
            $validator->validate($certificate);
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertStringContainsString($id, $e->getMessage());
            $this->assertStringContainsString(self::CHILEAN_ID_FORMAT, $e->getMessage());
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIdsProvider(): array
    {
        return [
            'without dash' => ['123'],
            'with a lowercase k' => ['10-k'],
            'with letters' => ['abc-9'],
            'with a long check' => ['10-99'],
            'empty' => [''],
        ];
    }

    public function testAnInvalidFormatIsRejectedWhenTheValidatorIsCreated(): void
    {
        $this->expectException(CertificateException::class);
        new CertificateValidator('/(unclosed');
    }

    public function testAnExpiredCertificateIsNotValid(): void
    {
        $certificate = $this->createStub(CertificateInterface::class);
        $certificate->method('getId')->willReturn('11222333-9');
        $certificate->method('isActive')->willReturn(false);
        $certificate->method('getTo')->willReturn('2020-01-01T23:59:59');

        try {
            $this->validator->validate($certificate);
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertStringContainsString('2020-01-01T23:59:59', $e->getMessage());
        }
    }
}
