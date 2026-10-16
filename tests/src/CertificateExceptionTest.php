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

use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Certificate\Translation\CertificateTranslationResourceProvider;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Translation\Translator;

/**
 * The exception of the package is a translatable exception like any other:
 * what it says is its message. What went wrong in detail (the errors of
 * OpenSSL) is data that it carries, not text that is added to the message.
 */
#[CoversClass(CertificateException::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(CertificateTranslationResourceProvider::class)]
final class CertificateExceptionTest extends TestCase
{
    private function translator(): Translator
    {
        return TranslatorFactory::create('es', [], [new CertificateTranslationResourceProvider()]);
    }

    public function testItIsTranslatedIntoTheLanguageOfTheTranslator(): void
    {
        $exception = new CertificateException(['The certificate expired on {date}, it must use a valid certificate. If you do not have one, you must acquire it from an authorized provider.', 'date' => '2020-01-01']);

        $this->assertStringStartsWith('The certificate expired on 2020-01-01,', $exception->getMessage());
        $this->assertStringStartsWith(
            'El certificado venció el 2020-01-01,',
            $exception->trans($this->translator())
        );
    }

    public function testItKeepsTheCodeAndThePreviousThrowable(): void
    {
        $previous = new RuntimeException('previous');
        $exception = new CertificateException('The certificate was not found.', 7, $previous);

        $this->assertSame(7, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testTheErrorsAreDataAndNotPartOfTheMessage(): void
    {
        $exception = new CertificateException('The certificate was not found.', errors: ['one', 'two']);

        $this->assertSame('The certificate was not found.', $exception->getMessage());
        $this->assertSame(['one', 'two'], $exception->getErrors());
    }

    public function testWithoutErrorsItTakesThePendingErrorsOfOpenssl(): void
    {
        while (openssl_error_string() !== false) {
            // Empty the queue of errors of OpenSSL.
        }
        @openssl_x509_parse('invalid');
        @openssl_pkey_get_private('invalid');

        $exception = new CertificateException('The certificate was not found.');

        $this->assertNotSame([], $exception->getErrors());
        $this->assertSame('The certificate was not found.', $exception->getMessage());
    }

    public function testTheKnownErrorsOfOpensslAreTranslatedForHumans(): void
    {
        while (openssl_error_string() !== false) {
            // Empty the queue of errors of OpenSSL.
        }
        @openssl_pkcs12_read('invalid', $certs, 'password');

        // The error of OpenSSL is unknown, so it is as OpenSSL says it.
        $unknown = CertificateException::opensslErrors();
        $this->assertNotSame([], $unknown);
        $this->assertStringContainsString('error:', $unknown[0]);

        // A known one is replaced by its explanation and its code.
        openssl_pkcs12_export(
            (string) file_get_contents(__DIR__ . '/../fixtures/repeated-fields.cert.pem'),
            $data,
            (string) file_get_contents(__DIR__ . '/../fixtures/repeated-fields.key.pem'),
            'password'
        );
        @openssl_pkcs12_read($data, $certs, 'wrong password');
        $errors = CertificateException::opensslErrors();
        $this->assertContains(
            'MAC verification failed in PKCS12, certificate or password is incorrect (Error #11800071).',
            $errors
        );
    }

    public function testTheErrorsOfDataThatCanNotBeLoadedAreInTheMessageAndInTheErrors(): void
    {
        try {
            (new CertificateLoader())->loadFromData('invalid', 'password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertNotSame([], $e->getErrors());
            $this->assertStringStartsWith(
                'It was not possible to read the digital certificate data. ',
                $e->getMessage()
            );
            $this->assertStringContainsString($e->getErrors()[0], $e->getMessage());
        }
    }
}
