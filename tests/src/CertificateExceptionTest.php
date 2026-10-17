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
use Derafu\Certificate\Service\OpenSsl;
use Derafu\Certificate\Translation\CertificateTranslationResourceProvider;
use Derafu\Translation\TranslatableMessage;
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
#[CoversClass(OpenSsl::class)]
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
        $one = new TranslatableMessage('OpenSSL: {text}', ['text' => 'one'], domain: 'errors');
        $two = new TranslatableMessage('OpenSSL: {text}', ['text' => 'two'], domain: 'errors');
        $exception = new CertificateException('The certificate was not found.', errors: [$one, $two]);

        $this->assertSame('The certificate was not found.', $exception->getMessage());
        $this->assertSame([$one, $two], $exception->getErrors());
    }

    /**
     * The queue of errors of OpenSSL belongs to the process: an exception that
     * was not given errors has none, whatever is in the queue.
     */
    public function testWithoutErrorsItDoesNotTakeTheErrorsThatAreInTheQueueOfOpenssl(): void
    {
        while (openssl_error_string() !== false) {
            // Empty the queue of errors of OpenSSL.
        }
        @openssl_x509_parse('invalid');
        @openssl_pkey_get_private('invalid');

        $exception = new CertificateException('The certificate was not found.');

        $this->assertSame([], $exception->getErrors());
        // And it left the queue as it was.
        $pending = openssl_error_string();
        $this->assertIsString($pending);
        while (openssl_error_string() !== false) {
            // Empty the queue of errors of OpenSSL.
        }
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
            $this->assertStringContainsString((string) $e->getErrors()[0], $e->getMessage());
        }
    }

    /**
     * The errors of OpenSSL that are known are translated, in the message and
     * in the errors: the whole text is in the language of the translator, not
     * the sentence in one language and the reason of the failure in another.
     */
    public function testTheKnownErrorsAreTranslatedInTheMessageAndInTheErrors(): void
    {
        $openSsl = new OpenSsl();
        $key = $openSsl->pkeyNew();
        $certificate = $openSsl->csrSign($openSsl->csrNew(['commonName' => 'Test'], $key), null, $key, 1, [], 1);
        $pkcs12 = $openSsl->pkcs12Export($certificate, $key, 'right password');

        try {
            (new CertificateLoader())->loadFromData($pkcs12, 'wrong password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertSame(
                'No fue posible leer los datos del certificado digital. Falló la verificación MAC en el PKCS12, el certificado o la contraseña es incorrecta (Error #11800071).',
                $e->trans($this->translator())
            );
            $this->assertSame(
                'Falló la verificación MAC en el PKCS12, el certificado o la contraseña es incorrecta (Error #11800071).',
                $e->getErrors()[0]->trans($this->translator())
            );
            $this->assertSame(
                'It was not possible to read the digital certificate data. MAC verification failed in PKCS12, certificate or password is incorrect (Error #11800071).',
                $e->getMessage()
            );
        }
    }

    /**
     * An error of OpenSSL that is not known is the text of OpenSSL, that has no
     * translation, and it is what it is: it is not changed.
     */
    public function testAnErrorThatIsNotKnownIsTheTextOfOpensslInAnyLanguage(): void
    {
        try {
            (new CertificateLoader())->loadFromData('invalid', 'password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $error = $e->getErrors()[0];

            $this->assertSame('OpenSSL: error:0680008E:asn1 encoding routines::not enough data', (string) $error);
            $this->assertSame((string) $error, $error->trans($this->translator()));
        }
    }
}
