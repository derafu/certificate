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
use Derafu\Certificate\Service\OpenSsl;
use Derafu\Certificate\Translation\CertificateTranslationResourceProvider;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Translation\TranslatorFactory;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Symfony\Component\Translation\Translator;

/**
 * The service is the only place that calls OpenSSL. The queue of errors of
 * OpenSSL belongs to the process, not to the call, so the service empties it
 * before each call and takes from it after: what is in the errors of an
 * exception is what that call left, and nothing is left behind.
 */
#[CoversClass(OpenSsl::class)]
#[CoversClass(CertificateException::class)]
#[CoversClass(CertificateTranslationResourceProvider::class)]
final class OpenSslTest extends TestCase
{
    private OpenSsl $openSsl;

    protected function setUp(): void
    {
        $this->openSsl = new OpenSsl();
    }

    /**
     * Leaves errors in the queue of OpenSSL, as any other code could do.
     */
    private function dirtyTheQueue(): void
    {
        $key = openssl_pkey_new();
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        openssl_sign('data', $signature, $key, OPENSSL_ALGO_SHA256);
        $certificate = $this->selfSignedCertificate($key);
        // A signature that is not valid is a result (0), and leaves errors.
        openssl_verify('tampered', 'signature', $certificate, OPENSSL_ALGO_SHA256);
    }

    private function selfSignedCertificate(OpenSSLAsymmetricKey $key): OpenSSLCertificate
    {
        $csr = openssl_csr_new(['commonName' => 'Test'], $key);
        $this->assertInstanceOf(OpenSSLCertificateSigningRequest::class, $csr);
        $certificate = openssl_csr_sign($csr, null, $key, 1, [], 1);
        $this->assertInstanceOf(OpenSSLCertificate::class, $certificate);

        return $certificate;
    }

    private function queueIsEmpty(): bool
    {
        return openssl_error_string() === false;
    }

    public function testItSignsAndVerifies(): void
    {
        $key = $this->openSsl->pkeyNew();
        $certificate = $this->selfSignedCertificate($key);
        openssl_pkey_export($key, $privateKey);
        openssl_x509_export($certificate, $pem);

        $signature = $this->openSsl->sign('hello', $privateKey, OPENSSL_ALGO_SHA1);

        $this->assertTrue($this->openSsl->verify('hello', $signature, $pem, OPENSSL_ALGO_SHA1));
        $this->assertFalse($this->openSsl->verify('tampered', $signature, $pem, OPENSSL_ALGO_SHA1));
    }

    public function testItReadsTheKeysAndTheDataOfACertificate(): void
    {
        $key = $this->openSsl->pkeyNew();
        $certificate = $this->selfSignedCertificate($key);
        openssl_pkey_export($key, $privateKey);
        openssl_x509_export($certificate, $pem);

        $this->assertArrayHasKey('bits', $this->openSsl->pkeyGetDetails($this->openSsl->pkeyGetPrivate($privateKey)));
        $this->assertArrayHasKey('key', $this->openSsl->pkeyGetDetails($this->openSsl->pkeyGetPublic($pem)));
        $this->assertSame('Test', $this->openSsl->x509Parse($pem)['subject']['CN']);
    }

    public function testItBuildsAndReadsAPkcs12(): void
    {
        $key = $this->openSsl->pkeyNew();
        $csr = $this->openSsl->csrNew(['commonName' => 'Test'], $key);
        $certificate = $this->openSsl->csrSign($csr, null, $key, 1, [], 1);

        $pkcs12 = $this->openSsl->pkcs12Export($certificate, $key, 'password');
        $read = $this->openSsl->pkcs12Read($pkcs12, 'password');

        $this->assertStringContainsString('BEGIN CERTIFICATE', $read['cert']);
        $this->assertStringContainsString('PRIVATE KEY', $read['pkey']);
    }

    public function testTheErrorsOfAnotherCallAreNotInTheErrorsOfAnException(): void
    {
        $this->dirtyTheQueue();

        try {
            $this->openSsl->pkcs12Read('invalid', 'password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertNotSame([], $e->getErrors());
            foreach ($e->getErrors() as $error) {
                $this->assertStringNotContainsString('bad signature', (string) $error);
                $this->assertStringNotContainsString('RSA lib', (string) $error);
            }
        }
    }

    public function testTheQueueIsEmptyAfterACallThatDoesNotFail(): void
    {
        $key = $this->openSsl->pkeyNew();
        $certificate = $this->selfSignedCertificate($key);
        openssl_x509_export($certificate, $pem);
        $signature = $this->openSsl->sign('hello', $this->privateKey($key), OPENSSL_ALGO_SHA256);

        // A signature that is not valid is a result, not an exception, and
        // OpenSSL leaves errors for it.
        $this->assertFalse($this->openSsl->verify('tampered', $signature, $pem, OPENSSL_ALGO_SHA256));

        $this->assertTrue($this->queueIsEmpty());
    }

    private function privateKey(OpenSSLAsymmetricKey $key): string
    {
        openssl_pkey_export($key, $privateKey);

        return $privateKey;
    }

    public function testTheQueueIsEmptyAfterACallThatFails(): void
    {
        try {
            $this->openSsl->pkcs12Read('invalid', 'password');
        } catch (CertificateException) {
        }

        $this->assertTrue($this->queueIsEmpty());
    }

    public function testAWarningOfPhpIsNotEmittedAndIsInTheErrors(): void
    {
        $key = $this->openSsl->pkeyNew();

        try {
            $this->openSsl->csrNew(['countryName' => 'CLX', 'commonName' => 'Test'], $key);
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertStringContainsString(
                'add_entry_by_NID',
                implode(' ', array_map('strval', $e->getErrors()))
            );
        }
    }

    public function testTheKnownErrorsAreExplained(): void
    {
        $key = $this->openSsl->pkeyNew();
        $csr = $this->openSsl->csrNew(['commonName' => 'Test'], $key);
        $certificate = $this->openSsl->csrSign($csr, null, $key, 1, [], 1);
        $pkcs12 = $this->openSsl->pkcs12Export($certificate, $key, 'right password');

        try {
            $this->openSsl->pkcs12Read($pkcs12, 'wrong password');
            $this->fail('It should have failed.');
        } catch (CertificateException $e) {
            $this->assertContains(
                'MAC verification failed in PKCS12, certificate or password is incorrect (Error #11800071).',
                array_map('strval', $e->getErrors())
            );
        }
    }

    public function testAVerificationThatFailsIsAnException(): void
    {
        $this->expectException(CertificateException::class);

        $this->openSsl->verify('data', 'signature', 'not a certificate', OPENSSL_ALGO_SHA256);
    }

    public function testASignatureWithAKeyThatIsNotValidIsAnException(): void
    {
        $this->expectException(CertificateException::class);

        $this->openSsl->sign('data', 'not a key', OPENSSL_ALGO_SHA256);
    }

    public function testTheKeysAndTheDataThatCanNotBeReadAreExceptions(): void
    {
        foreach ([
            fn () => $this->openSsl->pkeyGetPrivate('invalid'),
            fn () => $this->openSsl->pkeyGetPublic('invalid'),
            fn () => $this->openSsl->x509Parse('invalid'),
        ] as $call) {
            try {
                $call();
                $this->fail('It should have failed.');
            } catch (CertificateException $e) {
                $this->assertNotSame('', $e->getMessage());
            }
        }
    }

    public function testASigningRequestThatCanNotBeSignedIsAnException(): void
    {
        $key = $this->openSsl->pkeyNew();
        $csr = $this->openSsl->csrNew(['commonName' => 'Test'], $key);

        $this->expectException(CertificateException::class);

        // The days must be between 0 and a maximum.
        $this->openSsl->csrSign($csr, null, $key, -5, [], 1);
    }

    public function testAPkcs12ThatCanNotBeExportedIsAnException(): void
    {
        $key = $this->openSsl->pkeyNew();
        $other = $this->openSsl->pkeyNew();
        $csr = $this->openSsl->csrNew(['commonName' => 'Test'], $key);
        $certificate = $this->openSsl->csrSign($csr, null, $key, 1, [], 1);

        $this->expectException(CertificateException::class);

        // The private key is not the one of the certificate.
        $this->openSsl->pkcs12Export($certificate, $other, 'password');
    }

    public function testAKeyThatCanNotBeGeneratedIsAnException(): void
    {
        $this->expectException(CertificateException::class);

        // A key of 128 bits is too short for OpenSSL.
        $this->openSsl->pkeyNew(['private_key_bits' => 128]);
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function knownErrorsProvider(): array
    {
        return [
            'encryption algorithm' => ['0308010C', 'Unsupported encryption algorithm or method (Error #0308010C).', 'Algoritmo o método de cifrado no soportado (Error #0308010C).'],
            'mac' => ['11800071', 'MAC verification failed in PKCS12, certificate or password is incorrect (Error #11800071).', 'Falló la verificación MAC en el PKCS12, el certificado o la contraseña es incorrecta (Error #11800071).'],
            'x509' => ['0906D06C', 'Failed to load X.509 certificate (Error #0906D06C).', 'No fue posible cargar el certificado X.509 (Error #0906D06C).'],
            'pem' => ['0B080074', 'Invalid PEM format (Error #0B080074).', 'Formato PEM inválido (Error #0B080074).'],
            'key length' => ['0A000086', 'Key length not allowed (Error #0A000086).', 'Largo de clave no permitido (Error #0A000086).'],
            'private key password' => ['06065064', 'Private key error: incorrect password (Error #06065064).', 'Error de clave privada: contraseña incorrecta (Error #06065064).'],
            'ssl layer' => ['14094418', 'SSL layer error: invalid certificate or CA not known (Error #14094418).', 'Error de la capa SSL: certificado inválido o CA desconocida (Error #14094418).'],
            'ssl configuration' => ['14090086', 'SSL configuration error: certificate or key problem (Error #14090086).', 'Error de configuración SSL: problema con el certificado o la clave (Error #14090086).'],
            'certificate file' => ['0907B068', 'Error in reading a certificate file (Error #0907B068).', 'Error al leer un archivo de certificado (Error #0907B068).'],
            'ssl protocol' => ['1403100E', 'SSL error: incompatible protocol (Error #1403100E).', 'Error SSL: protocolo incompatible (Error #1403100E).'],
        ];
    }

    /**
     * Each known error of OpenSSL is a message of the catalogue, in English and
     * in Spanish. They can not be made to happen one by one (some are errors of
     * the SSL layer, that these functions do not use), so the text that OpenSSL
     * gives is tested as it gives it.
     */
    #[DataProvider('knownErrorsProvider')]
    public function testEachKnownErrorIsAMessageOfTheCatalogue(string $code, string $english, string $spanish): void
    {
        $error = $this->explain(sprintf('error:%s:lib:func::reason', $code));

        $this->assertSame($english, (string) $error);
        $this->assertSame($spanish, $error->trans($this->translator()));
    }

    public function testAnErrorThatIsNotKnownKeepsTheTextOfOpenssl(): void
    {
        foreach (['error:0680008E:asn1 encoding routines::not enough data', 'a text that is not an error of OpenSSL'] as $text) {
            $error = $this->explain($text);

            $this->assertSame('OpenSSL: ' . $text, (string) $error);
            $this->assertSame('OpenSSL: ' . $text, $error->trans($this->translator()));
        }
    }

    public function testTheTextOfAnErrorIsNotInterpretedAsAMessage(): void
    {
        $text = "error:0680008E: it's {not} a pattern, 'quoted'";

        $this->assertSame('OpenSSL: ' . $text, $this->explain($text)->trans($this->translator()));
    }

    private function translator(): Translator
    {
        return TranslatorFactory::create('es', [], [new CertificateTranslationResourceProvider()]);
    }

    private function explain(string $error): TranslatableInterface
    {
        $explain = new ReflectionMethod($this->openSsl, 'explain');

        $result = $explain->invoke($this->openSsl, $error);
        $this->assertInstanceOf(TranslatableInterface::class, $result);

        return $result;
    }
}
