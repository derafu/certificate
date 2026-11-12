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
use Derafu\Certificate\DistinguishedName;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\SelfSignedCertificate;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Certificate\Service\OpenSsl;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What identifies a certificate: its serial number, its fingerprint and the
 * distinguished name of its issuer.
 */
#[CoversClass(Certificate::class)]
#[CoversClass(DistinguishedName::class)]
#[CoversClass(CertificateException::class)]
#[CoversClass(OpenSsl::class)]
#[CoversClass(CertificateFaker::class)]
#[CoversClass(CertificateLoader::class)]
#[CoversClass(AsymmetricKeyHelper::class)]
#[CoversClass(SelfSignedCertificate::class)]
final class CertificateIdentifiersTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../fixtures/';

    private function fixture(string $name): Certificate
    {
        return new Certificate((string) file_get_contents(self::FIXTURES . $name . '.cert.pem'));
    }

    /**
     * Makes a self-signed certificate whose issuer has the given name.
     *
     * @param array<string, string> $dn
     */
    private function selfSigned(array $dn, int $serial): Certificate
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            $this->fail('OpenSSL could not make the key.');
        }
        $copy = $key;
        $request = openssl_csr_new($dn, $copy);
        if (!$request instanceof OpenSSLCertificateSigningRequest) {
            $this->fail('OpenSSL could not make the request of the certificate.');
        }
        $certificate = openssl_csr_sign($request, null, $key, 2, [], $serial);
        if (!$certificate instanceof OpenSSLCertificate) {
            $this->fail('OpenSSL could not sign the certificate.');
        }

        $pem = '';
        $privateKey = '';
        $this->assertTrue(openssl_x509_export($certificate, $pem));
        $copy = $key;
        $this->assertTrue(openssl_pkey_export($copy, $privateKey));
        $this->assertIsString($pem);
        $this->assertIsString($privateKey);

        return new Certificate($pem, $privateKey);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function serialProvider(): array
    {
        return [
            // Larger than an integer: OpenSSL gives it as hexadecimal.
            'larger than 64 bits' => ['oasis-ubl', '17517295961972146475'],
            'of 160 bits, one' => ['no-extensions', '337327660841019170709866522403337268262884511495'],
            'of 160 bits, two' => ['repeated-fields', '264071301517740966479857068611351727129912289443'],
            'of 160 bits, three' => ['ec-no-id', '657882793279225817261135698567242483772103199678'],
            'of 160 bits, four' => ['san-id', '473083512582697220662289149989916191314673608830'],
        ];
    }

    #[DataProvider('serialProvider')]
    public function testTheSerialNumberIsInDecimalWhateverItsSize(string $fixture, string $expected): void
    {
        $this->assertSame($expected, $this->fixture($fixture)->getSerialNumber());
    }

    /**
     * @return array<string, array{int, string}>
     */
    public static function smallSerialProvider(): array
    {
        return [
            'one' => [1, '1'],
            'a byte' => [255, '255'],
            'more than a byte' => [256, '256'],
            'ten' => [10, '10'],
            'the largest integer' => [9223372036854775807, '9223372036854775807'],
        ];
    }

    #[DataProvider('smallSerialProvider')]
    public function testASerialNumberThatFitsInAnIntegerIsTheSame(int $serial, string $expected): void
    {
        $certificate = $this->selfSigned(['commonName' => 'Serial'], $serial);

        $this->assertSame($expected, $certificate->getSerialNumber());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function algorithmProvider(): array
    {
        return ['sha1' => ['sha1'], 'sha256' => ['sha256'], 'sha384' => ['sha384'], 'sha512' => ['sha512'], 'md5' => ['md5']];
    }

    #[DataProvider('algorithmProvider')]
    public function testTheFingerprintIsTheOneOfOpenSsl(string $algorithm): void
    {
        $certificate = $this->fixture('oasis-ubl');
        $pem = (string) file_get_contents(self::FIXTURES . 'oasis-ubl.cert.pem');

        $this->assertSame(openssl_x509_fingerprint($pem, $algorithm), $certificate->getFingerprint($algorithm));
        $this->assertSame(openssl_x509_fingerprint($pem, $algorithm, true), $certificate->getFingerprint($algorithm, true));
        $this->assertSame(hex2bin($certificate->getFingerprint($algorithm)), $certificate->getFingerprint($algorithm, true));
    }

    public function testTheFingerprintIsSha256ByDefault(): void
    {
        $certificate = $this->fixture('san-id');

        $this->assertSame($certificate->getFingerprint('sha256'), $certificate->getFingerprint());
        $this->assertSame(64, strlen($certificate->getFingerprint()));
        $this->assertSame(32, strlen($certificate->getFingerprint(binary: true)));
    }

    public function testTheFingerprintOfAnAlgorithmThatIsNotSupportedIsAnError(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The hash algorithm "sha-0" is not supported.');

        $this->fixture('san-id')->getFingerprint('sha-0');
    }

    public function testTheIssuerOfTheOasisCertificateIsTheOneOfItsOwnSignature(): void
    {
        // The name that the signed example of OASIS has in its `X509IssuerName`.
        $this->assertSame(
            'CN=UBL TC,OU=UBL Technical Committee,O=OASIS,L=Burlington,ST=Massachusetts,C=US',
            $this->fixture('oasis-ubl')->getIssuerDn()
        );
    }

    public function testTheIssuerIsTheOneThatOpenSslWritesWhenItsAttributesHaveName(): void
    {
        foreach (['oasis-ubl', 'ec-no-id', 'no-extensions', 'san-id'] as $fixture) {
            exec(
                'openssl x509 -noout -issuer -nameopt RFC2253 -in ' . escapeshellarg(self::FIXTURES . $fixture . '.cert.pem') . ' 2>&1',
                $lines,
                $status
            );
            if ($status !== 0) {
                $this->markTestSkipped('The openssl command is not installed.');
            }

            $this->assertSame(
                'issuer=' . $this->fixture($fixture)->getIssuerDn(),
                implode("\n", $lines),
                $fixture
            );
            $lines = [];
        }
    }

    public function testTheIssuerIsTheSameNameThatOpenSslWritesWithTheNamesOfTheAttributes(): void
    {
        foreach (['oasis-ubl', 'repeated-fields', 'no-extensions', 'san-id', 'ec-no-id'] as $fixture) {
            $lines = [];
            exec(
                'openssl x509 -noout -issuer -nameopt RFC2253 -in ' . escapeshellarg(self::FIXTURES . $fixture . '.cert.pem') . ' 2>&1',
                $lines,
                $status
            );
            if ($status !== 0) {
                $this->markTestSkipped('The openssl command is not installed.');
            }

            // `issuer=` and the name, written with the names that OpenSSL gives to the attributes.
            $this->assertTrue(
                DistinguishedName::equals((string) preg_replace('/^issuer=/', '', implode("\n", $lines)), $this->fixture($fixture)->getIssuerDn()),
                $fixture
            );
        }
    }

    public function testTheAttributesRepeatedInTheIssuerKeepTheirOrderAndTheOnesWithoutNameHaveTheirOid(): void
    {
        // CN, CN, emailAddress, emailAddress, serialNumber and serialNumber, as the
        // certificate has them, written in the inverse order.
        $this->assertSame(
            '2.5.4.5=#130a34343535353636362d37,2.5.4.5=#130a31313232323333332d39,'
            . '1.2.840.113549.1.9.1=#1611616e612e70406578616d706c652e636f6d,'
            . '1.2.840.113549.1.9.1=#160f616e61406578616d706c652e636f6d,'
            . 'CN=Ana P.,CN=Ana Perez',
            $this->fixture('repeated-fields')->getIssuerDn()
        );
    }

    public function testTheIssuerOfTheFakeCertificateHasTheAttributesOfTheAuthority(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();

        $this->assertSame(
            '2.5.4.5=#130a37363139323038332d39,'
            . '1.2.840.113549.1.9.1=#161d66616b65732d636572746966696361746573406465726166752e6f7267,'
            . 'CN=Derafu Test Certificate Authority,OU=Technology,O=Derafu,L=Santa Cruz,ST=Colchagua,C=CL',
            $certificate->getIssuerDn()
        );
    }

    public function testTheCharactersOfTheNameThatRfc4514EscapesAreEscaped(): void
    {
        $certificate = $this->selfSigned([
            'countryName' => 'CL',
            'organizationName' => ' lead, space',
            'organizationalUnitName' => '#hash+plus',
            'commonName' => 'A "q" <b>;c\\d trail  ',
            'stateOrProvinceName' => 'Ñuñoa',
        ], 1);

        // The text of non ASCII characters is as it is: RFC 4514 writes UTF-8.
        $this->assertSame(
            'ST=Ñuñoa,CN=A \"q\" \<b\>\;c\\\\d trail \ ,OU=\#hash\+plus,O=\ lead\, space,C=CL',
            $certificate->getIssuerDn()
        );
    }

    public function testTheSerialNumberOfACertificateThatCanNotBeReadIsAnError(): void
    {
        $certificate = (new CertificateLoader())->loadFromKeys('invalid', 'invalid');

        $this->expectException(CertificateException::class);

        $certificate->getSerialNumber();
    }

    public function testTheIssuerOfACertificateThatIsNotDerIsAnError(): void
    {
        $certificate = new Certificate("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n");

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The distinguished name of the certificate could not be read.');

        $certificate->getIssuerDn();
    }

    public function testACertificateThatIsNotBase64CanNotBeReadAsDer(): void
    {
        $certificate = new Certificate("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n");

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The certificate could not be read as DER.');

        $certificate->getFingerprint();
    }

    /**
     * The ID is the serial number of the subject without the spaces and without
     * the zeros that go first, and in capital letters unless it is asked to be
     * left as it is.
     */
    public function testTheIdsAreWithoutSpacesAndLeadingZerosAndInCapitalLettersByDefault(): void
    {
        $certificate = $this->selfSigned(['commonName' => 'x', 'serialNumber' => '0012-k '], 5);

        $this->assertSame(['12-K'], $certificate->getIds());
        $this->assertSame(['12-k'], $certificate->getIds(false));
        $this->assertSame('12-K', $certificate->getId());
        $this->assertSame('12-k', $certificate->getId(false));
    }

    /**
     * Only the subject alternative name has an ID: another extension that has
     * the same structure does not, and it is searched in all the extensions, in
     * whatever place it is.
     */
    public function testTheIdOfTheSubjectAlternativeNameIsFoundAfterOtherExtensions(): void
    {
        $this->assertSame(['12-3'], $this->fixture('ids-in-other-extensions')->getIds());
    }

    public function testAnIdThatIsNotInCapitalLettersIsLeftAsItIs(): void
    {
        $certificate = $this->fixture('lowercase-id');

        $this->assertSame('10-k', $certificate->getId(false));
        $this->assertSame('10-K', $certificate->getId());
    }

    public function testASerialNumberOfZeroIsZero(): void
    {
        $this->assertSame('0', $this->selfSigned(['commonName' => 'x'], 0)->getSerialNumber());
    }

    /**
     * A name, an email and an issuer are asked from a certificate that has none:
     * it is an error of the package, not a value that is not a text.
     */
    public function testACertificateWithoutCommonNameAndEmailHasNoNameNorEmailNorIssuer(): void
    {
        $certificate = $this->selfSigned(['organizationName' => 'Organization'], 7);

        foreach (['getName', 'getEmail', 'getIssuer'] as $method) {
            try {
                $certificate->$method();
                $this->fail($method . '() should have failed.');
            } catch (CertificateException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /**
     * The certificate is active from the first second of its validity to the
     * last one.
     */
    public function testTheCertificateIsActiveInTheFirstAndTheLastSecondOfItsValidity(): void
    {
        $certificate = $this->selfSigned(['commonName' => 'x'], 5);

        $this->assertTrue($certificate->isActive($certificate->getFrom()));
        $this->assertTrue($certificate->isActive($certificate->getTo()));
    }

    public function testTheModulusIsWrappedInLinesOf64CharactersByDefault(): void
    {
        $lines = explode("\n", $this->selfSigned(['commonName' => 'x'], 5)->getModulus());

        $this->assertGreaterThan(1, count($lines));
        $this->assertSame(64, strlen($lines[0]));
    }

    /**
     * The certificate and its chain are written one after the other, whatever
     * the number of certificates in the chain.
     */
    public function testTheBundleHasTheCertificateAndEveryCertificateOfTheChain(): void
    {
        $leaf = $this->selfSigned(['commonName' => 'leaf'], 1);
        $first = $this->selfSigned(['commonName' => 'first'], 2);
        $second = $this->selfSigned(['commonName' => 'second'], 3);

        $chained = new Certificate($leaf->getCertificate(), null, [$first->getCertificate(), $second->getCertificate()]);

        $this->assertSame($leaf->getCertificate(), (new Certificate($leaf->getCertificate()))->getCertificateBundle());
        $this->assertSame(
            $leaf->getCertificate() . $first->getCertificate() . $second->getCertificate(),
            $chained->getCertificateBundle()
        );
    }

    public function testTheKeysAreNotCleanUnlessTheyAreAskedToBe(): void
    {
        $certificate = $this->selfSigned(['commonName' => 'x'], 5);

        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $certificate->getKeys()['cert']);
        $this->assertStringNotContainsString('-----', $certificate->getKeys(true)['cert']);
    }

    /**
     * What is left of a certificate without the header and the footer is the
     * body: without the line breaks that were around it.
     */
    public function testTheCleanCertificateHasNoSpacesAroundIt(): void
    {
        $clean = $this->selfSigned(['commonName' => 'x'], 5)->getCertificate(true);

        $this->assertSame(trim($clean), $clean);
        $this->assertNotSame('', $clean);
    }
}
