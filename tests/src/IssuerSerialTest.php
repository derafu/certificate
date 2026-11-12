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
use Derafu\Certificate\IssuerSerial;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The DER of the issuer, of the serial number and of the `IssuerSerial` of a
 * certificate, as the certificate has them. The expected values were made with
 * another implementation (the `cryptography` library of Python) from the same
 * certificates.
 */
#[CoversClass(IssuerSerial::class)]
#[UsesClass(AsymmetricKeyHelper::class)]
#[CoversClass(DistinguishedName::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(CertificateException::class)]
final class IssuerSerialTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../fixtures/';

    /**
     * @return array<string, array{string, string, string, string}>
     */
    public static function certificateProvider(): array
    {
        return [
            'a serial number that has a byte of zeros before' => [
                'oasis-ubl',
                '307d310b30090603550406130255533116301406035504080c0d4d6173736163687573657474733113301106035504070c0a4275726c696e67746f6e310e300c060355040a0c054f415349533120301e060355040b0c1755424c20546563686e6963616c20436f6d6d6974746565310f300d06035504030c0655424c205443',
                '020900f319efdde6bc012b',
                '30818f308181a47f307d310b30090603550406130255533116301406035504080c0d4d6173736163687573657474733113301106035504070c0a4275726c696e67746f6e310e300c060355040a0c054f415349533120301e060355040b0c1755424c20546563686e6963616c20436f6d6d6974746565310f300d06035504030c0655424c205443020900f319efdde6bc012b',
            ],
            'an issuer that is short' => [
                'no-extensions',
                '30183116301406035504030c0d4e6f20457874656e73696f6e73',
                '02143b164ba33c9e0a77760fd6002145b760d9ea8f07',
                '3034301ca41a30183116301406035504030c0d4e6f20457874656e73696f6e7302143b164ba33c9e0a77760fd6002145b760d9ea8f07',
            ],
            'an issuer with repeated attributes' => [
                'repeated-fields',
                '3081913112301006035504030c09416e6120506572657a310f300d06035504030c06416e6120502e311e301c06092a864886f70d010901160f616e61406578616d706c652e636f6d3120301e06092a864886f70d0109011611616e612e70406578616d706c652e636f6d311330110603550405130a31313232323333332d39311330110603550405130a34343535353636362d37',
                '02142e415ddfdef8c8f7a8e6a3bba75add69437628a3',
                '3081b0308197a481943081913112301006035504030c09416e6120506572657a310f300d06035504030c06416e6120502e311e301c06092a864886f70d010901160f616e61406578616d706c652e636f6d3120301e06092a864886f70d0109011611616e612e70406578616d706c652e636f6d311330110603550405130a31313232323333332d39311330110603550405130a34343535353636362d3702142e415ddfdef8c8f7a8e6a3bba75add69437628a3',
            ],
        ];
    }

    private function der(string $fixture): string
    {
        $pem = (string) file_get_contents(self::FIXTURES . $fixture . '.cert.pem');

        return (string) base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem), true);
    }

    #[DataProvider('certificateProvider')]
    public function testTheIssuerAndTheSerialNumberAreTheBytesOfTheCertificate(string $fixture, string $issuer, string $serial, string $expected): void
    {
        $this->assertSame($issuer, bin2hex(DistinguishedName::issuerDerOf($this->der($fixture))));
        $this->assertSame($serial, bin2hex(DistinguishedName::serialDerOf($this->der($fixture))));
    }

    #[DataProvider('certificateProvider')]
    public function testTheIssuerSerialIsTheOneThatRfc5035Defines(string $fixture, string $issuer, string $serial, string $expected): void
    {
        $certificate = new Certificate((string) file_get_contents(self::FIXTURES . $fixture . '.cert.pem'));

        $this->assertSame($expected, bin2hex($certificate->getIssuerSerialDer()));
        $this->assertSame($expected, bin2hex(IssuerSerial::derOf($this->der($fixture))));
    }

    public function testTheIssuerSerialIsReadByOpenSslAsTheIssuerAndTheSerialNumber(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'issuer-serial');
        $this->assertNotFalse($file);
        $certificate = new Certificate((string) file_get_contents(self::FIXTURES . 'oasis-ubl.cert.pem'));
        file_put_contents($file, $certificate->getIssuerSerialDer());
        exec('openssl asn1parse -inform DER -in ' . escapeshellarg($file) . ' 2>&1', $lines, $status);
        unlink($file);
        if ($status !== 0) {
            $this->markTestSkipped('The openssl command is not installed.');
        }

        $text = implode("\n", $lines);
        $this->assertStringContainsString('cont [ 4 ]', $text);
        $this->assertStringContainsString('commonName', $text);
        $this->assertStringContainsString('UBL TC', $text);
        $this->assertStringContainsString('INTEGER           :F319EFDDE6BC012B', $text);
    }

    public function testAnIssuerSerialLargerThanThe127BytesUsesTheLongFormOfTheLength(): void
    {
        // The issuer has 127 bytes, so its sequences and the one of the issuer
        // serial are larger than what the short form says.
        $der = $this->der('oasis-ubl');
        $issuerSerial = IssuerSerial::derOf($der);

        $this->assertSame(127, strlen(DistinguishedName::issuerDerOf($der)));
        $this->assertSame("\x30\x81\x8f", substr($issuerSerial, 0, 3));
        $this->assertSame(0x8f + 3, strlen($issuerSerial));
    }

    public function testALongerIssuerUsesTwoBytesForTheLength(): void
    {
        // An issuer of 300 bytes, in a certificate that has only what is before it.
        $name = "\x30\x82\x01\x2C" . str_repeat("\x00", 300);
        $tbs = "\x02\x01\x01\x30\x00" . $name . "\x30\x00";
        $der = "\x30\x82" . pack('n', strlen($tbs) + 4) . "\x30\x82" . pack('n', strlen($tbs)) . $tbs;

        $issuerSerial = IssuerSerial::derOf($der);

        $this->assertStringContainsString("\xA4\x82\x01\x30", $issuerSerial);
        $this->assertSame("\x02\x01\x01", substr($issuerSerial, -3));
    }

    public function testTheIssuerSerialOfAnInvalidCertificateIsAnError(): void
    {
        $certificate = new Certificate("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n");

        $this->expectException(CertificateException::class);

        $certificate->getIssuerSerialDer();
    }

    public function testTheIssuerAndTheSerialNumberOfSomethingThatIsNotACertificateAreAnError(): void
    {
        $this->expectException(CertificateException::class);

        DistinguishedName::serialDerOf("\x30\x00");
    }

    /**
     * An element of 128 bytes is the first that needs the long form of the
     * length: the byte `0x80` alone would be the indefinite length.
     */
    public function testAnElementOf128BytesUsesTheLongFormOfTheLength(): void
    {
        // A name of 128 bytes: a sequence with a set with an attribute with a
        // text of 115 bytes.
        $text = $this->tlv(0x0C, str_repeat('x', 115));
        $attribute = $this->tlv(0x30, "\x06\x03\x55\x04\x03" . $text);
        $issuer = $this->tlv(0x30, $this->tlv(0x31, $attribute));
        $this->assertSame(128, strlen($issuer));

        $der = $this->tlv(0x30, $this->tlv(0x30, $this->tlv(0x02, "\x01") . $this->tlv(0x30, "\x06\x01\x2A") . $issuer . $this->tlv(0x30, '')));

        // The `[4]` that holds the issuer has 128 bytes of content.
        $this->assertStringContainsString("\xA4\x81\x80" . $issuer, IssuerSerial::derOf($der));
    }

    private function tlv(int $tag, string $content): string
    {
        $length = strlen($content);

        return pack('C', $tag) . ($length < 0x80 ? pack('C', $length) : "\x81" . pack('C', $length)) . $content;
    }
}
