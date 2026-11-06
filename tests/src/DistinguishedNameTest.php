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

use Derafu\Certificate\DistinguishedName;
use Derafu\Certificate\Exception\CertificateException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The name of the issuer, written from the DER of a certificate as RFC 4514
 * says. The DER is made here, so every type of text, every attribute and every
 * way that the DER can be wrong is tried.
 */
#[CoversClass(DistinguishedName::class)]
#[CoversClass(CertificateException::class)]
final class DistinguishedNameTest extends TestCase
{
    private const SEQUENCE = 0x30;

    private const SET = 0x31;

    private const OID = 0x06;

    /**
     * Writes an element of the DER.
     */
    private function tlv(int $tag, string $content): string
    {
        $length = strlen($content);
        $header = $length < 0x80
            ? pack('C', $length)
            : pack('C', 0x80 | strlen(ltrim(pack('N', $length), "\x00"))) . ltrim(pack('N', $length), "\x00");

        return pack('C', $tag) . $header . $content;
    }

    /**
     * Writes the OID of dotted numbers.
     */
    private function oid(string $dotted): string
    {
        $numbers = array_map(intval(...), explode('.', $dotted));
        $first = 40 * $numbers[0] + $numbers[1];
        $content = '';
        foreach ([$first, ...array_slice($numbers, 2)] as $number) {
            $bytes = pack('C', $number & 0x7F);
            for ($number >>= 7; $number > 0; $number >>= 7) {
                $bytes = pack('C', 0x80 | ($number & 0x7F)) . $bytes;
            }
            $content .= $bytes;
        }

        return $this->tlv(self::OID, $content);
    }

    /**
     * Writes an attribute, with its OID and the element of its value.
     */
    private function attribute(string $oid, string $value): string
    {
        return $this->tlv(self::SEQUENCE, $this->oid($oid) . $value);
    }

    /**
     * Writes a name, with a set for each list of attributes.
     *
     * @param list<list<string>> $sets
     */
    private function names(array $sets): string
    {
        return $this->tlv(self::SEQUENCE, implode('', array_map(
            fn (array $attributes): string => $this->tlv(self::SET, implode('', $attributes)),
            $sets
        )));
    }

    /**
     * Writes a certificate that has only what is before its issuer, the
     * issuer, and something after it.
     */
    private function certificate(string $issuer, bool $version = true): string
    {
        $tbs = ($version ? $this->tlv(0xA0, $this->tlv(0x02, "\x02")) : '')
            . $this->tlv(0x02, "\x01")
            . $this->tlv(self::SEQUENCE, $this->oid('1.2.840.113549.1.1.11'))
            . $issuer
            . $this->tlv(self::SEQUENCE, '');

        return $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $tbs));
    }

    /**
     * @param list<list<string>> $sets
     */
    private function issuerOf(array $sets, bool $version = true): string
    {
        return DistinguishedName::issuerOf($this->certificate($this->names($sets), $version));
    }

    /**
     * @return array<string, array{int, string, string}>
     */
    public static function textProvider(): array
    {
        return [
            'UTF8String' => [0x0C, "\xC3\x91", 'Ñ'],
            'PrintableString' => [0x13, 'Ab 1', 'Ab 1'],
            'IA5String' => [0x16, 'a@b', 'a@b'],
            'NumericString' => [0x12, '123 45', '123 45'],
            'VisibleString' => [0x1A, 'Visible', 'Visible'],
            'TeletexString' => [0x14, "\xE9", 'é'],
            'BMPString' => [0x1E, "\x00\xD1\x00a", 'Ña'],
            'UniversalString' => [0x1C, "\x00\x00\x00\xD1", 'Ñ'],
        ];
    }

    #[DataProvider('textProvider')]
    public function testEveryTypeOfTextIsWrittenAsUtf8(int $tag, string $content, string $expected): void
    {
        $this->assertSame('CN=' . $expected, $this->issuerOf([[$this->attribute('2.5.4.3', $this->tlv($tag, $content))]]));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function nameProvider(): array
    {
        return [
            'common name' => ['2.5.4.3', 'CN'],
            'locality' => ['2.5.4.7', 'L'],
            'state' => ['2.5.4.8', 'ST'],
            'organization' => ['2.5.4.10', 'O'],
            'organizational unit' => ['2.5.4.11', 'OU'],
            'country' => ['2.5.4.6', 'C'],
            'street' => ['2.5.4.9', 'STREET'],
            'domain component' => ['0.9.2342.19200300.100.1.25', 'DC'],
            'user id' => ['0.9.2342.19200300.100.1.1', 'UID'],
        ];
    }

    #[DataProvider('nameProvider')]
    public function testTheAttributesThatRfc4514NamesAreWrittenWithTheirName(string $oid, string $name): void
    {
        $this->assertSame($name . '=x', $this->issuerOf([[$this->attribute($oid, $this->tlv(0x0C, 'x'))]]));
    }

    public function testAnAttributeWithoutNameIsWrittenWithItsOidAndItsValueInHexadecimal(): void
    {
        $this->assertSame(
            '1.2.840.113549.1.9.1=#160161',
            $this->issuerOf([[$this->attribute('1.2.840.113549.1.9.1', $this->tlv(0x16, 'a'))]])
        );
        // An OID with arcs that need more than a byte, and a first number that is of the arc 2.
        $this->assertSame(
            '2.999.3=#0c0161',
            $this->issuerOf([[$this->attribute('2.999.3', $this->tlv(0x0C, 'a'))]])
        );
    }

    public function testAnAttributeThatIsNotATextIsWrittenWithItsOidAndItsValueInHexadecimal(): void
    {
        $this->assertSame('2.5.4.3=#020105', $this->issuerOf([[$this->attribute('2.5.4.3', $this->tlv(0x02, "\x05"))]]));
    }

    public function testTheAttributesAreWrittenInTheInverseOrderAndTheOnesOfASetAreJoinedWithAPlus(): void
    {
        $name = [
            [$this->attribute('2.5.4.6', $this->tlv(0x13, 'CL'))],
            [$this->attribute('2.5.4.10', $this->tlv(0x0C, 'Company')), $this->attribute('2.5.4.11', $this->tlv(0x0C, 'Unit'))],
            [$this->attribute('2.5.4.3', $this->tlv(0x0C, 'Authority'))],
        ];

        $this->assertSame('CN=Authority,O=Company+OU=Unit,C=CL', $this->issuerOf($name));
    }

    public function testACertificateWithoutVersionHasTheIssuerToo(): void
    {
        $this->assertSame('CN=a', $this->issuerOf([[$this->attribute('2.5.4.3', $this->tlv(0x0C, 'a'))]], version: false));
    }

    public function testALongNameUsesTheLongFormOfTheLength(): void
    {
        $text = str_repeat('x', 300);

        $this->assertSame('CN=' . $text, $this->issuerOf([[$this->attribute('2.5.4.3', $this->tlv(0x0C, $text))]]));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function escapeProvider(): array
    {
        return [
            'nothing' => ['plain', 'plain'],
            'a comma' => ['a,b', 'a\,b'],
            'a plus' => ['a+b', 'a\+b'],
            'a quote' => ['a"b', 'a\"b'],
            'a semicolon' => ['a;b', 'a\;b'],
            'a less than' => ['a<b', 'a\<b'],
            'a greater than' => ['a>b', 'a\>b'],
            'a backslash' => ['a\\b', 'a\\\\b'],
            'a space at the start' => [' a', '\ a'],
            'a number sign at the start' => ['#a', '\#a'],
            'a number sign inside' => ['a#b', 'a#b'],
            'a space at the end' => ['a ', 'a\ '],
            'several spaces at the end' => ['a  ', 'a \ '],
            'a backslash and a space at the end' => ['a\\ ', 'a\\\\\ '],
            'only a space' => [' ', '\ '],
            'a character that is not of ASCII' => ['Ñ', 'Ñ'],
            'a null character' => ["a\x00b", 'a\00b'],
            'empty' => ['', ''],
        ];
    }

    #[DataProvider('escapeProvider')]
    public function testTheCharactersThatRfc4514EscapesAreEscaped(string $text, string $expected): void
    {
        $this->assertSame('CN=' . $expected, $this->issuerOf([[$this->attribute('2.5.4.3', $this->tlv(0x0C, $text))]]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedProvider(): array
    {
        $name = "\x30\x00";

        return [
            'empty' => [''],
            'not a sequence' => ["\x31\x00"],
            'without length' => ["\x30"],
            'with a length that is indefinite' => ["\x30\x80"],
            'with a length of too many bytes' => ["\x30\x85\x00\x00\x00\x00\x01\x00"],
            'with a length that does not fit' => ["\x30\x82\x01"],
            'with a length that goes beyond the data' => ["\x30\x05\x30"],
            'without the certificate' => ["\x30\x00"],
            'without what is after the version' => ["\x30\x04\x30\x02\xA0\x00"],
            'without the issuer' => ["\x30\x0A\x30\x08\x02\x01\x01\x30\x03\x06\x01\x2A"],
            'with an issuer that is not a sequence' => ["\x30\x0F\x30\x0D\x02\x01\x01\x30\x03\x06\x01\x2A\x31\x02\x00\x00"],
            'with a set that is not a set' => ["\x30\x0F\x30\x0D\x02\x01\x01\x30\x00\x30\x04\x30\x02\x00\x00"],
        ];
    }

    #[DataProvider('malformedProvider')]
    public function testADerThatIsNotTheOneOfACertificateIsAnError(string $der): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('The distinguished name of the certificate could not be read.');

        DistinguishedName::issuerOf($der);
    }

    /**
     * @return array<string, array{list<list<string>>}>
     */
    public static function malformedNameProvider(): array
    {
        return [
            'a set without attributes' => [[[]]],
            'an attribute that is not a sequence' => [[["\x02\x01\x05"]]],
            'an attribute without OID' => [[["\x30\x03\x02\x01\x05"]]],
            'an attribute without value' => [[["\x30\x03\x06\x01\x2A"]]],
            'an OID without content' => [[["\x30\x04\x06\x00\x0C\x00"]]],
            'an OID that is not complete' => [[["\x30\x05\x06\x01\x81\x0C\x00"]]],
        ];
    }

    /**
     * @param list<list<string>> $sets
     */
    #[DataProvider('malformedNameProvider')]
    public function testANameThatIsNotWellMadeIsAnError(array $sets): void
    {
        $this->expectException(CertificateException::class);

        $this->issuerOf($sets);
    }
}
