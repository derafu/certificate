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
            // The bytes of a text that is not valid for its type are given as they are.
            'PrintableString with bytes that are not ASCII' => [0x13, "\xC3\x91", 'Ñ'],
            'UTF8String with bytes that are not UTF-8' => [0x0C, "\xFF", "\xFF"],
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

    /**
     * @return array<string, array{string, string}>
     */
    public static function sameNameProvider(): array
    {
        return [
            'the same text' => ['CN=a,O=b,C=CL', 'CN=a,O=b,C=CL'],
            'in the inverse order' => ['CN=a,O=b,C=CL', 'C=CL,O=b,CN=a'],
            'with another case and other spaces' => ['CN=Ana  Perez, O= Co ', 'cn=ana perez,o=co'],
            'with spaces around the type and the equal sign' => ['CN = a , O = b', 'CN=a,O=b'],
            'with the type written as its OID' => ['CN=a', '2.5.4.3=a'],
            'with the type written as OID and its number' => ['CN=a', 'OID.2.5.4.3=a'],
            'with the email as its name' => ['emailAddress=a@b.c', 'E=a@b.c'],
            'with the email as its OID' => ['1.2.840.113549.1.9.1=a@b.c', 'emailAddress=a@b.c'],
            'with the state as the names that other systems write' => ['ST=x', 'S=x'],
            'with the state as another name' => ['SP=x', 'stateOrProvinceName=x'],
            'with names that are long' => ['commonName=a,organizationName=b,organizationalUnitName=c,countryName=CL,localityName=d', 'CN=a,O=b,OU=c,C=CL,L=d'],
            'with other names' => ['surname=a,givenName=b,title=c,serialNumber=1,street=d,dc=e,uid=f', 'SN=a,GN=b,T=c,2.5.4.5=1,STREET=d,DC=e,UID=f'],
            'with an escaped comma written in hexadecimal' => ['CN=a\2Cb', 'CN=a\,b'],
            'with the value as the DER of a text' => ['CN=#0c03612c62', 'CN=a\,b'],
            'with the value as the DER of an IA5String' => ['1.2.840.113549.1.9.1=#1603612e62', 'E=a.b'],
            'with a value that is not ASCII, in UTF-8 and escaped' => ['ST=Ñuñoa', 'ST=\C3\91u\C3\B1oa'],
            'with another case of a value that is not ASCII' => ['ST=ÑUÑOA', 'ST=ñuñoa'],
            'with the sets separated by semicolons' => ['CN=a;O=b', 'CN=a,O=b'],
            'with the attributes of a set in another order' => ['CN=a+OU=b,O=c', 'OU=b+CN=a,O=c'],
            'with a value that is not a text, in hexadecimal' => ['CN=#020105', 'CN=#020105'],
            'with an unknown name' => ['FOO=a', 'foo=A'],
            'with a space that is escaped at the end' => ['CN=a\ ', 'CN=a\ '],
            // The spaces of the ends of a value are not significant when names are matched, escaped or not.
            'with a space that is escaped at the end and one that is not' => ['CN=a\ ', 'CN=a'],
            'with a space at the end, after an escaped backslash' => ['CN=a\\\\ ', 'CN=a\\\\'],
            'with a value that is empty' => ['CN=', 'CN='],
            'with an equal sign escaped in the type' => ['A\=B=c', 'a\=b=C'],
            'with an escaped comma at the end' => ['CN=a\,', 'CN=a\,'],
            'with an empty value and the type as its OID' => ['CN=', '2.5.4.3='],
            'with a space before the value in hexadecimal' => ['CN= #0c0141', 'CN=A'],
            'with a space after the value in hexadecimal' => ['CN=#0c0141 ', 'CN=A'],
            'with spaces after the value in hexadecimal' => ['CN=#0c0141  ', 'CN=A'],
            'with an escaped backslash and an escaped space at the end' => ['CN=a\\\\\\ ', 'CN=a\\\\'],
            'with an escaped digit at the end' => ['CN=a\2', 'CN=a2'],
            'with an escaped byte at the end' => ['CN=a\2C', 'CN=a\,'],
            'with a backslash and a digit and a letter that is not hexadecimal' => ['CN=\2G', 'CN=2G'],
            'with the DER of a text that is not complete' => ['CN=#0c05', 'CN=\#0c05'],
            'with the DER of something that is not a text' => ['CN=#020105', 'CN=\#020105'],
            'with the DER of a TeletexString' => ['CN=#1401e9', 'CN=é'],
            'with the DER of a text and bytes after it' => ['CN=#0c01410000', 'CN=\#0c01410000'],
            'with the same DER of a text and bytes after it' => ['CN=#0c01410000', 'CN=#0c01410000'],
        ];
    }

    #[DataProvider('sameNameProvider')]
    public function testTheNamesThatAreWrittenInDifferentWaysAreTheSameName(string $first, string $second): void
    {
        $this->assertTrue(DistinguishedName::equals($first, $second));
        $this->assertTrue(DistinguishedName::equals($second, $first));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function differentNameProvider(): array
    {
        return [
            'with another value' => ['CN=a,O=b', 'CN=a,O=c'],
            'with another attribute' => ['CN=a,O=b', 'CN=a,OU=b'],
            'with another number of attributes' => ['CN=a,O=b', 'CN=a'],
            'with the sets in an order that is not the inverse one' => ['CN=a,O=b,C=CL', 'O=b,CN=a,C=CL'],
            'with a set that is not the one of another' => ['CN=a+OU=b', 'CN=a,OU=b'],
            'with an unknown name that is another' => ['FOO=a', 'BAR=a'],
            'with a value that is not a text and is another' => ['CN=#020105', 'CN=#020106'],
            'with the DER of a text that is another' => ['CN=#0c0161', 'CN=b'],
        ];
    }

    #[DataProvider('differentNameProvider')]
    public function testTheNamesThatHaveAnotherAttributeAreNotTheSameName(string $first, string $second): void
    {
        $this->assertFalse(DistinguishedName::equals($first, $second));
        $this->assertFalse(DistinguishedName::equals($second, $first));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function notANameProvider(): array
    {
        return [
            'empty' => [''],
            'only spaces' => ['   '],
            'an attribute without equal sign' => ['CN'],
            'a set without equal sign' => ['CN=a,O'],
            'an attribute without type' => ['=a'],
            'a backslash at the end' => ['CN=a\\'],
            'a value in hexadecimal that is not' => ['CN=#zz'],
            'a value in hexadecimal that is odd' => ['CN=#123'],
            'a number sign alone' => ['CN=#'],
        ];
    }

    #[DataProvider('notANameProvider')]
    public function testATextThatIsNotANameIsNotTheSameAsAnything(string $text): void
    {
        $this->assertFalse(DistinguishedName::equals($text, $text));
        $this->assertFalse(DistinguishedName::equals($text, 'CN=a'));
        $this->assertFalse(DistinguishedName::equals('CN=a', $text));
    }

    public function testAValueInHexadecimalThatIsNotACompleteDerIsComparedAsItIs(): void
    {
        $this->assertTrue(DistinguishedName::equals('CN=#0c05', 'CN=#0c05'));
        $this->assertFalse(DistinguishedName::equals('CN=#0c05', 'CN=#0c06'));
    }

    public function testTheTypeAndTheValueOfAnAttributeAreNotMixedUp(): void
    {
        $this->assertFalse(DistinguishedName::equals('CN=1', '2.5.4.31='));
    }

    public function testAValueInHexadecimalWithCharactersThatAreNotHexadecimalIsNotAName(): void
    {
        $this->assertFalse(DistinguishedName::equals('CN=#g0', 'CN=#g0'));
    }

    /**
     * A first number that has the first two arcs: the arc is its quotient by 40,
     * up to 2.
     *
     * @return array<string, array{string}>
     */
    public static function oidProvider(): array
    {
        return [
            'the first arc 0, the last of its second arcs' => ['0.39.1'],
            'the first arc 1, the first of its second arcs' => ['1.0.5'],
            'the first arc 1, the last of its second arcs' => ['1.38.9'],
            'the first arc 2, the first of its second arcs' => ['2.1.3'],
            'the first arc 2, with a second arc that is large' => ['2.100.3'],
        ];
    }

    #[DataProvider('oidProvider')]
    public function testTheOidIsWrittenWithTheArcsThatItHas(string $oid): void
    {
        $this->assertSame($oid . '=#0c0161', $this->issuerOf([[$this->attribute($oid, $this->tlv(0x0C, 'a'))]]));
    }

    /**
     * The part of the certificate that goes before its issuer.
     */
    private function head(): string
    {
        return $this->tlv(0xA0, $this->tlv(0x02, "\x02"))
            . $this->tlv(0x02, "\x01")
            . $this->tlv(self::SEQUENCE, $this->oid('1.2.840.113549.1.1.11'));
    }

    private function issuerThatIsA(): string
    {
        return $this->names([[$this->attribute('2.5.4.3', $this->tlv(0x0C, 'a'))]]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function wrongTagProvider(): array
    {
        return [
            'the certificate' => ['certificate'],
            'the certificate to be signed' => ['tbs'],
            'the issuer' => ['issuer'],
            'a set of the name' => ['set'],
            'an attribute' => ['attribute'],
            'the type of an attribute' => ['type'],
        ];
    }

    /**
     * Each element has the tag that it must have, so a DER that has another one
     * is not read as if it had the right one.
     */
    #[DataProvider('wrongTagProvider')]
    public function testAnElementWithAnotherTagIsAnError(string $wrong): void
    {
        $attribute = $this->tlv(self::SEQUENCE, $this->oid('2.5.4.3') . $this->tlv(0x0C, 'a'));
        $set = $this->tlv(self::SET, $attribute);
        $issuer = $this->tlv(self::SEQUENCE, $set);

        $der = match ($wrong) {
            'certificate' => $this->tlv(0x31, $this->tlv(self::SEQUENCE, $this->head() . $issuer)),
            'tbs' => $this->tlv(self::SEQUENCE, $this->tlv(0x31, $this->head() . $issuer)),
            'issuer' => $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head() . $this->tlv(0x31, $set))),
            'set' => $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head() . $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $attribute)))),
            'attribute' => $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head() . $this->tlv(self::SEQUENCE, $this->tlv(self::SET, $this->tlv(0x31, $this->oid('2.5.4.3') . $this->tlv(0x0C, 'a')))))),
            default => $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head() . $this->tlv(self::SEQUENCE, $this->tlv(self::SET, $this->tlv(self::SEQUENCE, $this->tlv(0x04, 'x') . $this->tlv(0x0C, 'a')))))),
        };

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf($der);
    }

    /**
     * A certificate to be signed that ends where its issuer should start has no
     * issuer, even if there is something after it in the certificate.
     */
    public function testACertificateWithoutIssuerIsAnErrorEvenIfSomethingFollowsIt(): void
    {
        $der = $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head()) . $this->tlv(self::SEQUENCE, ''));

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf($der);
    }

    public function testALengthThatIsIndefiniteIsAnError(): void
    {
        $content = $this->tlv(self::SEQUENCE, $this->head() . $this->issuerThatIsA() . $this->tlv(self::SEQUENCE, ''));

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf("\x30\x80" . $content);
    }

    public function testALengthThatHasFiveBytesIsAnError(): void
    {
        $content = $this->tlv(self::SEQUENCE, $this->head() . $this->issuerThatIsA() . $this->tlv(self::SEQUENCE, ''));

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf("\x30\x85\x00\x00\x00\x00" . pack('C', strlen($content)) . $content);
    }

    public function testALengthThatHasFourBytesIsRead(): void
    {
        $content = $this->tlv(self::SEQUENCE, $this->head() . $this->issuerThatIsA() . $this->tlv(self::SEQUENCE, ''));

        $this->assertSame(
            'CN=a',
            DistinguishedName::issuerOf("\x30\x84\x00\x00\x00" . pack('C', strlen($content)) . $content)
        );
    }

    /**
     * The byte `0x80` is not the length 128: it is the indefinite one, even if
     * what follows is exactly 128 bytes.
     */
    public function testTheByteThatMeansIndefiniteIsNotALengthOf128(): void
    {
        $base = $this->head() . $this->issuerThatIsA();
        $filler = $this->tlv(self::SEQUENCE, str_repeat("\x00", 124 - strlen($base)));
        $element = $this->tlv(self::SEQUENCE, $base . $filler);
        $this->assertSame(128, strlen($element));

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf("\x30\x80" . $element);
    }

    /**
     * The length of an element can be the last bytes of the certificate.
     */
    public function testAnIssuerWhoseLengthIsAtTheEndOfTheCertificateIsRead(): void
    {
        $der = $this->tlv(self::SEQUENCE, $this->tlv(self::SEQUENCE, $this->head() . "\x30\x81\x00"));

        $this->assertSame('', DistinguishedName::issuerOf($der));
    }

    /**
     * The value in hexadecimal is the encoding of one value: a text and bytes
     * after it is not the text, so it is not the same as the text.
     */
    public function testAValueInHexadecimalWithBytesAfterTheElementIsNotTheElement(): void
    {
        $this->assertFalse(DistinguishedName::equals('CN=#0c01410000', 'CN=A'));
        $this->assertFalse(DistinguishedName::equals('CN=#0c01410000', 'CN=#0c01410001'));
        $this->assertFalse(DistinguishedName::equals('CN=#0c01410000', 'CN=#0c0141'));
    }

    /**
     * A length that goes beyond the end of the DER is an error by itself: the
     * rest of the certificate is well made.
     */
    public function testALengthThatGoesBeyondTheEndOfTheCertificateIsAnError(): void
    {
        $der = $this->certificate($this->names([[$this->attribute('2.5.4.3', $this->tlv(0x0C, 'a'))]]));
        $this->assertLessThan(0x80, ord($der[1]));
        $der[1] = pack('C', ord($der[1]) + 1);

        $this->expectException(CertificateException::class);

        DistinguishedName::issuerOf($der);
    }
}
