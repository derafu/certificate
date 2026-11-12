<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate;

use Derafu\Certificate\Exception\CertificateException;

/**
 * Writes the distinguished name of the issuer of a certificate as RFC 4514
 * says.
 *
 * It is read from the DER of the certificate, and not from the data that
 * OpenSSL parses, because that data groups the attributes that are repeated:
 * the order of the attributes of the name is part of what identifies the issuer.
 *
 * The attributes that RFC 4514 gives a name to are written with it (`CN`, `L`,
 * `ST`, `O`, `OU`, `C`, `STREET`, `DC` and `UID`) and the other ones, or the
 * ones that are not a text, with their OID and their value in hexadecimal, as
 * the RFC says.
 */
final class DistinguishedName
{
    private const int SEQUENCE = 0x30;

    private const int SET = 0x31;

    private const int OID = 0x06;

    /**
     * The attributes that have a name in RFC 4514, by OID.
     *
     * @var array<string, string>
     */
    private const array NAMES = [
        '2.5.4.3' => 'CN',
        '2.5.4.7' => 'L',
        '2.5.4.8' => 'ST',
        '2.5.4.10' => 'O',
        '2.5.4.11' => 'OU',
        '2.5.4.6' => 'C',
        '2.5.4.9' => 'STREET',
        '0.9.2342.19200300.100.1.25' => 'DC',
        '0.9.2342.19200300.100.1.1' => 'UID',
    ];

    /**
     * The names that attributes have, by the OID that they are: the ones of RFC
     * 4514 and the ones that other systems write.
     *
     * @var array<string, string>
     */
    private const array NAMES_TO_OID = [
        'CN' => '2.5.4.3', 'COMMONNAME' => '2.5.4.3',
        'SN' => '2.5.4.4', 'SURNAME' => '2.5.4.4',
        'SERIALNUMBER' => '2.5.4.5',
        'C' => '2.5.4.6', 'COUNTRYNAME' => '2.5.4.6',
        'L' => '2.5.4.7', 'LOCALITYNAME' => '2.5.4.7',
        'ST' => '2.5.4.8', 'S' => '2.5.4.8', 'SP' => '2.5.4.8', 'STATEORPROVINCENAME' => '2.5.4.8',
        'STREET' => '2.5.4.9',
        'O' => '2.5.4.10', 'ORGANIZATIONNAME' => '2.5.4.10',
        'OU' => '2.5.4.11', 'ORGANIZATIONALUNITNAME' => '2.5.4.11',
        'T' => '2.5.4.12', 'TITLE' => '2.5.4.12',
        'GN' => '2.5.4.42', 'GIVENNAME' => '2.5.4.42',
        'E' => '1.2.840.113549.1.9.1', 'EMAIL' => '1.2.840.113549.1.9.1', 'EMAILADDRESS' => '1.2.840.113549.1.9.1',
        'DC' => '0.9.2342.19200300.100.1.25',
        'UID' => '0.9.2342.19200300.100.1.1',
    ];

    /**
     * The encodings of the texts of a name, by the tag of its DER.
     *
     * @var array<int, string>
     */
    private const array TEXT_ENCODINGS = [
        0x0C => 'UTF-8',        // UTF8String.
        0x12 => 'ASCII',        // NumericString.
        0x13 => 'ASCII',        // PrintableString.
        0x14 => 'ISO-8859-1',   // TeletexString.
        0x16 => 'ASCII',        // IA5String.
        0x1A => 'ASCII',        // VisibleString.
        0x1C => 'UTF-32BE',     // UniversalString.
        0x1E => 'UTF-16BE',     // BMPString.
    ];

    /**
     * Gives the distinguished name of the issuer of a certificate.
     *
     * @param string $der The certificate, in DER.
     * @return string The name as RFC 4514 writes it: the attributes in the order
     * inverse to the one of the certificate, separated by commas, and the
     * attributes of a same set separated by `+`.
     * @throws CertificateException If it is not the DER of a certificate.
     */
    public static function issuerOf(string $der): string
    {
        return self::name($der, self::locate($der)['issuer'][0]);
    }

    /**
     * Gives the DER of the name of the issuer of a certificate, as the
     * certificate has it.
     *
     * @param string $der The certificate, in DER.
     * @throws CertificateException If it is not the DER of a certificate.
     */
    public static function issuerDerOf(string $der): string
    {
        [$start, $next] = self::locate($der)['issuer'];

        return substr($der, $start, $next - $start);
    }

    /**
     * Gives the DER of the serial number of a certificate (its `INTEGER`), as
     * the certificate has it.
     *
     * @param string $der The certificate, in DER.
     * @throws CertificateException If it is not the DER of a certificate.
     */
    public static function serialDerOf(string $der): string
    {
        [$start, $next] = self::locate($der)['serial'];

        return substr($der, $start, $next - $start);
    }

    /**
     * Indicates if two distinguished names written as text are the same name.
     *
     * The names are compared as the attributes that they have, not as the text:
     * the case and the spaces of the values do not matter, the attributes can be
     * written with their name (`CN`, `emailAddress`, `E`) or with their OID
     * (`2.5.4.3`, `OID.2.5.4.3`), the values can be escaped with a backslash
     * or in hexadecimal (`\2C`, `#0c01..`), the attributes can be separated by
     * commas or semicolons, the attributes of a set (joined by `+`) are in any
     * order, and the sets can be in the order of the certificate or in the
     * inverse one (RFC 4514 and RFC 2253 write them inverted, other systems do
     * not).
     *
     * @return bool `true` if they are the same name. A text that is not a name is
     * not the same as anything.
     */
    public static function equals(string $first, string $second): bool
    {
        $first = self::parse($first);
        $second = self::parse($second);
        if ($first === null || $second === null) {
            return false;
        }

        return $first === $second || $first === array_reverse($second);
    }

    /**
     * Finds where the serial number and the issuer are in the DER of a
     * certificate.
     *
     * @return array{serial: array{int, int}, issuer: array{int, int}} For each,
     * where its element starts and where the next one starts.
     * @throws CertificateException If it is not the DER of a certificate.
     */
    private static function locate(string $der): array
    {
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... issuer ... } }.
        [$certificate] = self::enter($der, 0, self::SEQUENCE);
        [$offset, $end] = self::enter($der, $certificate, self::SEQUENCE);

        // The version is optional (tag A0): after it go the serial number, the
        // algorithm of the signature and the issuer.
        if (self::tagAt($der, $offset) === 0xA0) {
            $offset = self::read($der, $offset)[2];
        }
        $serial = [$offset, self::read($der, $offset)[2]];
        $offset = self::read($der, $serial[1])[2];
        if ($offset >= $end) {
            throw self::invalid();
        }

        return ['serial' => $serial, 'issuer' => [$offset, self::read($der, $offset, self::SEQUENCE)[2]]];
    }

    /**
     * Reads a name written as text.
     *
     * @return list<string>|null The attributes of each set, as `type=value`
     * with the type as an OID when it is known and the value normalized, sorted
     * inside each set; `null` if it is not a name.
     */
    private static function parse(string $name): ?array
    {
        if (trim($name) === '') {
            return null;
        }

        $sets = [];
        foreach (self::split($name, [',', ';']) as $set) {
            $attributes = [];
            foreach (self::split($set, ['+']) as $attribute) {
                $position = self::firstUnescaped($attribute, '=');
                if ($position === null) {
                    return null;
                }

                $type = self::normalizeType(trim(substr($attribute, 0, $position)));
                $value = self::normalizeValue(substr($attribute, $position + 1));
                if ($type === '' || $value === null) {
                    return null;
                }
                $attributes[] = $type . '=' . $value;
            }
            sort($attributes);
            $sets[] = implode('+', $attributes);
        }

        return $sets;
    }

    /**
     * Splits a text by some separators that are not escaped.
     *
     * @param list<string> $separators
     * @return list<string>
     */
    private static function split(string $text, array $separators): array
    {
        $parts = [];
        $current = '';
        for ($i = 0, $length = strlen($text); $i < $length; $i++) {
            $character = $text[$i];
            if ($character === '\\' && $i + 1 < $length) {
                $current .= $character . $text[++$i];
            } elseif (in_array($character, $separators, true)) {
                $parts[] = $current;
                $current = '';
            } else {
                $current .= $character;
            }
        }
        $parts[] = $current;

        return $parts;
    }

    /**
     * Gives the position of the first character that is not escaped.
     */
    private static function firstUnescaped(string $text, string $character): ?int
    {
        for ($i = 0, $length = strlen($text); $i < $length; $i++) {
            if ($text[$i] === '\\') {
                $i++;
            } elseif ($text[$i] === $character) {
                return $i;
            }
        }

        return null;
    }

    /**
     * Gives the type of an attribute as its OID if it is a name that is known.
     */
    private static function normalizeType(string $type): string
    {
        $type = strtoupper($type);
        if (str_starts_with($type, 'OID.')) {
            $type = substr($type, 4);
        }

        return self::NAMES_TO_OID[$type] ?? $type;
    }

    /**
     * Gives the value of an attribute as the text that is compared: unescaped,
     * without the spaces of its ends, with one space between words and in
     * lower case.
     *
     * @return string|null `null` if the value is not valid.
     */
    private static function normalizeValue(string $value): ?string
    {
        $value = self::trimUnescaped($value);

        if (str_starts_with($value, '#')) {
            $der = ctype_xdigit(substr($value, 1)) && strlen($value) % 2 === 1 ? hex2bin(substr($value, 1)) : false;
            if ($der === false) {
                return null;
            }
            $text = self::textOfDer($der);
        } else {
            $text = self::unescape($value);
            if ($text === null) {
                return null;
            }
        }

        return mb_strtolower((string) preg_replace('/\s+/u', ' ', trim($text)));
    }

    /**
     * Removes the spaces of the ends of a value that are not escaped.
     */
    private static function trimUnescaped(string $value): string
    {
        $value = ltrim($value, ' ');
        while (str_ends_with($value, ' ')) {
            $slashes = strlen($value) - 1 - strlen(rtrim(substr($value, 0, -1), '\\'));
            if ($slashes % 2 === 1) {
                break;
            }
            $value = substr($value, 0, -1);
        }

        return $value;
    }

    /**
     * Removes the backslashes of a value: `\,` is the character and `\2C` is
     * the byte.
     *
     * @return string|null `null` if a backslash is at the end.
     */
    private static function unescape(string $value): ?string
    {
        $text = '';
        for ($i = 0, $length = strlen($value); $i < $length; $i++) {
            if ($value[$i] !== '\\') {
                $text .= $value[$i];
                continue;
            }
            if ($i + 1 >= $length) {
                return null;
            }
            $next = $value[$i + 1];
            if ($i + 2 < $length && ctype_xdigit($next) && ctype_xdigit($value[$i + 2])) {
                $text .= pack('C', intval($next . $value[$i + 2], 16));
                $i += 2;
            } else {
                $text .= $next;
                $i++;
            }
        }

        return $text;
    }

    /**
     * Gives the text that the DER of a value has, or the DER in hexadecimal if
     * it is not a text, or if it is not exactly one element (it is not complete,
     * or something follows it): its octets are then what is compared.
     */
    private static function textOfDer(string $der): string
    {
        try {
            [$start, $end] = self::read($der, 0);
            $encoding = self::TEXT_ENCODINGS[ord($der[0])] ?? null;
        } catch (CertificateException) {
            return '#' . bin2hex($der);
        }
        if ($encoding === null || $end !== strlen($der)) {
            return '#' . bin2hex($der);
        }

        $text = substr($der, $start, $end - $start);

        return $encoding === 'UTF-8' || $encoding === 'ASCII' ? $text : mb_convert_encoding($text, 'UTF-8', $encoding);
    }

    /**
     * Writes a name that is in the DER.
     *
     * @param int $offset Where the name is.
     */
    private static function name(string $der, int $offset): string
    {
        [$offset, $end] = self::enter($der, $offset, self::SEQUENCE);

        $sets = [];
        while ($offset < $end) {
            [$content, $setEnd, $next] = self::read($der, $offset, self::SET);

            $attributes = [];
            while ($content < $setEnd) {
                [$attribute, $attributeEnd, $content] = self::read($der, $content, self::SEQUENCE);
                [$typeStart, $typeEnd, $valueOffset] = self::read($der, $attribute, self::OID);
                if ($valueOffset >= $attributeEnd) {
                    throw self::invalid();
                }
                $attributes[] = self::attribute(
                    self::oid(substr($der, $typeStart, $typeEnd - $typeStart)),
                    $der,
                    $valueOffset
                );
            }
            if ($attributes === []) {
                throw self::invalid();
            }

            $sets[] = implode('+', $attributes);
            $offset = $next;
        }

        return implode(',', array_reverse($sets));
    }

    /**
     * Writes an attribute: its name and its value.
     */
    private static function attribute(string $oid, string $der, int $offset): string
    {
        [$start, $end, $next] = self::read($der, $offset);
        $tag = self::tagAt($der, $offset);

        $name = self::NAMES[$oid] ?? null;
        $encoding = self::TEXT_ENCODINGS[$tag] ?? null;
        if ($name === null || $encoding === null) {
            return $oid . '=#' . bin2hex(substr($der, $offset, $next - $offset));
        }

        $text = substr($der, $start, $end - $start);
        if ($encoding !== 'UTF-8' && $encoding !== 'ASCII') {
            $text = mb_convert_encoding($text, 'UTF-8', $encoding);
        }

        return $name . '=' . self::escape($text);
    }

    /**
     * Escapes a text as RFC 4514 says.
     */
    private static function escape(string $text): string
    {
        // The last space is escaped, the other ones of the end are not.
        $space = str_ends_with($text, ' ');
        $body = $space ? substr($text, 0, -1) : $text;

        $escaped = (string) preg_replace('/(["+,;<>\\\\])/', '\\\\$1', $body);
        $escaped = str_replace("\x00", '\\00', $escaped);

        // A space or a `#` at the start.
        if ($escaped !== '' && ($escaped[0] === ' ' || $escaped[0] === '#')) {
            $escaped = '\\' . $escaped;
        }

        return $escaped . ($space ? '\\ ' : '');
    }

    /**
     * Writes an OID that is in the DER as its numbers separated by dots.
     */
    private static function oid(string $content): string
    {
        $numbers = [];
        $value = 0;
        $open = false;
        for ($i = 0, $length = strlen($content); $i < $length; $i++) {
            $byte = ord($content[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            $open = ($byte & 0x80) !== 0;
            if (!$open) {
                $numbers[] = $value;
                $value = 0;
            }
        }
        if ($numbers === [] || $open) {
            throw self::invalid();
        }

        // The first number has the first two arcs.
        $first = array_shift($numbers);
        $arc = min(intdiv($first, 40), 2);

        return implode('.', [$arc, $first - 40 * $arc, ...$numbers]);
    }

    /**
     * Gives the tag of the element that is at an offset.
     */
    private static function tagAt(string $der, int $offset): int
    {
        if ($offset >= strlen($der)) {
            throw self::invalid();
        }

        return ord($der[$offset]);
    }

    /**
     * Enters an element: gives where its content starts and ends.
     *
     * @return array{int, int} The start and the end of its content.
     */
    private static function enter(string $der, int $offset, int $tag): array
    {
        [$start, $end] = self::read($der, $offset, $tag);

        return [$start, $end];
    }

    /**
     * Reads the header of an element.
     *
     * @param int|null $tag The tag that it must have, if it is one.
     * @return array{int, int, int} Where its content starts, where it ends and
     * where the next element starts.
     * @throws CertificateException If there is no element in the offset, or it
     * is not the one that is expected.
     */
    private static function read(string $der, int $offset, ?int $tag = null): array
    {
        if (self::tagAt($der, $offset) !== ($tag ?? self::tagAt($der, $offset))) {
            throw self::invalid();
        }

        $position = $offset + 1;
        if ($position >= strlen($der)) {
            throw self::invalid();
        }
        $length = ord($der[$position]);
        $position++;
        if ($length >= 0x80) {
            $count = $length & 0x7F;
            if ($count === 0 || $count > 4 || $position + $count > strlen($der)) {
                throw self::invalid();
            }
            $length = 0;
            for ($i = 0; $i < $count; $i++) {
                $length = ($length << 8) | ord($der[$position + $i]);
            }
            $position += $count;
        }

        $end = $position + $length;
        if ($end > strlen($der)) {
            throw self::invalid();
        }

        return [$position, $end, $end];
    }

    /**
     * Creates the exception for a DER that is not the one of a certificate.
     */
    private static function invalid(): CertificateException
    {
        return new CertificateException('The distinguished name of the certificate could not be read.');
    }
}
