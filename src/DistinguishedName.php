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
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... issuer ... } }.
        [$certificate] = self::enter($der, 0, self::SEQUENCE);
        [$offset, $end] = self::enter($der, $certificate, self::SEQUENCE);

        // The version is optional (tag A0): after it go the serial number, the
        // algorithm of the signature and the issuer.
        if (self::tagAt($der, $offset) === 0xA0) {
            $offset = self::read($der, $offset)[2];
        }
        $offset = self::read($der, $offset)[2];
        $offset = self::read($der, $offset)[2];
        if ($offset >= $end) {
            throw self::invalid();
        }

        return self::name($der, $offset);
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
