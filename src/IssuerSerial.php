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
 * Writes the DER of the `IssuerSerial` of a certificate, as RFC 5035 defines
 * it: the issuer, as a `GeneralNames` with a `directoryName`, and the serial
 * number.
 *
 * The issuer and the serial number are the ones that the certificate has, byte
 * by byte.
 */
final class IssuerSerial
{
    /**
     * Gives the DER of the `IssuerSerial` of a certificate.
     *
     * @param string $der The certificate, in DER.
     * @throws CertificateException If it is not the DER of a certificate.
     */
    public static function derOf(string $der): string
    {
        // GeneralNames ::= SEQUENCE OF GeneralName, and directoryName is [4]
        // Name (explicit).
        $directoryName = self::element(0xA4, DistinguishedName::issuerDerOf($der));
        $issuer = self::element(0x30, $directoryName);

        return self::element(0x30, $issuer . DistinguishedName::serialDerOf($der));
    }

    /**
     * Writes an element of the DER.
     */
    private static function element(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            $header = pack('C', $length);
        } else {
            $bytes = ltrim(pack('N', $length), "\x00");
            $header = pack('C', 0x80 | strlen($bytes)) . $bytes;
        }

        return pack('C', $tag) . $header . $content;
    }
}
