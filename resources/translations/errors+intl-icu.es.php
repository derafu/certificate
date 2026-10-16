<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

return [
    // AsymmetricKeyHelper.
    'The certificate cannot be empty.' =>
        'El certificado no puede estar vacío.',
    'The private key cannot be empty.' =>
        'La clave privada no puede estar vacía.',
    'It was not possible to generate the public key from the modulus and the exponent.' =>
        'No fue posible generar la clave pública a partir del módulo y el exponente.',

    // Certificate.
    'The private key is not available in the certificate.' =>
        'La clave privada no está disponible en el certificado.',
    'It was not possible to read the private key of the certificate.' =>
        'No fue posible leer la clave privada del certificado.',
    'It was not possible to read the public key of the certificate.' =>
        'No fue posible leer la clave pública del certificado.',
    'It was not possible to read the data of the certificate.' =>
        'No fue posible leer los datos del certificado.',
    'Cannot get the ID of the digital certificate. It is recommended to verify the format and password of the certificate.' =>
        'No fue posible obtener el ID del certificado digital. Se recomienda verificar el formato y la contraseña del certificado.',
    'Cannot get the name of the digital certificate.' =>
        'No fue posible obtener el nombre del certificado digital.',
    'Cannot get the email of the digital certificate.' =>
        'No fue posible obtener el correo electrónico del certificado digital.',
    'Cannot get the issuer of the digital certificate.' =>
        'No fue posible obtener el emisor del certificado digital.',
    'Cannot get the modulus of the certificate.' =>
        'No fue posible obtener el módulo del certificado.',
    'Cannot get the exponent of the certificate.' =>
        'No fue posible obtener el exponente del certificado.',
    // AsymmetricKeyHelper (dependency).
    'First install phpseclib3/phpseclib: composer require phpseclib/phpseclib' =>
        'Primero instale phpseclib3/phpseclib: composer require phpseclib/phpseclib',

    // SelfSignedCertificate.
    'The CN, emailAddress and serialNumber are required.' =>
        'El CN, el emailAddress y el serialNumber son obligatorios.',
    'It was not possible to generate the private key of the issuer of the certificate.' =>
        'No fue posible generar la clave privada del emisor del certificado.',
    'It was not possible to generate the CSR of the issuer of the certificate.' =>
        'No fue posible generar el CSR del emisor del certificado.',
    'It was not possible to generate the issuer certificate (CA).' =>
        'No fue posible generar el certificado del emisor (CA).',
    'It was not possible to generate the private key of the certificate.' =>
        'No fue posible generar la clave privada del certificado.',
    'It was not possible to generate the CSR of the certificate.' =>
        'No fue posible generar el CSR del certificado.',
    'It was not possible to generate the user certificate.' =>
        'No fue posible generar el certificado del usuario.',
    // CertificateLoader.
    'It was not possible to read the digital certificate file from {path}' =>
        'No fue posible leer el archivo del certificado digital desde {path}',
    'It was not possible to read the digital certificate data.' =>
        'No fue posible leer los datos del certificado digital.',
    'It was not possible to read the digital certificate data. {errors}' =>
        'No fue posible leer los datos del certificado digital. {errors}',
    'The certificate was not found.' =>
        'No se encontró el certificado.',
    'The certificate must be a text.' =>
        'El certificado debe ser un texto.',
    'The private key of the certificate must be a text.' =>
        'La clave privada del certificado debe ser un texto.',
    'The chain of the certificate must contain only texts.' =>
        'La cadena del certificado debe contener solo textos.',
    'The private key of the certificate was not found.' =>
        'No se encontró la clave privada del certificado.',
    // CertificateValidator.
    'The ID format {format} is not a valid regular expression.' =>
        'El formato de ID {format} no es una expresión regular válida.',
    'The ID {id} of the certificate does not match the format {format}.' =>
        'El ID {id} del certificado no coincide con el formato {format}.',
    'The certificate expired on {date}, it must use a valid certificate. If you do not have one, you must acquire it from an authorized provider.' =>
        'El certificado venció el {date}, debe usar un certificado válido. Si no tiene uno, debe adquirirlo en un proveedor autorizado.',
];
