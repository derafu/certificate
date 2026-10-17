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

    // OpenSsl.
    'OpenSSL could not generate the private key.' =>
        'OpenSSL no pudo generar la clave privada.',
    'OpenSSL could not read the private key.' =>
        'OpenSSL no pudo leer la clave privada.',
    'OpenSSL could not read the public key.' =>
        'OpenSSL no pudo leer la clave pública.',
    'OpenSSL could not read the details of the key.' =>
        'OpenSSL no pudo leer los detalles de la clave.',
    'OpenSSL could not read the data of the certificate.' =>
        'OpenSSL no pudo leer los datos del certificado.',
    'OpenSSL could not generate the certificate signing request.' =>
        'OpenSSL no pudo generar la solicitud de firma del certificado.',
    'OpenSSL could not sign the certificate signing request.' =>
        'OpenSSL no pudo firmar la solicitud de firma del certificado.',
    'OpenSSL could not read the PKCS#12.' =>
        'OpenSSL no pudo leer el PKCS#12.',
    'OpenSSL could not export the PKCS#12.' =>
        'OpenSSL no pudo exportar el PKCS#12.',
    'OpenSSL could not sign the data.' =>
        'OpenSSL no pudo firmar los datos.',
    'OpenSSL could not verify the signature.' =>
        'OpenSSL no pudo verificar la firma.',

    // SelfSignedCertificate.
    'The CN, emailAddress and serialNumber are required.' =>
        'El CN, el emailAddress y el serialNumber son obligatorios.',
    // OpenSsl: the errors of OpenSSL that are known (each one has its code).
    'Unsupported encryption algorithm or method (Error #{code}).' =>
        'Algoritmo o método de cifrado no soportado (Error #{code}).',
    'MAC verification failed in PKCS12, certificate or password is incorrect (Error #{code}).' =>
        'Falló la verificación MAC en el PKCS12, el certificado o la contraseña es incorrecta (Error #{code}).',
    'Failed to load X.509 certificate (Error #{code}).' =>
        'No fue posible cargar el certificado X.509 (Error #{code}).',
    'Invalid PEM format (Error #{code}).' =>
        'Formato PEM inválido (Error #{code}).',
    'Key length not allowed (Error #{code}).' =>
        'Largo de clave no permitido (Error #{code}).',
    'Private key error: incorrect password (Error #{code}).' =>
        'Error de clave privada: contraseña incorrecta (Error #{code}).',
    'SSL layer error: invalid certificate or CA not known (Error #{code}).' =>
        'Error de la capa SSL: certificado inválido o CA desconocida (Error #{code}).',
    'SSL configuration error: certificate or key problem (Error #{code}).' =>
        'Error de configuración SSL: problema con el certificado o la clave (Error #{code}).',
    'Error in reading a certificate file (Error #{code}).' =>
        'Error al leer un archivo de certificado (Error #{code}).',
    'SSL error: incompatible protocol (Error #{code}).' =>
        'Error SSL: protocolo incompatible (Error #{code}).',
    // OpenSsl: any other error of OpenSSL, or a warning of PHP, as it is.
    'OpenSSL: {text}' =>
        'OpenSSL: {text}',

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
