<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate\Service;

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Contract\CertificateValidatorInterface;
use Derafu\Certificate\Exception\CertificateException;

/**
 * Class that performs validations on the digital certificate.
 *
 * It validates that the certificate has an ID, that the ID has the format that
 * was configured (if any) and that the certificate is not expired. If you need
 * to validate a certificate for another purpose, you must implement the
 * CertificateValidatorInterface interface with your own logic.
 */
final class CertificateValidator implements CertificateValidatorInterface
{
    /**
     * Constructor.
     *
     * @param string|null $idFormat Regular expression (with delimiters) that
     * the ID of the certificate must match. If it is `null`, the format of the
     * ID is not validated.
     * @throws CertificateException If the regular expression is not valid.
     */
    public function __construct(private readonly ?string $idFormat = null)
    {
        if ($idFormat !== null && @preg_match($idFormat, '') === false) {
            throw new CertificateException([
                'The ID format {format} is not a valid regular expression.',
                'format' => $idFormat,
            ]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function validate(CertificateInterface $certificate): void
    {
        // Validate that the ID of the certificate is present.
        $id = $certificate->getId(false);

        // Validate that the ID has the format, if there is one.
        if ($this->idFormat !== null && preg_match($this->idFormat, $id) !== 1) {
            throw new CertificateException([
                'The ID {id} of the certificate does not match the format {format}.',
                'id' => $id,
                'format' => $this->idFormat,
            ]);
        }

        // Validate that the certificate is active (not expired).
        if (!$certificate->isActive()) {
            throw new CertificateException([
                'The certificate expired on {date}, it must use a valid certificate. If you do not have one, you must acquire it from an authorized provider.',
                'date' => $certificate->getTo(),
            ]);
        }
    }
}
