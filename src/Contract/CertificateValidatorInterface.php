<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Certificate\Contract;

use Derafu\Certificate\Exception\CertificateException;

/**
 * Interface for the certificate validator.
 */
interface CertificateValidatorInterface
{
    /**
     * Validates that the certificate can be used.
     *
     * A certificate that is not valid MUST be reported with a
     * `CertificateException`. A certificate that is valid is not reported in
     * any way.
     *
     * @param CertificateInterface $certificate Certificate to validate.
     * @return void
     * @throws CertificateException If the certificate is not valid.
     */
    public function validate(CertificateInterface $certificate): void;
}
