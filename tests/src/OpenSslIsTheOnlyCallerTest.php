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

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Only the OpenSSL service calls OpenSSL.
 *
 * What is common to every call (the queue of errors of OpenSSL, the warnings of
 * PHP and what a failure is) is done once, in that service. A call to OpenSSL
 * anywhere else would not have it.
 */
#[CoversNothing]
final class OpenSslIsTheOnlyCallerTest extends TestCase
{
    public function testNoCodeOutsideTheServiceCallsOpenssl(): void
    {
        $src = dirname(__DIR__, 2) . '/src';
        $service = realpath($src . '/Service/OpenSsl.php');
        $callers = [];

        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
        foreach ($files as $file) {
            if (!$file instanceof SplFileInfo) {
                continue;
            }

            if ($file->getExtension() !== 'php' || $file->getRealPath() === $service) {
                continue;
            }

            // Only the code is read: a comment can name a function.
            $code = '';
            foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
                if (is_array($token) && !in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    $code .= $token[1];
                } elseif (is_string($token)) {
                    $code .= $token;
                }
            }

            if (preg_match('/\bopenssl_[a-z0-9_]+\s*\(/', $code) === 1) {
                $callers[] = substr($file->getPathname(), strlen($src) + 1);
            }
        }

        $this->assertSame([], $callers);
    }
}
