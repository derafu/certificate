<?php

declare(strict_types=1);

/**
 * Derafu: Certificate - Library for digital certificates.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsCertificate;

use Derafu\Certificate\Contract\CertificateFakerInterface;
use Derafu\Certificate\Contract\CertificateLoaderInterface;
use Derafu\Certificate\Contract\CertificateServiceInterface;
use Derafu\Certificate\Contract\CertificateValidatorInterface;
use Derafu\Certificate\Contract\OpenSslInterface;
use Derafu\Certificate\Exception\CertificateException;
use Derafu\Certificate\Translation\CertificateTranslationResourceProvider;
use Derafu\Translation\TranslatorFactory;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;

/**
 * Exercise the actual service YAML with real certificates and OpenSSL.
 */
#[CoversNothing]
final class ServicesTest extends TestCase
{
    private function container(): ContainerBuilder
    {
        $container = new ContainerBuilder();
        (new YamlFileLoader($container, new FileLocator(dirname(__DIR__, 2) . '/resources/config')))
            ->load('certificate-services.yaml');
        $this->assertArrayHasKey(
            CertificateTranslationResourceProvider::class,
            $container->findTaggedServiceIds('derafu_translation.resource_provider')
        );
        $container->register('app.translator', Translator::class)
            ->setFactory([TranslatorFactory::class, 'create'])
            ->setArguments(['es', ['en'], new TaggedIteratorArgument('derafu_translation.resource_provider')]);
        foreach ($container->getDefinitions() as $definition) {
            $definition->setPublic(true);
        }
        $container->compile();

        return $container;
    }

    public function testEveryDeclaredServiceCanBeConstructed(): void
    {
        $container = $this->container();
        foreach ($container->getDefinitions() as $id => $definition) {
            if (!str_starts_with($id, 'Derafu\\Certificate\\')) {
                continue;
            }
            $class = $definition->getClass();
            $this->assertNotNull($class);
            $this->assertTrue(class_exists($class));
            $this->assertInstanceOf($class, $container->get($id), $id);
        }
        $provider = $container->get(CertificateTranslationResourceProvider::class);
        $this->assertInstanceOf(CertificateTranslationResourceProvider::class, $provider);
        $directories = [...$provider->getDirectories()];
        $this->assertCount(1, $directories);
        $this->assertSame(realpath(dirname(__DIR__, 2) . '/resources/translations'), realpath($directories[0]));
    }

    public function testConfiguredServicesCreateValidateAndReloadAPkcs12Certificate(): void
    {
        $container = $this->container();
        $faker = $container->get(CertificateFakerInterface::class);
        $this->assertInstanceOf(CertificateFakerInterface::class, $faker);
        $certificate = $faker->createFake('11222333-9', 'Services Test', 'services@example.com');
        $service = $container->get(CertificateServiceInterface::class);
        $this->assertInstanceOf(CertificateServiceInterface::class, $service);
        $service->validate($certificate);
        $validator = $container->get(CertificateValidatorInterface::class);
        $this->assertInstanceOf(CertificateValidatorInterface::class, $validator);
        $validator->validate($certificate);
        $loaded = $service->loadFromData($certificate->getPkcs12('test-password'), 'test-password');
        $this->assertSame('11222333-9', $loaded->getId());
        $this->assertSame('Services Test', $loaded->getName());
        $this->assertSame('services@example.com', $loaded->getEmail());
        $this->assertSame($certificate->getModulus(), $loaded->getModulus());
    }

    public function testConfiguredLoaderAndOpenSslSignAndVerifyUsingExistingFixtures(): void
    {
        $container = $this->container();
        $loader = $container->get(CertificateLoaderInterface::class);
        $this->assertInstanceOf(CertificateLoaderInterface::class, $loader);
        $pem = file_get_contents(__DIR__ . '/../fixtures/san-id.cert.pem');
        $key = file_get_contents(__DIR__ . '/../fixtures/san-id.key.pem');
        $this->assertIsString($pem);
        $this->assertIsString($key);
        $certificate = $loader->loadFromKeys($pem, $key);
        $openssl = $container->get(OpenSslInterface::class);
        $this->assertInstanceOf(OpenSslInterface::class, $openssl);
        $signature = $openssl->sign('Original payload', $certificate->getPrivateKey(), OPENSSL_ALGO_SHA256);
        $this->assertNotSame('', $signature);
        $this->assertTrue($openssl->verify('Original payload', $signature, $certificate->getCertificate(), OPENSSL_ALGO_SHA256));
        $this->assertFalse($openssl->verify('Changed payload', $signature, $certificate->getCertificate(), OPENSSL_ALGO_SHA256));
    }

    public function testTaggedResourcesTranslateAnExceptionFromTheConfiguredLoader(): void
    {
        $container = $this->container();
        $translator = $container->get('app.translator');
        $this->assertInstanceOf(Translator::class, $translator);
        $loader = $container->get(CertificateLoaderInterface::class);
        $this->assertInstanceOf(CertificateLoaderInterface::class, $loader);
        try {
            $loader->loadFromArray([]);
            $this->fail('A certificate without its public certificate was accepted.');
        } catch (CertificateException $exception) {
            $this->assertSame('The certificate was not found.', $exception->getMessage());
            $this->assertSame('No se encontró el certificado.', $exception->trans($translator));
        }
    }
}
