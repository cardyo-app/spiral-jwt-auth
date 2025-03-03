<?php

namespace Cardyo\SpiralJwtAuth\Bootloader;

use Cardyo\SpiralJwtAuth\Config\JWTConfig;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Spiral\Boot\Bootloader\Bootloader;
use Spiral\Core\Attribute\Singleton;
use Spiral\Core\Container;

#[Singleton]
final class VerifierBootloader extends Bootloader
{
    protected const DEPENDENCIES = [
        BaseBootloader::class,
    ];

    public const SINGLETONS = [
        HeaderCheckerManagerFactory::class => [self::class, 'createHeaderCheckerManagerFactory'],
        HeaderCheckerManager::class => [self::class, 'createDefaultHeaderCheckerManager'],

        ClaimCheckerManagerFactory::class => [self::class, 'createClaimCheckerManagerFactory'],
        ClaimCheckerManager::class => [self::class, 'createDefaultClaimCheckerManager'],

        JWSVerifierFactory::class => JWSVerifierFactory::class,

        JWSLoaderFactory::class => JWSLoaderFactory::class,
        JWSLoader::class => [self::class, 'createJWSLoader'],
    ];

    private function createHeaderCheckerManagerFactory(
        Container $container,
        JWTConfig $config
    ): HeaderCheckerManagerFactory {
        $factory = new HeaderCheckerManagerFactory();

        foreach ($config->getSupportedTokenTypes() as $tokenType) {
            if (is_string($tokenType)) {
                $tokenType = $container->get($tokenType);
            }

            if ($tokenType instanceof Container\Autowire) {
                $tokenType = $tokenType->resolve($container);
            }

            $factory->addTokenTypeSupport($tokenType);
        }

        foreach ($config->getHeaderCheckers() as $alias => $checker) {
            if (is_string($checker)) {
                $checker = $container->get($checker);
            }

            if ($checker instanceof Container\Autowire) {
                $checker = $checker->resolve($container);
            }

            $factory->add($alias, $checker);
        }

        return $factory;
    }

    private function createDefaultHeaderCheckerManager(
        HeaderCheckerManagerFactory $factory,
        JWTConfig $config
    ): HeaderCheckerManager {
        return $factory->create($config->getHeaderCheckerManager($config->getDefaultCheckerHeaderName())['headers']);
    }

    private function createClaimCheckerManagerFactory(
        Container $container,
        JWTConfig $config
    ): ClaimCheckerManagerFactory {
        $factory = new ClaimCheckerManagerFactory();

        foreach ($config->getClaimCheckers() as $alias => $checker) {
            if (is_string($checker)) {
                $checker = $container->get($checker);
            }

            if ($checker instanceof Container\Autowire) {
                $checker = $checker->resolve($container);
            }

            $factory->add($alias, $checker);
        }

        return $factory;
    }

    private function createDefaultClaimCheckerManager(
        ClaimCheckerManagerFactory $factory,
        JWTConfig $config
    ): ClaimCheckerManager {
        return $factory->create($config->getClaimCheckerManager($config->getDefaultCheckerClaimName())['claims']);
    }

    private function createJWSLoader(
        JWSLoaderFactory $factory,
        JWSSerializerManagerFactory $serializers,
        JWTConfig $config,
    ): JWSLoader {
        return $factory->create(
            serializers: $serializers->names(),
            algorithms: array_keys($config->getAlgorithms()),
            headerCheckers: $config->getHeaderCheckerManager($config->getDefaultCheckerHeaderName())['headers'],
        );
    }
}
