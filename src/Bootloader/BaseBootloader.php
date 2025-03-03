<?php

namespace Cardyo\SpiralJwtAuth\Bootloader;

use Cardyo\SpiralJwtAuth\Config\JWTConfig;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Jose\Component\Signature\Serializer as SignatureSerializer;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Spiral\Boot\Bootloader\Bootloader;
use Spiral\Config\ConfiguratorInterface;
use Spiral\Core\Attribute\Singleton;
use Spiral\Core\Container;
use Spiral\Core\InvokerInterface;

#[Singleton]
final class BaseBootloader extends Bootloader
{
    public const KEY_PREFIX = JWK::class . '#';
    public const KEYSET_PREFIX = JWKSet::class . '#';

    public const SINGLETONS = [
        AlgorithmManagerFactory::class => [self::class, 'createAlgorithmManagerFactory'],
        AlgorithmManager::class => [self::class, 'createAlgorithmManager'],

        JWK::class => [self::class, 'createDefaultJWK'],
        JWKSet::class => [self::class, 'createDefaultJWKSet'],

        JWSSerializerManagerFactory::class => [self::class, 'createJWSSerializerManagerFactory'],
    ];

    public function __construct(
        private readonly ConfiguratorInterface $config,
    ) {
    }

    public function init(Container $container): void
    {
        $this->config->setDefaults(JWTConfig::CONFIG, []);$config = $container->get(JWTConfig::class);

        foreach ($config->getKeys() as $alias => $key) {
            $container->bindSingleton(
                self::KEY_PREFIX . $alias,
                fn() => $this->createJWK($alias, $container, $config)
            );
        }

        foreach ($config->getKeySets() as $alias => $keySet) {
            $container->bindSingleton(
                self::KEYSET_PREFIX . $alias,
                fn() => $this->createJWKSet($alias, $container, $config)
            );
        }
    }

    private function createAlgorithmManagerFactory(
        ContainerInterface $container,
        JWTConfig $config
    ): AlgorithmManagerFactory {
        $factory = new AlgorithmManagerFactory();

        foreach ($config->getAlgorithms() as $name => $algorithm) {
            if (!$algorithm instanceof Algorithm) {
                $algorithm = $container->get($algorithm);
            }

            $factory->add($name, $algorithm);
        }

        return $factory;
    }

    private function createJWK(string $alias, InvokerInterface $invoker, JWTConfig $config): JWK
    {
        $jwk = $config->getKey($alias);

        if (is_callable($jwk) && !$jwk instanceof JWK) {
            $jwk = $invoker->invoke($jwk);
        }

        return $jwk;
    }

    public function createAlgorithmManager(AlgorithmManagerFactory $factory, JWTConfig $config): AlgorithmManager
    {
        return $factory->create(array_keys($config->getAlgorithms()));
    }

    private function createDefaultJWK(InvokerInterface $invoker, JWTConfig $config): JWK
    {
        return $this->createJWK($config->getDefaultKeyName(), $invoker, $config);
    }

    private function createJWKSet(
        string $alias,
        Container $container,
        JWTConfig $config
    ): JWKSet {
        $jwkSet = $config->getKeySet($alias);

        if (is_callable($jwkSet) && !$jwkSet instanceof JWKSet) {
            $jwkSet = $container->invoke($jwkSet);
        } else if (is_array($jwkSet)) {
            $jwkSet = array_map(static function (mixed $jwk) use ($container, $config): JWK {
                if ($jwk instanceof JWK) {
                    return $jwk;
                }

                if (is_string($jwk) && $config->hasKey($jwk)) {
                    return $container->get(self::KEY_PREFIX . $jwk);
                }

                if (is_callable($jwk)) {
                    return $container->invoke($jwk);
                }

                if ($container->has($jwk)) {
                    return $container->get($jwk);
                }

                return $jwk;
            }, $jwkSet);
        }

        if (is_array($jwkSet)) {
            $jwkSet = new JWKSet($jwkSet);
        }

        return $jwkSet;
    }

    private function createDefaultJWKSet(Container $container, JWTConfig $config): JWKSet
    {
        return $this->createJWKSet($config->getDefaultKeySetName(), $container, $config);
    }

    private function createJWSSerializerManagerFactory(): JWSSerializerManagerFactory
    {
        $factory = new JWSSerializerManagerFactory();

        // todo: this should be configurable
        $factory->add(new SignatureSerializer\CompactSerializer());
        $factory->add(new SignatureSerializer\JSONGeneralSerializer());
        $factory->add(new SignatureSerializer\JSONFlattenedSerializer());

        return $factory;
    }
}
