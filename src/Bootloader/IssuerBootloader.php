<?php

namespace Cardyo\SpiralJwtAuth\Bootloader;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Spiral\Boot\Bootloader\Bootloader;
use Spiral\Core\Attribute\Singleton;

#[Singleton]
final class IssuerBootloader extends Bootloader
{
    protected const DEPENDENCIES = [
        BaseBootloader::class,
    ];

    public const BINDINGS = [
        JWSBuilder::class => [self::class, 'createJWSBuilder'],
    ];

    public function createJWSBuilder(AlgorithmManager $algorithmManager): JWSBuilder
    {
        return (new JWSBuilder($algorithmManager))->create();
    }
}
