<?php

namespace Cardyo\SpiralJwtAuth\Config;

use Jose\Component\Checker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm as SignatureAlgorithm;
use Jose\Component\Signature\JWSTokenSupport;
use Spiral\Core\Container\Autowire;
use Spiral\Core\InjectableConfig;

/**
 * @psalm-type AlgorithmEntry = Algorithm|class-string<Algorithm>|Autowire<Algorithm>
 *
 * @psalm-type JWKEntry = JWK|(callable(mixed...): JWK)
 * @psalm-type JWKSetEntry = JWKSet|(callable(mixed...): JWKSet)|array<array-key, string|JWKEntry>
 *
 * @psalm-type TokenTypeEntry = TokenTypeSupport|class-string<TokenTypeSupport>
 *
 * @psalm-type HeaderCheckerEntry = HeaderChecker|class-string<HeaderChecker>|Autowire<HeaderChecker>
 * @psalm-type HeaderCheckerManagerEntry = array{
 *     headers: array<int, HeaderCheckerEntry|string>
 * }
 *
 * @psalm-type ClaimCheckerEntry = Checker\ClaimChecker|class-string<Checker\ClaimChecker>|Autowire<Checker\ClaimChecker>
 * @psalm-type ClaimCheckerManagerEntry = array{
 *     claims: array<int, ClaimCheckerEntry|string>
 * }
 *
 * @psalm-type JWTConfigData = array{
 *     algorithms: array<string, AlgorithmEntry>,
 *     checkers: array{
 *         token_types: array<int, TokenTypeEntry>,
 *         header_checkers: array<string, HeaderCheckerEntry>,
 *         claim_checkers: array<string, ClaimCheckerEntry>,
 *         headers: array<string, HeaderCheckerManagerEntry>,
 *         claims: array<string, ClaimCheckerManagerEntry>,
 *     },
 * }
 */
final class JWTConfig extends InjectableConfig
{
    public const CONFIG = 'jwt';

    /**
     * @psalm-type JWTConfigData
     */
    public array $config = [
        'algorithms' => [
            'HS256' => SignatureAlgorithm\HS256::class
        ],
        'keys' => [],
        'keysets' => [],
        'checkers' => [
            'token_types' => [
                JWSTokenSupport::class,
            ],
            'header_checkers' => [],
            'claim_checkers' => [
                'iat' => Checker\IssuedAtChecker::class,
                'nbf' => Checker\NotBeforeChecker::class,
                'exp' => Checker\ExpirationTimeChecker::class,
            ],
            'headers' => [
                'default' => [
                    'types' => [
                        JWSTokenSupport::class,
                    ],
                    'headers' => [],
                ],
            ],
            'claims' => [
                'default' => [
                    'claims' => [
                        'iat',
                        'nbf',
                        'exp',
                    ],
                ],
            ],
        ],
        'default_key' => 'default',
        'default_keyset' => 'default',
        'default_checker_header' => 'default',
        'default_checker_claim' => 'default',
    ];

    /**
     * @return array<string, AlgorithmEntry>
     */
    public function getAlgorithms(): array
    {
        return $this->config['algorithms'];
    }

    /**
     * @return array<string, JWKEntry>
     */
    public function getKeys(): array
    {
        return $this->config['keys'];
    }

    /**
     * @return JWKEntry
     */
    public function getKey(string $key): mixed
    {
        return $this->config['keys'][$key];
    }

    public function hasKey(string $key): bool
    {
        return isset($this->config['keys'][$key]);
    }

    public function getDefaultKeyName(): string
    {
        return $this->config['default_key'];
    }

    /**
     * @return array<string, JWKSetEntry>
     */
    public function getKeySets(): array
    {
        return $this->config['keysets'];
    }

    public function hasKeySet(string $keyset): bool
    {
        return isset($this->config['keysets'][$keyset]);
    }

    /**
     * @return JWKSetEntry
     */
    public function getKeySet(string $keyset): mixed
    {
        return $this->config['keysets'][$keyset];
    }

    public function getDefaultKeySetName(): string
    {
        return $this->config['default_keyset'];
    }

    /**
     * @return array<int, TokenTypeEntry>
     */
    public function getSupportedTokenTypes(): array
    {
        return $this->config['checkers']['token_types'];
    }

    /**
     * @return array<string, HeaderCheckerEntry>
     */
    public function getHeaderCheckers(): array
    {
        return $this->config['checkers']['header_checkers'];
    }

    /**
     * @return array<string, ClaimCheckerEntry>
     */
    public function getClaimCheckers(): array
    {
        return $this->config['checkers']['claim_checkers'];
    }

    public function getHeaderCheckerManager(string $name): array
    {
        return $this->config['checkers']['headers'][$name];
    }

    public function getDefaultCheckerHeaderName(): string
    {
        return $this->config['default_checker_header'];
    }

    public function getClaimCheckerManager(string $name): array
    {
        return $this->config['checkers']['claims'][$name];
    }

    public function getDefaultCheckerClaimName(): string
    {
        return $this->config['default_checker_claim'];
    }
}
