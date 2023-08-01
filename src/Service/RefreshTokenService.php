<?php

/**
 * Platine OAuth2
 *
 * Platine OAuth2 is a library that implements the OAuth2 specification
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2020 Platine OAuth2
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace Platine\OAuth2\Service;

use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\RefreshToken;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Repository\RefreshTokenRepositoryInterface;

/**
 * @class RefreshTokenService
 * @package Platine\OAuth2\Service
 */
class RefreshTokenService extends BaseTokenService
{
    /**
     * The RefreshTokenRepositoryInterface instance
     * @var RefreshTokenRepositoryInterface
     */
    protected $tokenRepository;

    /**
     * Create new instance
     * @param RefreshTokenRepositoryInterface $tokenRepository
     * @param ScopeService $scopeService
     * @param Configuration $configuration
     */
    public function __construct(
        RefreshTokenRepositoryInterface $tokenRepository,
        ScopeService $scopeService,
        Configuration $configuration
    ) {
        parent::__construct($tokenRepository, $scopeService, $configuration);
    }

    /**
     * Create new refresh token
     * @param TokenOwnerInterface|null $owner
     * @param Client|null $client
     * @param array<string>|Scope[] $scopes
     * @return RefreshToken
     */
    public function createToken(
        ?TokenOwnerInterface $owner = null,
        ?Client $client = null,
        array $scopes = []
    ): RefreshToken {
        if (count($scopes) === 0) {
            $scopes = $this->scopeService->defaults();
        }

        $this->validateTokenScopes($scopes, $client);
        do {
            $token = RefreshToken::createNewRefreshToken(
                $this->configuration->getRefreshTokenTtl(),
                $owner,
                $client,
                $scopes
            );
        } while ($this->tokenRepository->isTokenExists($token->getToken()));

        return $this->tokenRepository->saveRefreshToken($token);
    }
}
