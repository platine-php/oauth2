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
use Platine\OAuth2\Entity\AuthorizationCode;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Repository\AuthorizationCodeRepositoryInterface;

/**
 * @class AuthorizationCodeService
 * @package Platine\OAuth2\Service
 */
class AuthorizationCodeService extends BaseTokenService
{
    /**
     * The AuthorizationCodeRepositoryInterface instance
     * @var AuthorizationCodeRepositoryInterface
     */
    protected $tokenRepository;

    /**
     * Create new instance
     * @param AuthorizationCodeRepositoryInterface $tokenRepository
     * @param ScopeService $scopeService
     * @param Configuration $configuration
     */
    public function __construct(
        AuthorizationCodeRepositoryInterface $tokenRepository,
        ScopeService $scopeService,
        Configuration $configuration
    ) {
        parent::__construct($tokenRepository, $scopeService, $configuration);
    }

    /**
     * Create new authorization code
     * @param string $redirectUri
     * @param TokenOwnerInterface $owner
     * @param Client $client
     * @param array<string>|array<Scope> $scopes
     * @return AuthorizationCode
     */
    public function createToken(
        string $redirectUri,
        TokenOwnerInterface $owner,
        Client $client,
        array $scopes = []
    ): AuthorizationCode {
        if (count($scopes) === 0) {
            $scopes = $this->scopeService->defaults();
        }

        $this->validateTokenScopes($scopes, $client);
        do {
            $token = AuthorizationCode::createNewAuthorizationCode(
                $this->configuration->getAuthorizationCodeTtl(),
                $redirectUri,
                $owner,
                $client,
                $scopes
            );
        } while ($this->tokenRepository->exists($token->getToken()));

        return $this->tokenRepository->save($token);
    }
}
