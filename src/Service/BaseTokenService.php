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
use Platine\OAuth2\Entity\BaseToken;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Repository\TokenRepositoryInterface;

/**
 * @class BaseTokenService
 * @package Platine\OAuth2\Service
 */
class BaseTokenService
{
    /**
     * The TokenRepository instance
     * @var TokenRepositoryInterface
     */
    protected $tokenRepository;

    /**
     * The ScopeService instance
     * @var ScopeService
     */
    protected ScopeService $scopeService;

    /**
     * The Configuration instance
     * @var Configuration
     */
    protected Configuration $configuration;

    /**
     * Create new instance
     * @param TokenRepositoryInterface $tokenRepository
     * @param ScopeService $scopeService
     * @param Configuration $configuration
     */
    public function __construct(
        TokenRepositoryInterface $tokenRepository,
        ScopeService $scopeService,
        Configuration $configuration
    ) {
        $this->tokenRepository = $tokenRepository;
        $this->scopeService = $scopeService;
        $this->configuration = $configuration;
    }

    /**
     * Return the token entity of given token value
     * @param string $tokenValue
     * @return BaseToken|null
     */
    public function getToken(string $tokenValue): ?BaseToken
    {
        $token = $this->tokenRepository->getByToken($tokenValue);
        // Because the collation is most often case insensitive, we need to add a
        // check here to ensure that the token matches case
        if ($token === null || hash_equals($token->getToken(), $tokenValue) === false) {
            return null;
        }


        return $token;
    }

    /**
     * Delete the given token
     * @param BaseToken $token
     * @return void
     */
    public function delete(BaseToken $token): void
    {
        $this->tokenRepository->delete($token);
    }

    /**
     * Clean the expired tokens
     * @return void
     */
    public function cleanExpired(): void
    {
        $this->tokenRepository->cleanExpired();
    }

    /**
     *
     * @param array<string>|Scope[] $scopes
     * @param Client|null $client
     * @return void
     */
    public function validateTokenScopes(array $scopes, ?Client $client = null): void
    {
        $scopeList = array_map(fn($scope) => (string) $scope, $scopes);

        $persistentScopes = $this->scopeService->all();
        $persistentList = array_map(fn($scope) => (string) $scope, $persistentScopes);

        $diff = array_diff($scopeList, $persistentList);
        if (count($diff) > 0) {
            throw OAuth2Exception::invalidScope(sprintf(
                'Some scope(s) do not exist: [%s]',
                implode(', ', $diff)
            ));
        }

        if ($client === null) {
            return;
        }

        $clientScopes = $client->getScopes();
        $diffClient = array_diff($scopeList, $clientScopes);
        if (count($diffClient) > 0) {
            throw OAuth2Exception::invalidScope(sprintf(
                'Some scope(s) are not assigned to client: %s',
                implode(', ', $diff)
            ));
        }
    }
}
