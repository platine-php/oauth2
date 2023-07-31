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

namespace Platine\OAuth2\Grant;

use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequestInterface;
use Platine\OAuth2\AuthorizationServerInterface;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\AuthorizationCodeService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * @class AuthorizationGrant
 * @package Platine\OAuth2\Grant
 */
class AuthorizationGrant extends BaseGrant implements AuthorizationServerAwareInterface
{
    public const GRANT_TYPE = 'authorization_code';
    public const GRANT_RESPONSE_TYPE = 'code';

    /**
     * The AuthorizationCodeService
     * @var AuthorizationCodeService
     */
    protected AuthorizationCodeService $authorizationCodeService;

    /**
     * The AccessTokenService
     * @var AccessTokenService
     */
    protected AccessTokenService $accessTokenService;

    /**
     * The RefreshTokenService
     * @var RefreshTokenService
     */
    protected RefreshTokenService $refreshTokenService;

    /**
     * The authorization server instance
     * @var AuthorizationServerInterface|null
     */
    protected ?AuthorizationServerInterface $authorizationServer = null;

    /**
     * Create new instance
     * @param AuthorizationCodeService $authorizationCodeService
     * @param AccessTokenService $accessTokenService
     * @param RefreshTokenService $refreshTokenService
     */
    public function __construct(
        AuthorizationCodeService $authorizationCodeService,
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService
    ) {
        $this->authorizationCodeService = $authorizationCodeService;
        $this->accessTokenService = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;
    }

        /**
     * {@inheritdoc}
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $queryParams = $request->getQueryParams();

        // We must validate some parameters first
        $responseType = $queryParams['response_type'] ?? null;
        if ($responseType !== self::GRANT_RESPONSE_TYPE) {
            throw OAuth2Exception::invalidRequest(sprintf(
                'The desired grant type must be "code", but "%s" was given',
                $responseType
            ));
        }

        // We try to fetch the redirect URI from query param as per spec,
        // and if none found, we just use the first redirect URI defined in the client
        $clientRedirectUris = $client->getRedirectUris();
        $redirectUri = $queryParams['redirect_uri'] ?? $clientRedirectUris[0];

        // If the redirect URI cannot be found in the list, we throw an error
        // as we don't want the user to be redirected to an unauthorized URL
        if ($client->hasRedirectUri($redirectUri) === false) {
            throw OAuth2Exception::invalidRequest('Redirect URI does not match the client registered one');
        }

        // Scope and state allow to perform additional validation
        $scope = $queryParams['scope'] ?? null;
        $state = $queryParams['state'] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorizationServer(
        AuthorizationServerInterface $authorizationServer
    ): void {
    }

    /**
     * {@inheritdoc}
     */
    public function allowPublicClients(): bool
    {
        return true;
    }
}
