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
use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\RefreshToken;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * @class RefreshTokenGrant
 * @package Platine\OAuth2\Grant
 */
class RefreshTokenGrant extends BaseGrant
{
    public const GRANT_TYPE = 'refresh_token';
    public const GRANT_RESPONSE_TYPE = '';

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
     * The Configuration instance
     * @var Configuration
     */
    protected Configuration $configuration;

    /**
     * Create new instance
     * @param AccessTokenService $accessTokenService
     * @param RefreshTokenService $refreshTokenService
     * @param Configuration $configuration
     */
    public function __construct(
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService,
        Configuration $configuration
    ) {
        $this->accessTokenService = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;
        $this->configuration = $configuration;
    }

        /**
     * {@inheritdoc}
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        throw OAuth2Exception::invalidRequest('Refresh token grant does not support authorization');
    }

    /**
     * {@inheritdoc}
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $postParams = (array) $request->getParsedBody();
        $refreshTokenValue = $postParams['refresh_token'] ?? null;
        if ($refreshTokenValue === null) {
            throw OAuth2Exception::invalidRequest('Refresh token is missin in request');
        }

        // We can fetch the actual token, and validate it
        /** @var RefreshToken|null $refreshToken */
        $refreshToken = $this->refreshTokenService->getToken((string) $refreshTokenValue);
        if ($refreshToken === null || $refreshToken->isExpired()) {
            throw OAuth2Exception::invalidGrant('Refresh token is expired');
        }

        // We can now create a new access token! First, we need to make some checks on the asked scopes,
        // because according to the spec, a refresh token can create an access token
        // with an equal or lesser scope, but not more
        $scope = $postParams['scope'] ?? null;
        $scopes = is_string($scope) ? explode(' ', $scope) : $refreshToken->getScopes();
        if ($refreshToken->matchScopes($scopes) === false) {
            throw OAuth2Exception::invalidScope(
                'The scope of the new access token exceeds the scope(s) of the refresh token'
            );
        }

        $refreshTokenOwner = $refreshToken->getOwner();
        $accessToken = $this->accessTokenService->createToken($refreshTokenOwner, $client, $scopes);
        // We may want to revoke the old refresh token
        if ($this->configuration->isRotateRefreshToken()) {
            if ($this->configuration->isRevokeRotatedRefreshToken()) {
                $this->refreshTokenService->delete($refreshToken);
            }

            /** @var RefreshToken $refreshToken */
            $refreshToken = $this->refreshTokenService->createToken($refreshTokenOwner, $client, $scopes);
        }

        return $this->generateTokenResponse($accessToken, $refreshToken, true);
    }


    /**
     * {@inheritdoc}
     */
    public function allowPublicClients(): bool
    {
        return true;
    }
}
