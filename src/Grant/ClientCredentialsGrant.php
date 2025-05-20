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
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Service\AccessTokenService;

/**
 * This is the most easy grant. It can creates an access token only by authenticating the client
 *
 * @class ClientCredentialsGrant
 * @package Platine\OAuth2\Grant
 */
class ClientCredentialsGrant extends BaseGrant
{
    public const GRANT_TYPE = 'client_credentials';
    public const GRANT_RESPONSE_TYPE = '';

    /**
     * Create new instance
     * @param AccessTokenService $accessTokenService
     */
    public function __construct(
        protected AccessTokenService $accessTokenService
    ) {
    }

     /**
     * {@inheritdoc}
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        throw OAuth2Exception::invalidRequest('Client credentials grant does not support authorization');
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
        $scope = $postParams['scope'] ?? null;
        $scopes = is_string($scope) ? explode(' ', $scope) : [];

        $accessToken = $this->accessTokenService->createToken($owner, $client, $scopes);

        return $this->generateTokenResponse($accessToken);
    }


    /**
     * {@inheritdoc}
     */
    public function allowPublicClients(): bool
    {
        return false;
    }
}
