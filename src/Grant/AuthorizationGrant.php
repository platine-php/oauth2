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
use Platine\OAuth2\Response\RedirectResponse;
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
        $scopes = is_string($scope) ? explode(' ', $scope) : [];
        $authorizationCode = $this->authorizationCodeService->createToken(
            $redirectUri,
            $owner,
            $client,
            $scopes
        );

        $uri = http_build_query(array_filter([
            'code' => $authorizationCode->getToken(),
            'state' => $state,
        ]));

        return new RedirectResponse($redirectUri . '?' . $uri);
    }

    /**
     * {@inheritdoc}
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $postParams = $request->getParsedBody();
        $code = $postParams['code'] ?? null;

        if ($code === null) {
            throw OAuth2Exception::invalidRequest('Could not find the authorization code in the request');
        }

        $authorizationCode = $this->authorizationCodeService->getToken($code);
        if ($authorizationCode === null || $authorizationCode->isExpired()) {
            throw OAuth2Exception::invalidGrant('Authorization code cannot be found or is expired');
        }

        $clientId = $postParams['client_id'] ?? null;
        if ($authorizationCode->getClient()->getId() !== $clientId) {
            throw OAuth2Exception::invalidRequest(
                'Authorization code\'s client does not match with the one that created the authorization code'
            );
        }

        // If owner is null, we reuse the same as the authorization code
        if ($owner === null) {
            $owner = $authorizationCode->getOwner();
        }

        $scopes = $authorizationCode->getScopes();
        $accessToken = $this->accessTokenService->createToken($owner, $client, $scopes);
        // Before generating a refresh token, we must make sure the
        //  authorization server supports this grant

        $refreshToken = null;
        if (
            $this->authorizationServer !== null &&
            $this->authorizationServer->hasGrant(RefreshTokenGrant::GRANT_TYPE)
        ) {
            $refreshToken = $this->refreshTokenService->createToken($owner, $client, $scopes);
        }

        return $this->generateTokenResponse($accessToken, $refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorizationServer(
        AuthorizationServerInterface $authorizationServer
    ): void {
        $this->authorizationServer = $authorizationServer;
    }

    /**
     * {@inheritdoc}
     */
    public function allowPublicClients(): bool
    {
        return true;
    }
}
