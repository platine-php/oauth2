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

namespace Platine\OAuth2;

use Platine\Http\Response;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequestInterface;
use Platine\OAuth2\AuthorizationServerInterface;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\AuthorizationServerAwareInterface;
use Platine\OAuth2\Grant\GrantInterface;
use Platine\OAuth2\Response\JsonResponse;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\ClientService;
use Platine\OAuth2\Service\RefreshTokenService;
use Throwable;

/**
 * @class AuthorizationServer
 * @package Platine\OAuth2
 */
class AuthorizationServer implements AuthorizationServerInterface
{
    /**
     * The ClientService
     * @var ClientService
     */
    protected ClientService $clientService;

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
     * The grant list
     * @var array<string, GrantInterface>
     */
    protected array $grants = [];

    /**
     * A list of grant that can answer to an authorization request
     * @var array<string, GrantInterface>
     */
    protected array $responseTypes = [];

    /**
     * Create new instance
     * @param ClientService $clientService
     * @param AccessTokenService $accessTokenService
     * @param RefreshTokenService $refreshTokenService
     * @param array<string, GrantInterface> $grants
     */
    public function __construct(
        ClientService $clientService,
        AccessTokenService $accessTokenService,
        RefreshTokenService $refreshTokenService,
        array $grants = []
    ) {
        $this->clientService = $clientService;
        $this->accessTokenService = $accessTokenService;
        $this->refreshTokenService = $refreshTokenService;

        foreach ($grants as /** @var GrantInterface $grant */ $grant) {
            if ($grant instanceof AuthorizationServerAwareInterface) {
                $grant->setAuthorizationServer($this);
            }

            $this->grants[$grant->getType()] = $grant;

            $responseType = $grant->getResponseType();
            if (!empty($responseType)) {
                $this->responseTypes[$responseType] = $grant;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function handleAuthorizationRequest(
        ServerRequestInterface $request,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        try {
            $queryParams = $request->getQueryParams();
            $responseTypeParam = $queryParams['response_type'] ?? null;
            if ($responseTypeParam === null) {
                throw OAuth2Exception::invalidRequest('No grant response type was found in the request');
            }

            $responseType = $this->getResponseType((string) $responseTypeParam);
            $client = $this->getClient($request, $responseType->allowPublicClients());

            if ($client === null) {
                throw OAuth2Exception::invalidClient('No client could be authenticated');
            }

            $response = $responseType->createAuthorizationResponse($request, $client, $owner);
        } catch (OAuth2Exception $ex) {
            $response = $this->createResponsFromException($ex);
        }

        return $response->withHeader('Content-Type', 'application/json');
    }

    /**
     * {@inheritdoc}
     */
    public function handleTokenRequest(
        ServerRequestInterface $request,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface {
        $postParams = (array) $request->getParsedBody();

        try {
            $grantParam = $postParams['grant_type'] ?? null;
            if ($grantParam === null) {
                throw OAuth2Exception::invalidRequest('No grant type was found in the request');
            }

            $grant = $this->getGrant((string) $grantParam);
            $client = $this->getClient($request, $grant->allowPublicClients());

            if ($client === null) {
                throw OAuth2Exception::invalidClient('No client could be authenticated');
            }

            $response = $grant->createTokenResponse($request, $client, $owner);
        } catch (OAuth2Exception $ex) {
            $response = $this->createResponsFromException($ex);
        }

        // According to the spec, we must set those headers
        // (http://tools.ietf.org/html/rfc6749#section-5.1)
        return $response->withHeader('Content-Type', 'application/json')
                        ->withHeader('Cache-Control', 'no-store')
                        ->withHeader('Pragma', 'no-cache');
    }

    /**
     * {@inheritdoc}
     */
    public function handleTokenRevocationRequest(ServerRequestInterface $request): ResponseInterface
    {
        $postParams = (array) $request->getParsedBody();
        $tokenParam = $postParams['token'] ?? null;
        $tokenHint = $postParams['token_type_hint'] ?? null;
        if ($tokenParam === null || $tokenHint === null) {
            throw OAuth2Exception::invalidRequest(
                'Cannot revoke a token as the "token" and/or "token_type_hint" parameters are missing'
            );
        }

        if (in_array($tokenHint, ['access_token', 'refresh_token']) === false) {
            throw OAuth2Exception::unsupportedTokenType(sprintf(
                'Authorization server does not support revocation of token of type "%s"',
                $tokenHint
            ));
        }

        if ($tokenHint === 'access_token') {
            $token = $this->accessTokenService->getToken((string) $tokenParam);
        } else {
            $token = $this->refreshTokenService->getToken((string) $tokenParam);
        }

        $response = new Response();
        // According to spec, we should return 200 if token is invalid
        if ($token === null) {
            return $response;
        }

        // Now, we must validate the client if the token was generated against a non-public client
        if ($token->getClient() !== null && $token->getClient()->isPublic() === false) {
            $requestClient = $this->getClient($request, false);

            if ($requestClient !== $token->getClient()) {
                throw OAuth2Exception::invalidClient(
                    'Token was issued for another client and cannot be revoked'
                );
            }
        }

        try {
            if ($tokenHint === 'access_token') {
                $this->accessTokenService->delete($token);
            } else {
                $this->refreshTokenService->delete($token);
            }
        } catch (Throwable $ex) {
            // According to spec (https://tools.ietf.org/html/rfc7009#section-2.2.1),
            // we should return a server 503
            // error if we cannot delete the token for any reason
            $response = $response->withStatus(503, 'An error occurred while trying to delete the token');
        }

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    public function hasGrant(string $grant): bool
    {
        return array_key_exists($grant, $this->grants);
    }

    /**
     * {@inheritdoc}
     */
    public function hasResponseType(string $responseType): bool
    {
        return array_key_exists($responseType, $this->responseTypes);
    }

    /**
     * Return the grant
     * @param string $grantType
     * @return GrantInterface
     */
    public function getGrant(string $grantType): GrantInterface
    {
        if ($this->hasGrant($grantType)) {
            return $this->grants[$grantType];
        }

        throw OAuth2Exception::unsupportedGrantType(sprintf(
            'Grant type "%s" is not supported by this server',
            $grantType
        ));
    }

    /**
     * Return the grant response type
     * @param string $responseType
     * @return GrantInterface
     */
    public function getResponseType(string $responseType): GrantInterface
    {
        if ($this->hasResponseType($responseType)) {
            return $this->responseTypes[$responseType];
        }

        throw OAuth2Exception::unsupportedResponseType(sprintf(
            'Response type "%s" is not supported by this server',
            $responseType
        ));
    }

    /**
     * Get the client (after authenticating it)
     *
     * According to the spec (http://tools.ietf.org/html/rfc6749#section-2.3), for public clients we do
     * not need to authenticate them
     *
     * @param ServerRequestInterface $request
     * @param bool $allowPublicClients
     * @return Client|null
     */
    protected function getClient(ServerRequestInterface $request, bool $allowPublicClients): ?Client
    {
        [$id, $secret] = $this->getClientCredentialsFromRequest($request);

        // If the grant type we are issuing does not allow public clients, and that the secret is
        // missing, then we have an error...
        if ($allowPublicClients === false && empty($secret)) {
            throw OAuth2Exception::invalidClient('Client secret is missing');
        }

        // If we allow public clients and no client id was set, we can return null
        if ($allowPublicClients && empty($id)) {
            return null;
        }

        $client = $this->clientService->find($id);
        // We delegate all the checks to the client service
        if ($client === null || ($allowPublicClients === false && $client->authenticate($secret) === false)) {
            throw OAuth2Exception::invalidClient('Client authentication failed');
        }

        return $client;
    }

    /**
     * Create a response from the exception, using the format of the spec
     * @link   http://tools.ietf.org/html/rfc6749#section-5.2
     *
     * @param OAuth2Exception $exception
     * @return ResponseInterface
     */
    protected function createResponsFromException(OAuth2Exception $exception): ResponseInterface
    {
        $data = [
            'error' => $exception->getCode(),
            'error_description' => $exception->getMessage(),
        ];

        return new JsonResponse($data, 400);
    }

    /**
     * Return the client id and secret from request data
     * @param ServerRequestInterface $request
     * @return array<string>
     */
    protected function getClientCredentialsFromRequest(ServerRequestInterface $request): array
    {
        // We first try to get the Authorization header, as this is
        // the recommended way according to the spec
        if ($request->hasHeader('Authorization')) {
            // Header value is expected to be "Bearer xxx"
            $parts = explode(' ', $request->getHeaderLine('Authorization'));
            $value = base64_decode(end($parts));

            [$id, $secret] = explode(':', $value);
        } else {
            $postParams = (array) $request->getParsedBody();
            $id = $postParams['client_id'] ?? null;
            $secret = $postParams['client_secret'] ?? null;
        }

        return [$id, $secret];
    }
}
