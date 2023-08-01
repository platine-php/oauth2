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

use Platine\Http\ServerRequestInterface;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Exception\InvalidAccessTokenException;
use Platine\OAuth2\Service\AccessTokenService;

/**
 * The resource server main role is to validate the access token and that its scope covers the
 * requested resource
 *
 * Currently, the resource server only implements the Bearer token usage, as described in the
 * RFC 6750 (http://tools.ietf.org/html/rfc6750)
 *
 * @class ResourceServer
 * @package Platine\OAuth2
 */
class ResourceServer implements ResourceServerInterface
{
    /**
     * The AccessTokenService
     * @var AccessTokenService
     */
    protected AccessTokenService $accessTokenService;

    /**
     * Create new instance
     * @param AccessTokenService $accessTokenService
     */
    public function __construct(
        AccessTokenService $accessTokenService
    ) {
        $this->accessTokenService = $accessTokenService;
    }

    /**
     * {@inheritdoc}
     * Note that this method will only match tokens that are not expired and match the given scopes
     * (if any). If no token is pass, this method will return null, but if a token is given
     * and does not exist (ie. has been deleted) or is not valid, then it will trigger an exception
     *
     * @link   http://tools.ietf.org/html/rfc6750#page-5
     */
    public function getAccessToken(ServerRequestInterface $request, $scopes = []): ?AccessToken
    {
        $accessToken = $this->getTokenFromRequest($request);
        if ($accessToken === null) {
            return null;
        }

        /** @var AccessToken|null $token */
        $token = $this->accessTokenService->getToken($accessToken);
        if ($token === null || $token->isValid($scopes) === false) {
            throw InvalidAccessTokenException::invalidToken(
                'Access token has expired or has been deleted'
            );
        }

        return $token;
    }

    /**
     * Return the access token value using server request
     * @param ServerRequestInterface $request
     * @return string|null
     */
    protected function getTokenFromRequest(ServerRequestInterface $request): ?string
    {
        // The preferred way is using Authorization header
        if ($request->hasHeader('Authorization')) {
            // Header value is expected to be "Bearer xxx"
            $parts = explode(' ', $request->getHeaderLine('Authorization'));
            if (count($parts) < 2) {
                return null;
            }

            return end($parts);
        }
        // Default back to authorization in query param
        $queryParams = $request->getQueryParams();

        return $queryParams['access_token'] ?? null;
    }
}
