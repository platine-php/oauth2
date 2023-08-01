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

use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequestInterface;
use Platine\OAuth2\Entity\TokenOwnerInterface;

/**
 * The authorization server main role is to create access tokens or refresh tokens
 *
 * @class AuthorizationServerInterface
 * @package Platine\OAuth2
 */
interface AuthorizationServerInterface
{
    /**
     * Whether the authorization server has support the given grant
     * @param string $grant
     * @return bool
     */
    public function hasGrant(string $grant): bool;

    /**
     * Whether the authorization server has support the given response type
     * @param string $responseType
     * @return bool
     */
    public function hasResponseType(string $responseType): bool;

    /**
     * Handle authorization request
     * @param ServerRequestInterface $request
     * @param TokenOwnerInterface|null $owner
     * @return ResponseInterface
     */
    public function handleAuthorizationRequest(
        ServerRequestInterface $request,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface;

    /**
     * Handle token request
     * @param ServerRequestInterface $request
     * @param TokenOwnerInterface|null $owner
     * @return ResponseInterface
     */
    public function handleTokenRequest(
        ServerRequestInterface $request,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface;

    /**
     * Handle token revocation request
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    public function handleTokenRevocationRequest(ServerRequestInterface $request): ResponseInterface;
}
