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

/**
 * Interface that all authorization grant type should implement
 *
 * Please note that the grants DOES NOT authenticate the client. This is done in the authorization
 * server. You must therefore make sure that the grants are only called from the authorization server
 *
 * @class GrantInterface
 * @package Platine\OAuth2\Grant
 * @link http://tools.ietf.org/html/rfc6749#section-1.3
 */
interface GrantInterface
{
    /**
     * Need to be overwrite by each grant
     */
    public const GRANT_TYPE = '';
    public const GRANT_RESPONSE_TYPE = '';

    /**
     * Create the authorization response
     * @param ServerRequestInterface $request
     * @param Client $client
     * @param TokenOwnerInterface|null $owner
     * @return ResponseInterface
     */
    public function createAuthorizationResponse(
        ServerRequestInterface $request,
        Client $client,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface;

    /**
     * Create the token response
     * @param ServerRequestInterface $request
     * @param Client|null $client
     * @param TokenOwnerInterface|null $owner
     * @return ResponseInterface
     */
    public function createTokenResponse(
        ServerRequestInterface $request,
        ?Client $client = null,
        ?TokenOwnerInterface $owner = null
    ): ResponseInterface;

    /**
     * Return the grant type
     * @return string
     */
    public function getType(): string;

    /**
     * Return the grant response type
     * @return string
     */
    public function getResponseType(): string;

    /**
     * Whether this grant allow public clients
     * @return bool
     */
    public function allowPublicClients(): bool;
}
