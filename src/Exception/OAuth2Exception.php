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

namespace Platine\OAuth2\Exception;

use Exception;

/**
 * @class OAuth2Exception
 * @package Platine\OAuth2\Exception
 */
class OAuth2Exception extends Exception
{
    /**
     * Create new instance
     * @param string $message
     * @param string $code
     */
    public function __construct(string $message, string $code)
    {
        parent::__construct($message);
        $this->code = $code;
    }

    /**
     * Throw exception for access denied
     * @param string $description
     * @return self
     */
    public static function accessDenied(string $description): self
    {
        return new self($description, 'access_denied');
    }

    /**
     * Throw exception for invalid request
     * @param string $description
     * @return self
     */
    public static function invalidRequest(string $description): self
    {
        return new self($description, 'invalid_request');
    }

    /**
     * Throw exception for invalid client
     * @param string $description
     * @return self
     */
    public static function invalidClient(string $description): self
    {
        return new self($description, 'invalid_client');
    }

    /**
     * Throw exception for invalid grant
     * @param string $description
     * @return self
     */
    public static function invalidGrant(string $description): self
    {
        return new self($description, 'invalid_grant');
    }

    /**
     * Throw exception for invalid scope
     * @param string $description
     * @return self
     */
    public static function invalidScope(string $description): self
    {
        return new self($description, 'invalid_scope');
    }

    /**
     * Throw exception for server error
     * @param string $description
     * @return self
     */
    public static function serverError(string $description): self
    {
        return new self($description, 'server_error');
    }

    /**
     * Throw exception for temporarily unavailable
     * @param string $description
     * @return self
     */
    public static function temporarilyUnavailable(string $description): self
    {
        return new self($description, 'temporarily_unavailable');
    }

    /**
     * Throw exception for unauthorized client
     * @param string $description
     * @return self
     */
    public static function unauthorizedClient(string $description): self
    {
        return new self($description, 'unauthorized_client');
    }

    /**
     * Throw exception for unsupported grant type
     * @param string $description
     * @return self
     */
    public static function unsupportedGrantType(string $description): self
    {
        return new self($description, 'unsupported_grant_type');
    }

    /**
     * Throw exception for unsupported response type
     * @param string $description
     * @return self
     */
    public static function unsupportedResponseType(string $description): self
    {
        return new self($description, 'unsupported_response_type');
    }

    /**
     * Throw exception for unsupported token type
     * @param string $description
     * @return self
     */
    public static function unsupportedTokenType(string $description): self
    {
        return new self($description, 'unsupported_token_type');
    }
}
