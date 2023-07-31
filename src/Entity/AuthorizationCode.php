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

namespace Platine\OAuth2\Entity;

/**
 * @class AuthorizationCode
 * @package Platine\OAuth2\Entity
 */
class AuthorizationCode extends BaseToken
{
    /**
     * The redirect URI
     * @var string
     */
    protected string $redirectUri;

    /**
     * Create new authorization code
     * @param int $ttl
     * @param string|null $redirectUri
     * @param TokenOwnerInterface|null $owner
     * @param Client|null $client
     * @param array<string>|Scope[]|null $scopes
     * @return $this
     */
    public static function createNewAuthorizationCode(
        int $ttl,
        ?string $redirectUri = null,
        ?TokenOwnerInterface $owner = null,
        ?Client $client = null,
        ?array $scopes = null
    ): self {
        $code = static::createNew($ttl, $owner, $client, $scopes);

        $code->redirectUri = $redirectUri ?? '';

        return $code;
    }

    /**
     * {@inheritdoc}
     */
    public static function hydrate(array $data): self
    {
        $code = parent::hydrate($data);
        $code->redirectUri = $data['redirect_uri'];

        return $code;
    }

    /**
     * Return the redirect URI
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }
}
