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

use Platine\Stdlib\Helper\Str;
use RuntimeException;

/**
 * @class Client
 * @package Platine\OAuth2\Entity
 */
class Client
{
    /**
     * The client id
     * @var string
     */
    protected string $id;

    /**
     * The client name
     * @var string
     */
    protected string $name;

    /**
     * The client secret
     * @var string
     */
    protected string $secret = '';

    /**
     * The client redirect URIs
     * @var array<string>
     */
    protected array $redirectUris = [];

    /**
     * The client scopes
     * @var array<string>
     */
    protected array $scopes = [];

    /**
     * Can not rewrite the constructor in child classes
     */
    final public function __construct()
    {
    }

    /**
     * Create new client
     * @param string $name
     * @param string|array<string>|null $redirectUris
     * @param array<string>|null $scopes
     * @return self
     */
    public static function createNewClient(
        string $name,
        string|array|null $redirectUris = null,
        ?array $scopes = null
    ): self {
        if (is_string($redirectUris)) {
            $redirectUris = explode(' ', $redirectUris);
        }

        if ($redirectUris !== null) {
            foreach ($redirectUris as &$redirectUri) {
                $redirectUri = trim((string) $redirectUri);
            }
        }

        $client = new static();
        $client->id = Str::randomString('hexdec', 20);
        $client->name = $name;
        $client->redirectUris = $redirectUris ?? [];
        $client->scopes = $scopes ?? [];

        return $client;
    }

    /**
     * Create client using given data
     * @param array<string, mixed> $data
     * @return self
     */
    public static function hydrate(array $data): self
    {
        $client = new static();
        $client->id = $data['id'];
        $client->name = $data['name'];
        $client->secret = $data['secret'];
        $client->redirectUris = (array) $data['redirect_uris'];
        $client->scopes = $data['scopes'];

        return $client;
    }

    /**
     * Return the client id
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Return the name
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Return the secret
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Return the redirect URIs
     * @return array<string>
     */
    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    /**
     * Return the scopes
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Whether the client has the given redirect URI
     * @param string $redirectUri
     * @return bool
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->redirectUris, true);
    }

    /**
     * Whether it's the public client
     * @return bool
     */
    public function isPublic(): bool
    {
        return empty($this->secret);
    }

    /**
     * Authenticate the client
     * @return bool
     */
    public function authenticate(string $secret): bool
    {
        return password_verify($secret, $this->getSecret());
    }

    /**
     * Generate a strong, unique secret and crypt it.
     * @return string
     */
    public function generateSecret(): string
    {
        $secret = bin2hex(random_bytes(20));
        $secretHash = password_hash($secret, PASSWORD_DEFAULT);
        if ($secretHash === false) {
            throw new RuntimeException('Can not hash secret');
        }
        $this->secret = $secretHash;

        return $secret;
    }
}
