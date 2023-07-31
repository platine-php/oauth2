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

use DateTime;
use DateTimeInterface;

/**
 * Provide basic functionality for both access tokens, refresh tokens and authorization codes
 * Please note that scopes are stored as a string instead using
 * associations to scope entities, mainly for performance reasons and to avoid useless database calls.
 *
 * @class BaseToken
 * @package Platine\OAuth2\Entity
 */
abstract class BaseToken
{
    /**
     * The token value
     * @var string
     */
    protected string $token;

    /**
     * The client to use
     * @var Client|null
     */
    protected ?Client $client = null;

    /**
     * The token owner
     * @var TokenOwnerInterface|null
     */
    protected ?TokenOwnerInterface $owner = null;

    /**
     * The token expires at
     * @var DateTimeInterface|null
     */
    protected ?DateTimeInterface $expireAt = null;

    /**
     * The scopes associated with the token
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
     * Create token using given data
     * @param array<string, mixed> $data
     * @return self
     */
    public static function hydrate(array $data): self
    {
        $token = new static();
        $token->token = $data['token'];
        $token->owner = $data['owner'];
        $token->client = $data['client'];
        $token->scopes = (array) $data['scopes'];
        $token->expireAt = $data['expires_at'];

        return $token;
    }

    /**
     * Return the token owner
     * @return TokenOwnerInterface|null
     */
    public function getOwner(): ?TokenOwnerInterface
    {
        return $this->owner;
    }

    /**
     * Return the client
     * @return Client|null
     */
    public function getClient(): ?Client
    {
        return $this->client;
    }

    /**
     * Return the token value
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Return the expires at
     * @return DateTimeInterface|null
     */
    public function getExpireAt(): ?DateTimeInterface
    {
        return $this->expireAt ? clone $this->expireAt : null;
    }


    /**
     * Return the token expires in (seconds)
     * (if expired, will return a negative value)
     * @return int
     */
    public function getExpiresIn(): int
    {
        if ($this->expireAt === null) {
            return 0;
        }

        return $this->expireAt->getTimestamp() - (new DateTime())->getTimestamp();
    }

    /**
     * Whether the token is expired
     * @return bool
     */
    public function isExpired(): bool
    {
        if ($this->expireAt === null) {
            return true;
        }

        return $this->expireAt->getTimestamp() <= (new DateTime())->getTimestamp();
    }

    /**
     * Return the scopes
     *
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Match the scopes of the token with the one provided in the parameter
     * @param string|array<string> $scopes
     * @return bool
     */
    public function matchScopes($scopes): bool
    {
        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        }
        $diff = array_diff($scopes, $this->scopes);

        return count($diff) === 0;
    }

    /**
     * Check if the token is valid, according to the
     * given scope(s) and expiration dates
     * @param string|array<string> $scopes
     * @return bool
     */
    public function isValid($scopes): bool
    {
        if ($this->isExpired()) {
            return false;
        }

        if (!empty($scopes) && $this->matchScopes($scopes) === false) {
            return false;
        }

        return true;
    }

    /**
     * Create new token
     * @param int $ttl
     * @param TokenOwnerInterface|null $owner
     * @param Client|null $client
     * @param array<string>|Scope[]|null $scopes
     * @return self
     */
    protected static function createNew(
        int $ttl,
        ?TokenOwnerInterface $owner = null,
        ?Client $client = null,
        ?array $scopes = null
    ): self {
        if (is_array($scopes)) {
            $scopes = array_map(fn($scope) => (string) $scope, $scopes);
        }

        $token = new static();
        $token->token = bin2hex(random_bytes(20));
        $token->owner = $owner;
        $token->client = $client;
        $token->scopes = $scopes ?? [];
        $token->expireAt = $ttl ? (new DateTime())->modify(sprintf('+%d seconds', $ttl)) : null;

        return $token;
    }
}
