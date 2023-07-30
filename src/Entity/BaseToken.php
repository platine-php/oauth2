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

/**
 *  @file Configuration.php
 *
 *  The OAuth2 Configuration class
 *
 *  @package    Platine\OAuth2
 *  @author Platine Developers Team
 *  @copyright  Copyright (c) 2020
 *  @license    http://opensource.org/licenses/MIT  MIT License
 *  @link   http://www.iacademy.cf
 *  @version 1.0.0
 *  @filesource
 */

declare(strict_types=1);

namespace Platine\OAuth2;

use Platine\Stdlib\Config\AbstractConfiguration;

/**
 * @class Configuration
 * @package Platine\OAuth2
 */
class Configuration extends AbstractConfiguration
{
    /**
     * Return the access token request attribute value
     * @return string
     */
    public function getTokenRequestAttribute(): string
    {
        return $this->get('request_attribute.token');
    }

    /**
     * Return the owner request attribute value
     * @return string
     */
    public function getOwnerRequestAttribute(): string
    {
        return $this->get('request_attribute.owner');
    }

    /**
     * Return the authorization code TTL value
     * @return int
     */
    public function getAuthorizationCodeTtl(): int
    {
        return $this->get('ttl.authorization_code');
    }

    /**
     * Return the access token TTL value
     * @return int
     */
    public function getAccessTokenTtl(): int
    {
        return $this->get('ttl.access_token');
    }

    /**
     * Return the refresh token TTL value
     * @return int
     */
    public function getRefreshTokenTtl(): int
    {
        return $this->get('ttl.refresh_token');
    }

    /**
     * Whether need rotate refresh token
     * @return bool
     */
    public function isRotateRefreshToken(): bool
    {
        return $this->get('rotate_refresh_token');
    }

    /**
     * Whether need rotate refresh token after revocation
     * @return bool
     */
    public function isRevokeRotatedRefreshToken(): bool
    {
        return $this->get('revoke_rotated_refresh_token');
    }

    /**
     * Return the supported grants
     * @return array<int, string>
     */
    public function getGrants(): array
    {
        return $this->get('grants');
    }

    /**
     * {@inheritdoc}
     */
    public function getValidationRules(): array
    {
        return [
            'request_attribute' => 'array',
            'request_attribute.token' => 'string',
            'request_attribute.owner' => 'string',
            'ttl' => 'array',
            'ttl.authorization_code' => 'integer',
            'ttl.access_token' => 'integer',
            'ttl.refresh_token' => 'integer',
            'rotate_refresh_token' => 'boolean',
            'revoke_rotated_refresh_token' => 'boolean',
            'grants' => 'array'
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getDefault(): array
    {
        return [
            'grants' => [],
            'ttl' => [
                'authorization_code' => 120,
                'access_token' => 3600,
                'refresh_token' => 86400,
            ],
            'rotate_refresh_token' => false,
            'revoke_rotated_refresh_token' => true,
            'request_attribute' => [
                'token' => 'oauth_token',
                'owner' => 'owner',
            ],
        ];
    }
}
