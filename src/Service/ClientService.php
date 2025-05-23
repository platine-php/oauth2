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

namespace Platine\OAuth2\Service;

use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Repository\ClientRepositoryInterface;

/**
 * @class ClientService
 * @package Platine\OAuth2\Service
 */
class ClientService
{
    /**
     * Create new instance
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(protected ClientRepositoryInterface $clientRepository)
    {
    }

    /**
     * Create new client
     * @param string $name
     * @param array<string> $redirectUris
     * @param array<string> $scopes
     * @return array<int, Client|string>
     */
    public function create(
        string $name,
        array $redirectUris,
        array $scopes = []
    ): array {
        do {
            $client = Client::createNewClient(
                $name,
                $redirectUris,
                $scopes
            );
        } while ($this->clientRepository->clientIdExists($client->getId()));

        $secret = $client->generateSecret();
        $this->clientRepository->saveClient($client);

        return [$client, $secret];
    }

    /**
     * Return the client based on the id
     * @param string $id
     * @return Client|null
     */
    public function find(string $id): ?Client
    {
        return $this->clientRepository->findClient($id);
    }
}
