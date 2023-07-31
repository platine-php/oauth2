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

use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Repository\ScopeRepositoryInterface;

/**
 * @class ScopeService
 * @package Platine\OAuth2\Service
 */
class ScopeService
{
    /**
     * The ScopeRepository instance
     * @var ScopeRepositoryInterface
     */
    protected ScopeRepositoryInterface $scopeRepository;

    /**
     * Create new instance
     * @param ScopeRepositoryInterface $scopeRepository
     */
    public function __construct(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * Create new scope
     * @param Scope $scope
     * @return Scope
     */
    public function create(Scope $scope): Scope
    {
        return $this->scopeRepository->save($scope);
    }

    /**
     * Return all scopes
     * @return array<Scope>
     */
    public function all(): array
    {
        return $this->scopeRepository->all();
    }

    /**
     * Return all defaults scopes
     * @return array<Scope>
     */
    public function defaults(): array
    {
        return $this->scopeRepository->defaults();
    }
}
