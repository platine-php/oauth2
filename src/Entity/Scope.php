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
 * @class Scope
 * @package Platine\OAuth2\Entity
 */
class Scope
{
    /**
     * The scope id
     * @var int
     */
    protected int $id;

    /**
     * The scope name
     * @var string
     */
    protected string $name;

    /**
     * The scope description
     * @var string|null
     */
    protected ?string $description = null;

    /**
     * Whether is the default scope
     * @var bool
     */
    protected bool $isDefault = false;

    /**
     * Can not rewrite the constructor in child classes
     */
    final public function __construct()
    {
    }

    /**
     * Create new scope
     * @param int $id
     * @param string $name
     * @param string|null $description
     * @param bool $isDefault
     * @return self
     */
    public static function createNewScope(
        int $id,
        string $name,
        ?string $description = null,
        bool $isDefault = false
    ): self {
        $scope = new static();
        $scope->id = $id;
        $scope->name = $name;
        $scope->description = $description;
        $scope->isDefault = $isDefault;

        return $scope;
    }

    /**
     * Create scope using given data
     * @param array<string, mixed> $data
     * @return self
     */
    public static function hydrate(array $data): self
    {
        $scope = new static();
        $scope->id = $data['id'];
        $scope->name = $data['name'];
        $scope->description = $data['description'];
        $scope->isDefault = $data['is_default'];

        return $scope;
    }

    /**
     * Return the id
     * @return int
     */
    public function getId(): int
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
     * Return the description
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * Whether is the default scope
     * @return bool
     */
    public function isDefault(): bool
    {
        return $this->isDefault;
    }


    /**
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->name;
    }
}
