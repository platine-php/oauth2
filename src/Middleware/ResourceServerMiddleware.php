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

namespace Platine\OAuth2\Middleware;

use Platine\Http\Handler\MiddlewareInterface;
use Platine\Http\Handler\RequestHandlerInterface;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequestInterface;
use Platine\OAuth2\Exception\InvalidAccessTokenException;
use Platine\OAuth2\ResourceServerInterface;
use Platine\OAuth2\Response\JsonResponse;

/**
 * Middleware for a resource server
 *
 * This middleware aims to sit very early in your pipeline. It will check if a request has an access token,
 * and if so, will try to validate it. If the token is invalid, the middleware will immediately return.
 *
 * If the token is valid, it will store it as part of the request under the attribute "oauth_token",
 * so that it can be used later one by a permission system, for instance
 *
 * @class ResourceServerMiddleware
 * @package Platine\OAuth2\Middleware
 */
class ResourceServerMiddleware implements MiddlewareInterface
{
    /**
     * The resource server instance
     * @var ResourceServerInterface
     */
    protected ResourceServerInterface $resourceServer;

    /**
     * The request attribute name to fetch access token
     * @var string
     */
    protected string $tokenRequestAttribute;

    /**
     * Create new instance
     * @param ResourceServerInterface $resourceServer
     * @param string $tokenRequestAttribute
     */
    public function __construct(
        ResourceServerInterface $resourceServer,
        string $tokenRequestAttribute = 'oauth_token'
    ) {
        $this->resourceServer = $resourceServer;
        $this->tokenRequestAttribute = $tokenRequestAttribute;
    }


    /**
     * {@inheritdoc}
     */
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        try {
            $token = $this->resourceServer->getAccessToken($request);
        } catch (InvalidAccessTokenException $ex) {
            // If we're here, this means that there was an access token, but it's either expired
            // or invalid. If that's the case we must immediately return
            return new JsonResponse(
                [
                    'error' => $ex->getCode(),
                    'error_description' => $ex->getMessage(),
                ],
                401
            );
        }


        return $handler->handle($request->withAttribute($this->tokenRequestAttribute, $token));
    }
}
