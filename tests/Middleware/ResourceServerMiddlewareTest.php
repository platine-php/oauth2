<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Middleware;

use Platine\Dev\PlatineTestCase;
use Platine\Http\Handler\RequestHandlerInterface;
use Platine\Http\Response;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Exception\InvalidAccessTokenException;
use Platine\OAuth2\Middleware\ResourceServerMiddleware;
use Platine\OAuth2\ResourceServer;

/**
 * ResourceServerMiddleware class tests
 *
 * @group core
 * @group oauth2
 */
class ResourceServerMiddlewareTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $resourceServer = $this->getMockInstance(ResourceServer::class);
        $o = new ResourceServerMiddleware(
            $resourceServer
        );
        $this->assertInstanceOf(ResourceServerMiddleware::class, $o);
    }

    public function testProcess()
    {
        $response = $this->getMockInstance(Response::class);
        $token = $this->getMockInstance(AccessToken::class);

        $request = $this->getMockInstance(
            ServerRequest::class,
            [
                'getAttribute' => []
            ],
            [
                'withAttribute',
            ]
        );
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $handler->expects($this->any())
                ->method('handle')
                ->will($this->returnValue($response));

        $resourceServer = $this->getMockInstance(ResourceServer::class, [
            'getAccessToken' => $token
        ]);

        $o = new ResourceServerMiddleware(
            $resourceServer
        );

        $res = $o->process($request, $handler);
        $this->assertInstanceOf(ResponseInterface::class, $res);
    }

    public function testProcessTokenNotFound()
    {
        $response = $this->getMockInstance(Response::class);

        $request = $this->getMockInstance(
            ServerRequest::class,
            [
                'getAttribute' => []
            ],
            [
                'withAttribute',
            ]
        );
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $handler->expects($this->any())
                ->method('handle')
                ->will($this->returnValue($response));

        $resourceServer = $this->getMockInstance(ResourceServer::class, [
            'getAccessToken' => null
        ]);

        $resourceServer->expects($this->any())
                ->method('getAccessToken')
                ->willThrowException(new InvalidAccessTokenException('', ''));

        $o = new ResourceServerMiddleware(
            $resourceServer
        );

        $res = $o->process($request, $handler);
        $this->assertInstanceOf(ResponseInterface::class, $res);
    }
}
