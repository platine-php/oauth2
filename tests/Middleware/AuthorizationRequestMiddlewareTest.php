<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Middleware;

use Platine\Dev\PlatineTestCase;
use Platine\Http\Handler\RequestHandlerInterface;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\AuthorizationServer;
use Platine\OAuth2\Middleware\AuthorizationRequestMiddleware;

/**
 * AuthorizationRequestMiddleware class tests
 *
 * @group core
 * @group oauth2
 */
class AuthorizationRequestMiddlewareTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $authorizationServer = $this->getMockInstance(AuthorizationServer::class);
        $o = new AuthorizationRequestMiddleware(
            $authorizationServer
        );
        $this->assertInstanceOf(AuthorizationRequestMiddleware::class, $o);
    }

    public function testProcess()
    {
        $request = $this->getMockInstance(ServerRequest::class, [
            'getAttribute' => null
        ]);
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $authorizationServer = $this->getMockInstance(AuthorizationServer::class);

        $authorizationServer->expects($this->once())
                ->method('handleAuthorizationRequest')
                ->with($request, null);

        $o = new AuthorizationRequestMiddleware(
            $authorizationServer
        );

        $res = $o->process($request, $handler);
        $this->assertInstanceOf(ResponseInterface::class, $res);
    }
}
