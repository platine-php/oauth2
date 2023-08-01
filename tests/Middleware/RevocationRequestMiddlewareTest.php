<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Middleware;

use Platine\Dev\PlatineTestCase;
use Platine\Http\Handler\RequestHandlerInterface;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\AuthorizationServer;
use Platine\OAuth2\Middleware\RevocationRequestMiddleware;

/**
 * RevocationRequestMiddleware class tests
 *
 * @group core
 * @group oauth2
 */
class RevocationRequestMiddlewareTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $authorizationServer = $this->getMockInstance(AuthorizationServer::class);
        $o = new RevocationRequestMiddleware(
            $authorizationServer
        );
        $this->assertInstanceOf(RevocationRequestMiddleware::class, $o);
    }

    public function testProcess()
    {
        $request = $this->getMockInstance(ServerRequest::class);
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $authorizationServer = $this->getMockInstance(AuthorizationServer::class);

        $authorizationServer->expects($this->once())
                ->method('handleTokenRevocationRequest')
                ->with($request);

        $o = new RevocationRequestMiddleware(
            $authorizationServer
        );

        $res = $o->process($request, $handler);
        $this->assertInstanceOf(ResponseInterface::class, $res);
    }
}
