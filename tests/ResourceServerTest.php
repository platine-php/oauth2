<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test;

use Platine\Dev\PlatineTestCase;
use Platine\Http\ServerRequest;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Exception\InvalidAccessTokenException;
use Platine\OAuth2\ResourceServer;
use Platine\OAuth2\Service\AccessTokenService;

/**
 * ResourceServer class tests
 *
 * @group core
 * @group oauth2
 */
class ResourceServerTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $o = new ResourceServer(
            $accessTokenService
        );
        $this->assertInstanceOf(ResourceServer::class, $o);
    }

    public function testGetAccessTokenNotFoundInRequest()
    {
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $o = new ResourceServer(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $this->assertNull($o->getAccessToken($request, ['read']));
    }

    public function testGetAccessTokenUsingRequestHeader()
    {
        $token = $this->getMockInstance(AccessToken::class, [
            'getToken' => 'my_token',
            'isValid' => true,
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => $token
        ]);
        $o = new ResourceServer(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'hasHeader' => true,
            'getHeaderLine' => 'Bearer my_token',
        ]);
        $this->assertInstanceOf(AccessToken::class, $o->getAccessToken($request, ['read']));
        $this->assertEquals($token, $o->getAccessToken($request, ['read']));
        $this->assertEquals('my_token', $o->getAccessToken($request, ['read'])->getToken());
    }

    public function testGetAccessTokenInvalidRequestHeader()
    {
        $token = $this->getMockInstance(AccessToken::class, [
            'getToken' => 'my_token',
            'isValid' => true,
            'getScopes' => [],
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => $token
        ]);
        $o = new ResourceServer(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'hasHeader' => true,
            'getHeaderLine' => 'my_token',
        ]);
        $this->assertNull($o->getAccessToken($request, ['read']));
    }

    public function testGetAccessTokenNotFoundOrInvalidUsingRequestHeader()
    {
        $token = $this->getMockInstance(AccessToken::class, [
            'getToken' => 'my_token',
            'isValid' => false,
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => $token
        ]);
        $o = new ResourceServer(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'hasHeader' => true,
            'getHeaderLine' => 'Bearer my_token',
        ]);
        $this->expectException(InvalidAccessTokenException::class);
        $o->getAccessToken($request, ['read']);
    }
}
