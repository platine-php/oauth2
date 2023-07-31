<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Grant;

use Platine\Dev\PlatineTestCase;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\AuthorizationServerInterface;
use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\AuthorizationCode;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\RefreshToken;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\AuthorizationGrant;
use Platine\OAuth2\Grant\RefreshTokenGrant;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\AuthorizationCodeService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * RefreshTokenGrant class tests
 *
 * @group core
 * @group oauth2
 */
class RefreshTokenGrantTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $cfg = $this->getMockInstance(Configuration::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $this->assertInstanceOf(RefreshTokenGrant::class, $o);
        $this->assertTrue($o->allowPublicClients());
        $this->assertEmpty($o->getResponseType());
        $this->assertEquals('refresh_token', $o->getType());
    }

    public function testCreateAuthorizationResponse()
    {
        $cfg = $this->getMockInstance(Configuration::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createAuthorizationResponse($request, $client, $owner);
    }



    public function testCreateTokenResponseRefreshTokenFoundRequest()
    {
        $cfg = $this->getMockInstance(Configuration::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponseWrongRefreshToken()
    {
        $cfg = $this->getMockInstance(Configuration::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'refresh_token' => 'my_refresh_token'
            ]
        ]);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponseWrongScope()
    {
        $rt = $this->getMockInstance(RefreshToken::class, [
            'getToken' => 'my_refresh_token',
            'matchScopes' => false,
        ]);


        $cfg = $this->getMockInstance(Configuration::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class, [
            'getToken' => $rt
        ]);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'refresh_token' => 'my_refresh_token'
            ]
        ]);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponse()
    {
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $rt = $this->getMockInstance(RefreshToken::class, [
            'getToken' => 'my_refresh_token',
            'matchScopes' => true,
            'getOwner' => $owner,
        ]);


        $cfg = $this->getMockInstance(Configuration::class, [
            'isRotateRefreshToken' => true,
            'isRevokeRotatedRefreshToken' => true,
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class, [
            'getToken' => $rt
        ]);
        $o = new RefreshTokenGrant(
            $accessTokenService,
            $refreshTokenService,
            $cfg
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'refresh_token' => 'my_refresh_token'
            ]
        ]);

        $client = $this->getMockInstance(Client::class);


        $res = $o->createTokenResponse($request, $client, null);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(200, $res->getStatusCode());
    }
}
