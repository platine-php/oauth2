<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Grant;

use Platine\Dev\PlatineTestCase;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\AuthorizationServerInterface;
use Platine\OAuth2\Entity\AuthorizationCode;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\AuthorizationGrant;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\AuthorizationCodeService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * AuthorizationGrant class tests
 *
 * @group core
 * @group oauth2
 */
class AuthorizationGrantTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $this->assertInstanceOf(AuthorizationGrant::class, $o);
        $this->assertTrue($o->allowPublicClients());
        $this->assertEquals('code', $o->getResponseType());
        $this->assertEquals('authorization_code', $o->getType());
    }

    public function testSetAuthorizationServer()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );

        $this->assertInstanceOf(AuthorizationGrant::class, $o);
        $this->assertNull($this->getPropertyValue(AuthorizationGrant::class, $o, 'authorizationServer'));

        $authorizationServer = $this->getMockBuilder(AuthorizationServerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $o->setAuthorizationServer($authorizationServer);

        $this->assertInstanceOf(
            AuthorizationServerInterface::class,
            $this->getPropertyValue(AuthorizationGrant::class, $o, 'authorizationServer')
        );
    }

    public function testCreateAuthorizationResponseWrongGrantType()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createAuthorizationResponse($request, $client, $owner);
    }

    public function testCreateAuthorizationResponseInValidRedirectUri()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code'
            ]
        ]);
        $client = $this->getMockInstance(Client::class, [
            'getRedirectUris' => ['http://localhost'],
            'hasRedirectUri' => false,
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createAuthorizationResponse($request, $client, $owner);
    }

    public function testCreateAuthorizationResponseSuccess()
    {
        $authCode = $this->getMockInstance(AuthorizationCode::class, [
            'getToken' => 'my_code'
        ]);

        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class, [
            'createToken' => $authCode,
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
                'state' => 'my_state',
            ]
        ]);
        $client = $this->getMockInstance(Client::class, [
            'getRedirectUris' => ['http://localhost'],
            'hasRedirectUri' => true,
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->createAuthorizationResponse($request, $client, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(302, $res->getStatusCode());
        $this->assertEquals('http://localhost?code=my_code&state=my_state', $res->getHeaderLine('location'));
    }

    public function testCreateTokenResponseCodeNotFoundRequest()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponseWrongCode()
    {
        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'code' => 'my_code'
            ]
        ]);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponseWrongClient()
    {
        $authClient = $this->getMockInstance(Client::class, [
            'getId' => 'my_client_id'
        ]);


        $authCode = $this->getMockInstance(AuthorizationCode::class, [
            'getToken' => 'my_code',
            'getClient' => $authClient,
        ]);

        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class, [
            'getToken' => $authCode,

        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'code' => 'my_code'
            ]
        ]);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createTokenResponse($request, $client, $owner);
    }

    public function testCreateTokenResponseWithoutRefreshToken()
    {
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $authClient = $this->getMockInstance(Client::class, [
            'getId' => 'my_client_id'
        ]);


        $authCode = $this->getMockInstance(AuthorizationCode::class, [
            'getToken' => 'my_code',
            'getClient' => $authClient,
            'getOwner' => $owner,
        ]);

        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class, [
            'getToken' => $authCode,

        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'code' => 'my_code',
                'client_id' => 'my_client_id',
            ]
        ]);
        $client = $this->getMockInstance(Client::class);


        $res = $o->createTokenResponse($request, $client, null);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(200, $res->getStatusCode());
    }

    public function testCreateTokenResponseWithtRefreshToken()
    {
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $authClient = $this->getMockInstance(Client::class, [
            'getId' => 'my_client_id'
        ]);


        $authCode = $this->getMockInstance(AuthorizationCode::class, [
            'getToken' => 'my_code',
            'getClient' => $authClient,
            'getOwner' => $owner,
        ]);

        $authorizationCodeService = $this->getMockInstance(AuthorizationCodeService::class, [
            'getToken' => $authCode,

        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationGrant(
            $authorizationCodeService,
            $accessTokenService,
            $refreshTokenService
        );

        $authorizationServer = $this->getMockBuilder(AuthorizationServerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $authorizationServer->expects($this->any())
                ->method('hasGrant')
                ->will($this->returnValue(true));

        $o->setAuthorizationServer($authorizationServer);

        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'code' => 'my_code',
                'client_id' => 'my_client_id',
            ]
        ]);
        $client = $this->getMockInstance(Client::class);


        $res = $o->createTokenResponse($request, $client, null);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(200, $res->getStatusCode());
    }
}
