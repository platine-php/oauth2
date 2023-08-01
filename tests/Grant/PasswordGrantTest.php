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
use Platine\OAuth2\Entity\UserAuthenticationInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\AuthorizationGrant;
use Platine\OAuth2\Grant\PasswordGrant;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\AuthorizationCodeService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * PasswordGrant class tests
 *
 * @group core
 * @group oauth2
 */
class PasswordGrantTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
            $accessTokenService,
            $refreshTokenService
        );
        $this->assertInstanceOf(PasswordGrant::class, $o);
        $this->assertTrue($o->allowPublicClients());
        $this->assertEmpty($o->getResponseType());
        $this->assertEquals('password', $o->getType());
    }

    public function testSetAuthorizationServer()
    {
        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
            $accessTokenService,
            $refreshTokenService
        );

        $this->assertInstanceOf(PasswordGrant::class, $o);
        $this->assertNull($this->getPropertyValue(PasswordGrant::class, $o, 'authorizationServer'));

        $authorizationServer = $this->getMockBuilder(AuthorizationServerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $o->setAuthorizationServer($authorizationServer);

        $this->assertInstanceOf(
            AuthorizationServerInterface::class,
            $this->getPropertyValue(PasswordGrant::class, $o, 'authorizationServer')
        );
    }

    public function testCreateAuthorizationResponse()
    {
        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
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



    public function testCreateTokenResponseUsernameOrPasswordNotFoundRequest()
    {
        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
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

    public function testCreateTokenResponseInvalidUsernameOrPassword()
    {
        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $userAuthentication->expects($this->any())
                ->method('validate')
                ->with('my_username', 'my_password')
                ->will($this->returnValue(null));

        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
            $accessTokenService,
            $refreshTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'username' => 'my_username',
                'password' => 'my_password',
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
        $tokenOwner = $this->getMockBuilder(TokenOwnerInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $userAuthentication = $this->getMockBuilder(UserAuthenticationInterface::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();

        $userAuthentication->expects($this->any())
                ->method('validate')
                ->with('my_username', 'my_password')
                ->will($this->returnValue($tokenOwner));

        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new PasswordGrant(
            $userAuthentication,
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
                'username' => 'my_username',
                'password' => 'my_password',
            ]
        ]);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->createTokenResponse($request, $client, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(200, $res->getStatusCode());
    }
}
