<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test;

use Platine\Dev\PlatineTestCase;
use Platine\Http\Response;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\Logger\Logger;
use Platine\OAuth2\AuthorizationServer;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\RefreshToken;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\AuthorizationGrant;
use Platine\OAuth2\Grant\ClientCredentialsGrant;
use Platine\OAuth2\Grant\GrantInterface;
use Platine\OAuth2\Grant\PasswordGrant;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\ClientService;
use Platine\OAuth2\Service\RefreshTokenService;

/**
 * AuthorizationServer class tests
 *
 * @group core
 * @group oauth2
 */
class AuthorizationServerTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [

             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );
        $this->assertInstanceOf(AuthorizationServer::class, $o);
        $this->assertEquals($authGrant->getResponseType(), 'code');
        $this->assertTrue($o->hasGrant(AuthorizationGrant::GRANT_TYPE));
        $this->assertTrue($o->hasResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));
        $this->assertFalse($o->hasGrant(ClientCredentialsGrant::GRANT_TYPE));
        $this->assertInstanceOf(GrantInterface::class, $o->getGrant(AuthorizationGrant::GRANT_TYPE));
        $this->assertInstanceOf(GrantInterface::class, $o->getResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));

        $this->expectException(OAuth2Exception::class);
        $o->getGrant(PasswordGrant::GRANT_TYPE);

        $this->expectException(OAuth2Exception::class);
        $o->getResponseType(PasswordGrant::GRANT_RESPONSE_TYPE);
    }

    public function testGetResponseTypeNotSupportted()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [

             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );
        $this->assertInstanceOf(AuthorizationServer::class, $o);
        $this->expectException(OAuth2Exception::class);
        $o->getResponseType(PasswordGrant::GRANT_RESPONSE_TYPE);
    }

    public function testHandleAuthorizationRequestMissingResponseType()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [

             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [

        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleAuthorizationRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleAuthorizationRequestClientSecretEmpty()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => false,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleAuthorizationRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }


    public function testHandleAuthorizationRequestClientIdEmpty()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleAuthorizationRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleAuthorizationRequestClientNotFoundInDb()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => null
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleAuthorizationRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleAuthorizationRequestSuccess()
    {
        $response = $this->getMockInstance(
            Response::class,
            [
                 'getStatusCode' => 200
             ],
            [
                 'withHeader',
             ]
        );

        $client = $this->getMockInstance(
            Client::class,
            [
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
                 'createAuthorizationResponse' => $response,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'hasHeader' => true,
            'getHeaderLine' => 'Bearer bXlfY2xpZW50X2lkOm15X2NsaWVudF9zZWNyZXQ',
            'getParsedBody' => [
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleAuthorizationRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 200);
    }

    public function testHandleTokenRequestSuccess()
    {
        $response = $this->getMockInstance(
            Response::class,
            [
                 'getStatusCode' => 200
             ],
            [
                 'withHeader',
             ]
        );

        $client = $this->getMockInstance(
            Client::class,
            [
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
                 'createTokenResponse' => $response,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'hasHeader' => true,
            'getHeaderLine' => 'Bearer bXlfY2xpZW50X2lkOm15X2NsaWVudF9zZWNyZXQ',
            'getParsedBody' => [
                'grant_type' => 'authorization_code',
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleTokenRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 200);
    }

    public function testHandleTokenRequestGrantTypeNotFound()
    {
        $client = $this->getMockInstance(
            Client::class,
            [
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'hasHeader' => true,
            'getHeaderLine' => 'Bearer bXlfY2xpZW50X2lkOm15X2NsaWVudF9zZWNyZXQ',
            'getParsedBody' => [
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleTokenRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleTokenRequestClientIsEmpty()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => null
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'client_secret' => 'my_client_secret',
                'grant_type' => 'authorization_code',
            ],
        ]);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $res = $o->handleTokenRequest($request, $owner);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleTokenRevocationRequestMissingParam()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => null
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'client_secret' => 'my_client_secret',
                'grant_type' => 'authorization_code',
            ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleTokenRevocationRequestWrongTokenType()
    {
        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => null
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'token' => 'my_token',
                'token_type_hint' => 'my_token_type_hint',
            ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }

    public function testHandleTokenRevocationRequestWrongClient()
    {
        $client = $this->getMockInstance(
            Client::class,
            [
                 'isPublic' => false,
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $tokenClient = $this->getMockInstance(
            Client::class,
            [
                 'getId' => '123',
                 'isPublic' => false,
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $token = $this->getMockInstance(
            AccessToken::class,
            [
                 'getClient' => $tokenClient,
             ],
        );


        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => $token,
        ]);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'token' => 'my_token',
                'token_type_hint' => 'access_token',
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 400);
    }


    public function testHandleTokenRevocationRequestDbTokenNull()
    {
        $client = $this->getMockInstance(
            Client::class,
            [
                 'isPublic' => false,
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );


        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => null,
        ]);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'token' => 'my_token',
                'token_type_hint' => 'access_token',
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 200);
        $this->assertEmpty((string) $res->getBody());
    }


    public function testHandleTokenRevocationRequestSuccess()
    {
        $client = $this->getMockInstance(
            Client::class,
            [
                 'isPublic' => true,
                 'authenticate' => true,
                 'hasRedirectUri' => true,
                 'getRedirectUris' => ['http://localhost'],
             ],
        );

        $token = $this->getMockInstance(
            AccessToken::class,
            [
                 'getClient' => null,
             ],
        );


        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                 'allowPublicClients' => true,
             ],
            [
                 'getType',
                 'getResponseType',
             ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
            'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
            'getToken' => $token,
        ]);
        $refreshTokenService = $this->getMockInstance(RefreshTokenService::class);
        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
            'getQueryParams' => [
                'response_type' => 'code',
            ],
            'getParsedBody' => [
                'token' => 'my_token',
                'token_type_hint' => 'access_token',
                'client_id' => 'my_client_id',
                'client_secret' => 'my_client_secret',
            ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 200);
        $this->assertEmpty((string) $res->getBody());
    }

    public function testHandleTokenRevocationRequestCannotDeleteToken()
    {
        $client = $this->getMockInstance(
            Client::class,
            [
                'isPublic' => true,
                'authenticate' => true,
                'hasRedirectUri' => true,
                'getRedirectUris' => ['http://localhost'],
            ],
        );

        $token = $this->getMockInstance(
            RefreshToken::class,
            [
                'getClient' => null,
            ],
        );


        $authGrant = $this->getMockInstance(
            AuthorizationGrant::class,
            [
                'allowPublicClients' => true,
            ],
            [
                'getType',
                'getResponseType',
            ]
        );
        $logger = $this->getMockInstance(Logger::class);
        $passwordGrant = $this->getMockInstance(PasswordGrant::class);
        $grants = [$authGrant, $passwordGrant];

        $clientService = $this->getMockInstance(ClientService::class, [
           'find' => $client
        ]);
        $accessTokenService = $this->getMockInstance(AccessTokenService::class, [
           'getToken' => $token,
        ]);
        $refreshTokenService = $this->getMockBuilder(RefreshTokenService::class)
                               ->disableOriginalConstructor()
                               ->getMock();

        $refreshTokenService->expects($this->any())
               ->method('delete')
               ->willThrowException(new \Exception());

        $refreshTokenService->expects($this->any())
               ->method('getToken')
               ->will($this->returnValue($token));

        $o = new AuthorizationServer(
            $clientService,
            $accessTokenService,
            $refreshTokenService,
            $logger,
            $grants
        );

        $request = $this->getMockInstance(ServerRequest::class, [
           'getQueryParams' => [
               'response_type' => 'code',
           ],
           'getParsedBody' => [
               'token' => 'my_token',
               'token_type_hint' => 'refresh_token',
               'client_id' => 'my_client_id',
               'client_secret' => 'my_client_secret',
           ],
        ]);

        $res = $o->handleTokenRevocationRequest($request);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals($res->getStatusCode(), 503);
        $this->assertEmpty((string) $res->getBody());
    }
}
