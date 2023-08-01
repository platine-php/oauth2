<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Grant;

use Platine\Dev\PlatineTestCase;
use Platine\Http\ResponseInterface;
use Platine\Http\ServerRequest;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Grant\ClientCredentialsGrant;
use Platine\OAuth2\Service\AccessTokenService;

/**
 * ClientCredentialsGrant class tests
 *
 * @group core
 * @group oauth2
 */
class ClientCredentialsGrantTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $o = new ClientCredentialsGrant(
            $accessTokenService
        );
        $this->assertInstanceOf(ClientCredentialsGrant::class, $o);
        $this->assertFalse($o->allowPublicClients());
        $this->assertEmpty($o->getResponseType());
        $this->assertEquals('client_credentials', $o->getType());
    }

    public function testCreateAuthorizationResponse()
    {
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $o = new ClientCredentialsGrant(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class);
        $client = $this->getMockInstance(Client::class);
        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $this->expectException(OAuth2Exception::class);
        $o->createAuthorizationResponse($request, $client, $owner);
    }

    public function testCreateTokenResponse()
    {
        $accessTokenService = $this->getMockInstance(AccessTokenService::class);
        $o = new ClientCredentialsGrant(
            $accessTokenService
        );
        $request = $this->getMockInstance(ServerRequest::class, [
            'getParsedBody' => [
                'scope' => 'my_refresh_token'
            ]
        ]);

        $client = $this->getMockInstance(Client::class);


        $res = $o->createTokenResponse($request, $client, null);
        $this->assertInstanceOf(ResponseInterface::class, $res);
        $this->assertEquals(200, $res->getStatusCode());
    }
}
