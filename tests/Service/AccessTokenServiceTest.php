<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Exception\OAuth2Exception;
use Platine\OAuth2\Repository\AccessTokenRepositoryInterface;
use Platine\OAuth2\Service\AccessTokenService;
use Platine\OAuth2\Service\ScopeService;

/**
 * AccessTokenService class tests
 *
 * @group core
 * @group oauth2
 */
class AccessTokenServiceTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);
    }

    public function testGetTokenNotExistInDB()
    {
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $tokenRepository->expects($this->any())
                ->method('getByToken')
                ->will($this->returnValue(null));

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $this->assertNull($o->getToken('token'));
    }

    public function testGetTokenExistInDB()
    {
        $at = $this->getMockInstance(AccessToken::class, [
            'getToken' => 'token'
        ]);
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $tokenRepository->expects($this->any())
                ->method('getByToken')
                ->will($this->returnValue($at));

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $this->assertInstanceOf(AccessToken::class, $o->getToken('token'));
    }

    public function testCreateNewToken()
    {
        $scope = Scope::createNewScope(1, 'read');
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [$scope],
            'defaults' => [$scope],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = $this->getMockInstance(Client::class, [
            'getScopes' => ['read']
        ]);

        $r = $o->createToken($owner, $client, []);

        $this->assertInstanceOf(AccessToken::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
    }

    public function testCreateNewTokenScopeNotExist()
    {
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = $this->getMockInstance(Client::class, [
            'getScopes' => ['read']
        ]);

        $this->expectException(OAuth2Exception::class);
        $r = $o->createToken($owner, $client, ['read']);

        $this->assertInstanceOf(AccessToken::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
    }

    public function testCreateNewTokenScopeClientDontHaveScope()
    {
        $scope = Scope::createNewScope(1, 'read');

        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [$scope],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = $this->getMockInstance(Client::class, [
            'getScopes' => ['write']
        ]);

        $this->expectException(OAuth2Exception::class);
        $r = $o->createToken($owner, $client, ['read']);

        $this->assertInstanceOf(AccessToken::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
    }

    public function testDelete()
    {
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $tokenRepository->expects($this->once())
                ->method('delete');

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $at = $this->getMockInstance(AccessToken::class, [
            'getToken' => 'token'
        ]);


        $o->delete($at);
    }

    public function testCleanExpired()
    {
        $tokenRepository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $tokenRepository->expects($this->once())
                ->method('cleanExpired');

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AccessTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AccessTokenService::class, $o);

        $o->cleanExpired();
    }
}
