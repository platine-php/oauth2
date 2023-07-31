<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\RefreshToken;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Repository\RefreshTokenRepositoryInterface;
use Platine\OAuth2\Service\RefreshTokenService;
use Platine\OAuth2\Service\ScopeService;

/**
 * RefreshTokenService class tests
 *
 * @group core
 * @group oauth2
 */
class RefreshTokenServiceTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $tokenRepository = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new RefreshTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(RefreshTokenService::class, $o);
    }


    public function testCreateNewToken()
    {
        $scope = Scope::createNewScope(1, 'read');
        $tokenRepository = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [$scope],
            'defaults' => [$scope],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new RefreshTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(RefreshTokenService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = $this->getMockInstance(Client::class, [
            'getScopes' => ['read']
        ]);

        $r = $o->createToken($owner, $client, []);

        $this->assertInstanceOf(RefreshToken::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
    }

    public function testCreateNewTokenClientIsNull()
    {
        $scope = Scope::createNewScope(1, 'read');
        $tokenRepository = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [$scope],
            'defaults' => [$scope],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new RefreshTokenService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(RefreshTokenService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = null;

        $r = $o->createToken($owner, $client, []);

        $this->assertInstanceOf(RefreshToken::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
    }
}
