<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Configuration;
use Platine\OAuth2\Entity\AuthorizationCode;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Entity\TokenOwnerInterface;
use Platine\OAuth2\Repository\AuthorizationCodeRepositoryInterface;
use Platine\OAuth2\Service\AuthorizationCodeService;
use Platine\OAuth2\Service\ScopeService;

/**
 * AuthorizationCodeService class tests
 *
 * @group core
 * @group oauth2
 */
class AuthorizationCodeServiceTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $tokenRepository = $this->getMockBuilder(AuthorizationCodeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AuthorizationCodeService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AuthorizationCodeService::class, $o);
    }

    public function testCreateNewToken()
    {
        $scope = Scope::createNewScope(1, 'read');
        $tokenRepository = $this->getMockBuilder(AuthorizationCodeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeService = $this->getMockInstance(ScopeService::class, [
            'all' => [$scope],
            'defaults' => [$scope],
        ]);
        $cfg = $this->getMockInstance(Configuration::class);
        $o = new AuthorizationCodeService(
            $tokenRepository,
            $scopeService,
            $cfg
        );
        $this->assertInstanceOf(AuthorizationCodeService::class, $o);

        $owner = $this->getMockBuilder(TokenOwnerInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $client = $this->getMockInstance(Client::class, [
            'getScopes' => ['read']
        ]);

        $r = $o->createToken('http://localhost', $owner, $client, []);

        $this->assertInstanceOf(AuthorizationCode::class, $r);
        $this->assertEquals(0, $r->getExpiresIn());
        $this->assertEquals('', $r->getToken());
        $this->assertEquals('', $r->getRedirectUri());
    }
}
