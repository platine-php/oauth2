<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Configuration;
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
}
