<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\Scope;
use Platine\OAuth2\Repository\ScopeRepositoryInterface;
use Platine\OAuth2\Service\ScopeService;

/**
 * ScopeService class tests
 *
 * @group core
 * @group oauth2
 */
class ScopeServiceTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $scopeRepository = $this->getMockBuilder(ScopeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $o = new ScopeService($scopeRepository);
        $this->assertInstanceOf(ScopeService::class, $o);
    }

    public function testCreateScope()
    {
        $scope = Scope::createNewScope(1, 'read');

        $scopeRepository = $this->getMockBuilder(ScopeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeRepository->expects($this->once())
                ->method('saveScope')
                ->with($scope);

        $o = new ScopeService($scopeRepository);
        $o->create($scope);
    }

    public function testGetAll()
    {
        $scope = Scope::createNewScope(1, 'read');

        $scopeRepository = $this->getMockBuilder(ScopeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeRepository->expects($this->once())
                ->method('getAllScopes')
                ->will($this->returnValue([$scope]));

        $o = new ScopeService($scopeRepository);
        $s = $o->all();

        $this->assertEquals($s, [$scope]);
    }

    public function testGetDefault()
    {
        $scope = Scope::createNewScope(1, 'read');

        $scopeRepository = $this->getMockBuilder(ScopeRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $scopeRepository->expects($this->once())
                ->method('getDefaultScopes')
                ->will($this->returnValue([$scope]));

        $o = new ScopeService($scopeRepository);
        $s = $o->defaults();

        $this->assertEquals($s, [$scope]);
    }
}
