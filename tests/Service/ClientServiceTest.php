<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Service;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Repository\ClientRepositoryInterface;
use Platine\OAuth2\Service\ClientService;

/**
 * ClientService class tests
 *
 * @group core
 * @group oauth2
 */
class ClientServiceTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $o = new ClientService($clientRepository);
        $this->assertInstanceOf(ClientService::class, $o);
    }

    public function testCreateClient()
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $clientRepository->expects($this->once())
                ->method('save');

        $o = new ClientService($clientRepository);


        $res = $o->create('Platine App', ['http://localhost'], ['read']);
        $this->assertCount(2, $res);
        $this->assertInstanceOf(Client::class, $res[0]);
        $this->assertNotEmpty($res[1]);
    }

    public function testFind()
    {
        $client = Client::createNewClient('Platine App');
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)
                                ->disableOriginalConstructor()
                                ->getMock();

        $clientRepository->expects($this->once())
                ->method('find')
                ->with('1234567890')
                ->will($this->returnValue($client));

        $o = new ClientService($clientRepository);
        $c = $o->find('1234567890');

        $this->assertEquals($c, $client);
    }
}
