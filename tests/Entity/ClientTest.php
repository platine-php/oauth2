<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Entity;

use DateTimeInterface;
use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\AccessToken;
use Platine\OAuth2\Entity\Client;

/**
 * Client class tests
 *
 * @group core
 * @group oauth2
 */
class ClientTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        global $mock_bin2hex, $mock_random_int;

        $mock_bin2hex = true;
        $mock_random_int = true;

        $o = Client::createNewClient('Platine App', 'http://localhost', ['read']);
        $this->assertInstanceOf(Client::class, $o);

        $this->assertTrue($o->isPublic());
        $this->assertEquals('00000000000000000000', $o->getId());
        $this->assertEquals('Platine App', $o->getName());
        $redirectUris = $o->getRedirectUris();
        $this->assertCount(1, $redirectUris);
        $this->assertEquals('http://localhost', $redirectUris[0]);
        $this->assertTrue($o->hasRedirectUri('http://localhost'));
        $this->assertFalse($o->hasRedirectUri('http://127.0.0.1'));
        $this->assertCount(1, $o->getScopes());
        $this->assertEmpty($o->getSecret());
        $this->assertEquals('token_bin2hex', $o->generateSecret());
        $this->assertTrue($o->authenticate('token_bin2hex'));
        $this->assertFalse($o->authenticate('token_bin2hexxx'));
    }

    public function testHydrate()
    {
        global $mock_bin2hex, $mock_random_int;

        $mock_bin2hex = true;
        $mock_random_int = true;

        $o = Client::hydrate([
            'id' => '00000000000000000000',
            'name' => 'Platine App',
            'secret' => 'token_bin2hex',
            'redirect_uris' => ['http://localhost'],
            'scopes' => ['read'],
        ]);
        $this->assertInstanceOf(Client::class, $o);

        $this->assertFalse($o->isPublic());
        $this->assertEquals('00000000000000000000', $o->getId());
        $this->assertEquals('Platine App', $o->getName());
        $redirectUris = $o->getRedirectUris();
        $this->assertCount(1, $redirectUris);
        $this->assertEquals('http://localhost', $redirectUris[0]);
        $this->assertTrue($o->hasRedirectUri('http://localhost'));
        $this->assertFalse($o->hasRedirectUri('http://127.0.0.1'));
        $this->assertCount(1, $o->getScopes());
        $this->assertEquals('token_bin2hex', $o->getSecret());
        $this->assertEquals('token_bin2hex', $o->generateSecret());
        $this->assertTrue($o->authenticate('token_bin2hex'));
        $this->assertFalse($o->authenticate('token_bin2hexxx'));
    }
}
