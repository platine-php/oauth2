<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Entity;

use DateTimeInterface;
use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\AccessToken;

/**
 * AccessToken class tests
 *
 * @group core
 * @group oauth2
 */
class AccessTokenTest extends PlatineTestCase
{
    public function testCreateAccessTokenDefault()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = AccessToken::createNewAccessToken(3600, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(AccessToken::class, $o);

        $this->assertInstanceOf(DateTimeInterface::class, $o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(3600, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->isValid('read'));
    }

    public function testCreateAccessTokenTtlZero()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = AccessToken::createNewAccessToken(0, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(AccessToken::class, $o);

        $this->assertNull($o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(0, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->matchScopes('read'));
        $this->assertTrue($o->isValid('read'));
        $this->assertFalse($o->isValid('write'));
    }

    public function testCreateAccessTokenExpired()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = AccessToken::createNewAccessToken(-100, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(AccessToken::class, $o);

        $this->assertInstanceOf(DateTimeInterface::class, $o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertTrue($o->isExpired());
        $this->assertEquals(-100, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->matchScopes('read'));
        $this->assertFalse($o->isValid('read'));
    }

    public function testHidrate()
    {
        $o = AccessToken::hydrate([
            'token' => 'token_bin2hex',
            'owner' => null,
            'client' => null,
            'scopes' => ['read'],
            'expires_at' => null,
        ]);
        $this->assertInstanceOf(AccessToken::class, $o);

        $this->assertNull($o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(0, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->matchScopes('read'));
        $this->assertTrue($o->isValid('read'));
        $this->assertFalse($o->isValid('write'));
    }
}
