<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Entity;

use DateTimeInterface;
use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\RefreshToken;

/**
 * RefreshToken class tests
 *
 * @group core
 * @group oauth2
 */
class RefreshTokenTest extends PlatineTestCase
{
    public function testCreateRefreshTokenDefault()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = RefreshToken::createNewRefreshToken(3600, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(RefreshToken::class, $o);

        $this->assertInstanceOf(DateTimeInterface::class, $o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(3600, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->isValid('read'));
    }

    public function testCreateRefreshTokenTtlZero()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = RefreshToken::createNewRefreshToken(0, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(RefreshToken::class, $o);

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

    public function testCreateRefreshTokenExpired()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = RefreshToken::createNewRefreshToken(0, $owner = null, $client = null, ['read']);
        $this->assertInstanceOf(RefreshToken::class, $o);

        $this->assertNull($o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(0, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->matchScopes('read'));
        $this->assertTrue($o->isValid('read'));
    }

    public function testHidrate()
    {
        $o = RefreshToken::hydrate([
            'token' => 'token_bin2hex',
            'owner' => null,
            'client' => null,
            'scopes' => ['read'],
            'expires_at' => null,
        ]);
        $this->assertInstanceOf(RefreshToken::class, $o);

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
