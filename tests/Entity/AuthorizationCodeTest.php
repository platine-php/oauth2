<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Entity;

use DateTimeInterface;
use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\AuthorizationCode;

/**
 * AuthorizationCode class tests
 *
 * @group core
 * @group oauth2
 */
class AuthorizationCodeTest extends PlatineTestCase
{
    public function testCreateAccessTokenDefault()
    {
        global $mock_bin2hex;

        $mock_bin2hex = true;

        $o = AuthorizationCode::createNewAuthorizationCode(
            3600,
            $redirectUri = null,
            $owner = null,
            $client = null,
            ['read']
        );
        $this->assertInstanceOf(AuthorizationCode::class, $o);

        $this->assertInstanceOf(DateTimeInterface::class, $o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertFalse($o->isExpired());
        $this->assertEquals(3600, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->isValid('read'));
    }



    public function testHidrate()
    {
        $o = AuthorizationCode::hydrate([
            'token' => 'token_bin2hex',
            'owner' => null,
            'client' => null,
            'scopes' => ['read'],
            'expires_at' => null,
            'redirect_uri' => 'http://localhost',
        ]);
        $this->assertInstanceOf(AuthorizationCode::class, $o);

        $this->assertNull($o->getExpireAt());
        $this->assertNull($o->getOwner());
        $this->assertNull($o->getClient());
        $this->assertTrue($o->isExpired());
        $this->assertEquals(0, $o->getExpiresIn());
        $this->assertEquals('token_bin2hex', $o->getToken());
        $this->assertEquals('http://localhost', $o->getRedirectUri());
        $this->assertCount(1, $o->getScopes());
        $this->assertTrue($o->matchScopes('read'));
        $this->assertFalse($o->isValid('read'));
        $this->assertFalse($o->isValid('write'));
    }
}
