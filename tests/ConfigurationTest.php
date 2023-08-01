<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test;

use InvalidArgumentException;
use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Configuration;

/**
 * Configuration class tests
 *
 * @group core
 * @group oauth2
 */
class ConfigurationTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $cfg = new Configuration([]);
        $this->assertInstanceOf(Configuration::class, $cfg);
    }

    public function testGetNotFound()
    {
        $this->expectException(InvalidArgumentException::class);
        $cfg = new Configuration([]);
        $cfg->get('not_found_config');
    }

    public function testGetDefaultValuesSuccess()
    {
        $cfg = new Configuration([]);
        $this->assertEquals(120, $cfg->get('ttl.authorization_code'));
        $this->assertEquals(120, $cfg->getAuthorizationCodeTtl());
        $this->assertEquals(3600, $cfg->getAccessTokenTtl());
        $this->assertEquals(86400, $cfg->getRefreshTokenTtl());
        $this->assertFalse($cfg->isRotateRefreshToken());
        $this->assertTrue($cfg->isRevokeRotatedRefreshToken());
        $this->assertCount(0, $cfg->getGrants());
    }

    public function testGetValuesSuccess()
    {
        $cfg = new Configuration(['grants' => ['foo', 'bar'], 'rotate_refresh_token' => true]);
        $this->assertEquals(120, $cfg->get('ttl.authorization_code'));
        $this->assertEquals(120, $cfg->getAuthorizationCodeTtl());
        $this->assertEquals(3600, $cfg->getAccessTokenTtl());
        $this->assertEquals(86400, $cfg->getRefreshTokenTtl());
        $this->assertTrue($cfg->isRotateRefreshToken());
        $this->assertTrue($cfg->isRevokeRotatedRefreshToken());
        $this->assertCount(2, $cfg->getGrants());
    }
}
