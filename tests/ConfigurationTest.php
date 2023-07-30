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

    public function testGetSuccess()
    {
        $cfg = new Configuration(['ttl' => ['authorization_code' => 120]]);
        $this->assertEquals(120, $cfg->get('ttl.authorization_code'));
    }
}
