<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Entity\Client;
use Platine\OAuth2\Entity\Scope;

/**
 * Scope class tests
 *
 * @group core
 * @group oauth2
 */
class ScopeTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $o = Scope::createNewScope(1, 'read', 'read all', false);
        $this->assertInstanceOf(Scope::class, $o);

        $this->assertFalse($o->isDefault());
        $this->assertEquals(1, $o->getId());
        $this->assertEquals('read', $o->getName());
        $this->assertEquals('read', $o->__toString());
        $this->assertEquals('read all', $o->getDescription());
    }

    public function testHydrate()
    {
        $o = Scope::hydrate([
            'id' => 2,
            'name' => 'read',
            'description' => 'read all',
            'is_default' => true,
        ]);
        $this->assertInstanceOf(Scope::class, $o);

        $this->assertTrue($o->isDefault());
        $this->assertEquals(2, $o->getId());
        $this->assertEquals('read', $o->getName());
        $this->assertEquals('read', $o->__toString());
        $this->assertEquals('read all', $o->getDescription());
    }
}
