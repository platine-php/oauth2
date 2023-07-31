<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Response;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Response\RedirectResponse;

/**
 * RedirectResponse class tests
 *
 * @group core
 * @group oauth2
 */
class RedirectResponseTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $o = new RedirectResponse('http://localhost');
        $this->assertInstanceOf(RedirectResponse::class, $o);

        $this->assertEquals(302, $o->getStatusCode());
        $this->assertEquals('http://localhost', $o->getHeaderLine('location'));
    }
}
