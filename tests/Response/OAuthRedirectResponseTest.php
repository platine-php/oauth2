<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Response;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Response\OAuthRedirectResponse;

/**
 * OAuthRedirectResponse class tests
 *
 * @group core
 * @group oauth2
 */
class OAuthRedirectResponseTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $o = new OAuthRedirectResponse('http://localhost');
        $this->assertInstanceOf(OAuthRedirectResponse::class, $o);

        $this->assertEquals(302, $o->getStatusCode());
        $this->assertEquals('http://localhost', $o->getHeaderLine('location'));
    }
}
