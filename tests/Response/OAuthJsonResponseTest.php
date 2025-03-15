<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Response;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Response\OAuthJsonResponse;

/**
 * OAuthJsonResponse class tests
 *
 * @group core
 * @group oauth2
 */
class OAuthJsonResponseTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $o = new OAuthJsonResponse(['foo' => 'bar']);
        $this->assertInstanceOf(OAuthJsonResponse::class, $o);

        $this->assertEquals(200, $o->getStatusCode());
        $this->assertEquals('application/json', $o->getHeaderLine('content-type'));
    }
}
