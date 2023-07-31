<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Response;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Response\JsonResponse;

/**
 * JsonResponse class tests
 *
 * @group core
 * @group oauth2
 */
class JsonResponseTest extends PlatineTestCase
{
    public function testCreateDefault()
    {
        $o = new JsonResponse(['foo' => 'bar']);
        $this->assertInstanceOf(JsonResponse::class, $o);

        $this->assertEquals(200, $o->getStatusCode());
        $this->assertEquals('application/json', $o->getHeaderLine('content-type'));
    }
}
