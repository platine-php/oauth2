<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Exception;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Exception\InvalidAccessTokenException;

/**
 * InvalidAccessTokenException class tests
 *
 * @group core
 * @group oauth2
 */
class InvalidAccessTokenExceptionTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $o = new InvalidAccessTokenException('foo', 'bar');
        $this->assertInstanceOf(InvalidAccessTokenException::class, $o);

        $this->assertEquals('foo', $o->getMessage());
        $this->assertEquals('bar', $o->getCode());
    }

    public function testInvalidToken()
    {
        $o = InvalidAccessTokenException::invalidToken('error description');
        $this->assertInstanceOf(InvalidAccessTokenException::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('invalid_token', $o->getCode());
    }
}
