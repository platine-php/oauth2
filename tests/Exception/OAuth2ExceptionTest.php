<?php

declare(strict_types=1);

namespace Platine\OAuth2\Test\Exception;

use Platine\Dev\PlatineTestCase;
use Platine\OAuth2\Exception\InvalidAccessTokenException;
use Platine\OAuth2\Exception\OAuth2Exception;

/**
 * OAuth2Exception class tests
 *
 * @group core
 * @group oauth2
 */
class OAuth2ExceptionTest extends PlatineTestCase
{
    public function testConstructor()
    {
        $o = new OAuth2Exception('foo', 'bar');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('foo', $o->getMessage());
        $this->assertEquals('bar', $o->getCode());
    }

    public function testAccessDenied()
    {
        $o = OAuth2Exception::accessDenied('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('access_denied', $o->getCode());
    }

    public function testInvalidRequest()
    {
        $o = OAuth2Exception::invalidRequest('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('invalid_request', $o->getCode());
    }

    public function testInvalidClient()
    {
        $o = OAuth2Exception::invalidClient('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('invalid_client', $o->getCode());
    }

    public function testInvalidGrant()
    {
        $o = OAuth2Exception::invalidGrant('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('invalid_grant', $o->getCode());
    }

    public function testInvalidScope()
    {
        $o = OAuth2Exception::invalidScope('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('invalid_scope', $o->getCode());
    }

    public function testServerError()
    {
        $o = OAuth2Exception::serverError('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('server_error', $o->getCode());
    }

    public function testTemporarilyUnavailable()
    {
        $o = OAuth2Exception::temporarilyUnavailable('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('temporarily_unavailable', $o->getCode());
    }

    public function testUnauthorizedClient()
    {
        $o = OAuth2Exception::unauthorizedClient('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('unauthorized_client', $o->getCode());
    }

    public function testUnsupportedGrantType()
    {
        $o = OAuth2Exception::unsupportedGrantType('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('unsupported_grant_type', $o->getCode());
    }

    public function testUnsupportedResponseType()
    {
        $o = OAuth2Exception::unsupportedResponseType('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('unsupported_response_type', $o->getCode());
    }

    public function testUnsupportedTokenType()
    {
        $o = OAuth2Exception::unsupportedTokenType('error description');
        $this->assertInstanceOf(OAuth2Exception::class, $o);

        $this->assertEquals('error description', $o->getMessage());
        $this->assertEquals('unsupported_token_type', $o->getCode());
    }
}
