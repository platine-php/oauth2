<?php

declare(strict_types=1);

namespace Platine\OAuth2\Entity;

$mock_bin2hex = false;



function bin2hex(string $str)
{
    global $mock_bin2hex;
    if ($mock_bin2hex) {
        return 'token_bin2hex';
    } else {
        return \bin2hex($str);
    }
}
