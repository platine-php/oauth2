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


namespace Platine\Stdlib\Helper;
$mock_random_int = false;

function random_int(int $min, int $max)
{
    global $mock_random_int;
    if ($mock_random_int) {
        return 0;
    } else {
        return \random_int($min, $max);
    }
}
