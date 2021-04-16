<?php
require __DIR__ . '/vendor/autoload.php';

use \KRN\KRNAuth;

// enter your partner-settings
$auth = new KRNAuth([
    'name' => '',
    'crypt_key' => '',
    'hmac_secret' => ''
]);

var_dump(
    $auth->validate($argv[1])
);

var_dump(
    $auth->deepValidate($argv[1])
);

// use: php example.php <PASSPORT>
