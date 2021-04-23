<?php
require __DIR__ . '/vendor/autoload.php';

use \KRN\KRNAuth;

// enter your partner-settings
$auth = new KRNAuth([
    'name' => '',
    'crypt_key' => '',
    'hmac_secret' => '',
    'rest_key' => '',
    'rsa_key' => '',
]);

var_dump(
    $auth->validate($argv[1])
);

var_dump(
    $auth->deepValidate($argv[1])
);

$r = $auth->sendRequest("GET", "/KRN/signing_test");
var_dump($r->getBody()->__toString());
// use: php example.php <PASSPORT>
