<?php

namespace KRN;

use \Firebase\JWT\JWT;

// internal vs external use
define('TRINITY_BASE_URL', getenv('KRN_HOST_PREFIX') ? 'http://' . getenv('KRN_HOST_PREFIX') . 'trinity.krn.krone.at' : 'https://trinity.krone.at');

class KRNAuth {
    static $ERR_INVALID_TOKEN = [ 'error' => 'Invalid Token' ];
    private $partner;

    public function __construct($partner) {
        $this->partner = (object) $partner;
    }

    public function validate($token) {
        $self = $this;

        if(substr($token, 0, strlen($this->partner->name)) !== $this->partner->name) {
            return $self::$ERR_INVALID_TOKEN;
        }

        // remove partner prefix
        $jwt = explode(':', $token)[1];

        // decode and validate token
        // https://github.com/firebase/php-jwt#example
        try {
            $decoded = JWT::decode($jwt, $this->partner->hmac_secret, array('HS256'));
        } catch(\Exception $ex) {
            return $self::$ERR_INVALID_TOKEN;
        }

        // decrypt payload
        $payload = $this->aesDecrypt($decoded->payload, $this->partner->crypt_key);
        return json_decode($payload);
    }

    public function deepValidate($token) {
        $self = $this;

        $RENEW_QUERY = '
            mutation doRenew($passport: String!) {
                renew(passport: $passport) {
                    Message
                    Renewed
                    PassPort
                    Expires
                    Error
                    DecodedToken {
                        Email,
                        ID,
                        IntID,
                        NickName
                    }
                }
            }
        ';

        $curl = curl_init(TRINITY_BASE_URL . '/graphql');
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);

        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
        ));

        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode([
            'operationName' => 'doRenew',
            'query' => $RENEW_QUERY,
            'variables' => [
                'passport' => $token
            ]
        ]));

        $response = curl_exec($curl);
        $response = json_decode($response);
        curl_close($curl);

        if(!is_null($response) && !is_null($response->data) && !isset($response->errors)) {
            return $response->data->renew->DecodedToken;
        }

        return $self::$ERR_INVALID_TOKEN;
    }

    private function aesDecrypt($ciphered, $password) {
        $method = 'aes-256-cbc';
        $ivSize = openssl_cipher_iv_length($method);
        $data = base64_decode($ciphered);
        $ivData = substr($data, 0, $ivSize);
        $encData = substr($data, $ivSize);
        $output = openssl_decrypt(
            $encData,
            $method,
            $password,
            OPENSSL_RAW_DATA,
            $ivData
        );
        return $output;
    }
}
