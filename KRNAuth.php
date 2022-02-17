<?php

namespace KRN;

use \Firebase\JWT\JWT;
use HttpSignatures\Context;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;


class KRNAuth {
    private $partner;

    public function __construct($partner) {
        $this->partner = (object) $partner;
        $this->trinity_base_url = getenv('KRN_HOST_PREFIX') ? 'http://' . getenv('KRN_HOST_PREFIX') . 'trinity.krn.krone.at' : 'https://trinity.krone.at';
        $this->err_invalid_token = (object)["error" => 'Invalid Token'];
    }

    public function sendRequest(string $method = null, string $path = null, array $headers = [], string $body = null) {
        $method = ($method == null ? "GET" : $method);
        $path = ($path == null ? "" : $path);
        $body = ($body == null ? "" : $body) ;


        $headers["user-agent"] = "KRN-API Trinity";

        $url = $this->trinity_base_url . $path;
        $req = new Request($method, $url, $headers, $body);

        // PRESIGN SETUP
        $req = $req->withHeader("krn-partner-key", $this->partner->rest_key);
        $req = $req->withHeader("KRN-SIGN-URL", $url);

        // SIGN WITH RSA KEY
        $req = $this->signRequest($req); // Sign

        // SEND REQ
        $client = new \GuzzleHttp\Client();
        $resp = $client->send($req); // SEND

        // RETURN PSR7 Response
        return $resp;
    }

    public function signRequest(Request $request) {
        $context = new \HttpSignatures\Context([
        'keys' => ['mykey' => $this->partner->rsa_key],
        'algorithm' => 'rsa-sha256',
        'headers' => ["(request-target)", "krn-partner-key", "KRN-SIGN-URL", "Date"],
        ]);

        $request = $request->withHeader("krn-partner-key", $this->partner->rest_key);
        $request = $request->withHeader("Date", time());

        $request =  $context->signer()->sign($request);

        return $request;
    }


    public function validate($token) {
        $self = $this;

        if(substr($token, 0, strlen($this->partner->name)) !== $this->partner->name) {
            return (object) $this->err_invalid_token;
        }

        // remove partner prefix
        $jwt = explode(':', $token)[1];

        // decode and validate token
        // https://github.com/firebase/php-jwt#example
        try {
            $decoded = JWT::decode($jwt, $this->partner->hmac_secret, array('HS256'));
        } catch(\Exception $ex) {
            return (object) $this->err_invalid_token;
        }

        // decrypt payload
        $payload = $this->aesDecrypt($decoded->payload, $this->partner->crypt_key);
        return json_decode($payload);
    }

    public function deepValidate($token) {


        $curl = curl_init($this->trinity_base_url . '/deep-validate?token='  . $token);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);

        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
        ));

        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode([     ]));

        $response = curl_exec($curl);
        $response = json_decode($response);
        curl_close($curl);

        if(!is_null($response) && !is_null($response->data) && !isset($response->errors)) {
            return $response;
        }

        return (object) $this->err_invalid_token;
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
