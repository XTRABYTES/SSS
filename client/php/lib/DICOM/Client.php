<?php

namespace DICOM;

use \Teapot\StatusCode;

class Client
{
    const VERSION = '1.0';
    const HASHING_ALGORITHM = OPENSSL_ALGO_SHA256;

    protected $endpoint;
    protected $client;
    protected $version;
    protected $privateKey;
    protected $publicKey;
    protected $serverPublicKey;
    protected $sessionId;

    public function __construct(string $host, int $port, string $version = self::VERSION) {
        $this->version = $version;
        $this->endpoint = sprintf('https://%s:%d/v%s/dicom', $host, $port, $version);

        $key = openssl_pkey_new();
        openssl_pkey_export($key, $this->privateKey);
        $this->publicKey = openssl_pkey_get_details($key)['key'];

        openssl_free_key($key);

        $this->client = new \GuzzleHttp\Client([
            // TODO: Fixup once SSS isn't using a self-signed cert
            'verify' => false,
        ]);
    }

    public function connect() {
        $res = $this->execute([
            'method' => 'connect',
            'pubkey' => $this->publicKey,
        ]);

        return $res;
    }

    public function ping()
    {
        return $this->execute([
            'method' => 'ping',
        ]);
    }

    public function echo(string $str)
    {
        return $this->execute([
            'method' => 'echo',
            'params' => $str,
        ]);
    }

    public function CheckUsername(string $username)
    {
        return $this->execute([
            'method' => 'CheckUsername',
            'username' => $username,
        ]);
    }

    public function CreateUser(string $username, string $password)
    {
        return $this->execute([
            'method' => 'CreateUser',
            'username' => $username,
            'password' => $password,
        ]);
    }

    public function CheckUser(string $username, string $password)
    {
        return $this->execute([
            'method' => 'CheckUser',
            'username' => $username,
            'password' => $password,
        ]);
    }

    protected function execute(array $params)
    {
        if ($this->sessionId) {
            $params['session_id'] = $this->sessionId;
        }

        $payload = json_encode($params);
        openssl_sign($payload, $signature, $this->privateKey, self::HASHING_ALGORITHM);
        $pemSignature = implode("\n", str_split(base64_encode($signature), 64));

        $request = [
            'dicom' => $this->version,
            'payload' => $payload,
            'signature' => $pemSignature,
            'pubkey' => $this->publicKey,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];

        $data = json_encode($request);

        $res = $this->client->request('POST', $this->endpoint, [
            'headers' => $headers,
            'body' => $data,
        ]);

        $responseData = json_decode($res->getBody());
        $this->verifySignature($responseData);

        return json_decode($responseData->payload);
    }

    protected function verifySignature(\stdClass $data)
    {
        // TODO: ensure fields exist

        $payload = json_decode($data->payload);
        $signature = $data->signature;

        if ($payload->method === 'connect') {
            $this->serverPublicKey = $payload->pubkey;
            $this->sessionId = $payload->session_id;
        }

        $isValid = (openssl_verify($data->payload, base64_decode($signature), $this->serverPublicKey, self::HASHING_ALGORITHM) === 1);

        if (!$isValid) {
            throw new \Exception("Invalid payload signature");
        }
    }
}
