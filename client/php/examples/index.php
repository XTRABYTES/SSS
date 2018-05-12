<?php

require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../lib/DICOM/Client.php';

const HOST = '172.16.144.132';
const PORT = 8080;

$client = new DICOM\Client(HOST, PORT);
$client->connect();

$res = $client->CreateUser('danny', 'foobarbaz');
var_dump($res);

$res = $client->CheckUsername('danny');
var_dump($res);

$res = $client->CheckUser('danny', 'foobarbaz');
var_dump($res);
