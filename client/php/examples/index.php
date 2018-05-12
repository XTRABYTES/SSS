<?php

require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../lib/DICOM/Client.php';

const HOST = 'sss.xtrabytes.services';
const PORT = 8443;

$client = new DICOM\Client(HOST, PORT);
$client->connect();

$res = $client->CreateUser('danny', 'foobarbaz');
var_dump($res);

$res = $client->CheckUsername('danny');
var_dump($res);

$res = $client->CheckUser('danny', 'foobarbaz');
var_dump($res);
