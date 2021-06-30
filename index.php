<?php
include_once 'vendor/autoload.php';

$data = [
    'name'=>'long',
    'age'=>18
];
$token = \Longxinhong\JwtToken\Jwt::init()->getToken($data);
var_dump($token);

var_dump(\Longxinhong\JwtToken\Jwt::init()->verifyToken($token. '123123123123'));