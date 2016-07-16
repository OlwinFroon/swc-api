<?php //////////////////////////////////////////////////////////////////////////
// mycallback.php:
// SWC API callback handler
////////////////////////////////////////////////////////////////////////////////

header('Content-Type: text/html; charset=UTF-8');
session_start();

// process parameters
$error = filter_input(INPUT_POST, 'error', FILTER_SANITIZE_STRING);
$state = filter_input(INPUT_POST, 'state', FILTER_SANITIZE_STRING);
$code  = filter_input(INPUT_POST, 'code',  FILTER_SANITIZE_STRING);


if ('auth' !== $state) {
  die('invalid state [' . $state . ']');
}

if ('' !== $error) {
  die('authorization failed [' . $error . ']');
}

if ('' == $code) {
  die('authorization did not return an authorization code');
} 

$response = swcapi::requestAccessToken($code);

if ($response === FALSE) {
  die('request access token failed [' . swcapi::getError() . ']');
}

// everything went well, you received the credentials for the current SWC user:
$accessToken  = $response['accesstoken'];
$refreshToken = $response['refreshtoken'];
$expiresAt    = $response['expires'];
$scope        = $response['scope'];

// store them in your database for further use

