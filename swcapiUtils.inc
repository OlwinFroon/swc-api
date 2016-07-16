<?php //////////////////////////////////////////////////////////////////////////
// custom/api/swcapiUtils.inc: Technical layer for the SWC API
// TFMS (c) 2016 Olwin Froon, Trade Federation
////////////////////////////////////////////////////////////////////////////////
// of 160716: revokeAccess
// of 160715: minor fix
// of 160714: initial spin-off
////////////////////////////////////////////////////////////////////////////////


// CONSTANTS TO BE SET BY YOUR CLIENT:
// define('API_CLIENTID',        '[your client ID as per SWC settings]');
// define('API_CLIENTSECRET',    '[your client secret as per SWC settings]');
// define('API_CLIENTINTERFACE', '[your callback URI]');



define('API_PATH_AUTHORIZE', 'http://www.swcombine.com/ws/oauth2/auth/');
define('API_PATH_REQUEST',   'http://www.swcombine.com/ws/v1.0/');
define('API_PATH_REVOKE',    'http://www.swcombine.com/ws/oauth2/revoke/');
define('API_PATH_TOKEN',     'http://www.swcombine.com/ws/oauth2/token/');
define('API_TIMEOFFSET',     912668400);



class swcapi implements swcapiInterface {
  protected static $errorCode;
  protected static $errorText;



  public static function getError($clear = FALSE) {
    // Returns a string describing the nature of the recent error,
    // an empty string if nothing went wrong.
    //
    // $clear (optional): TRUE will reset the error marker afterwards.
    // If omitted, $clear defaults to FALSE.

    $ret = '';
    if (self::hasError()) $ret = self::$errorCode . ': ' . self::$errorText;
    if ($clear) self::clearError();
    return $ret;
  }



  public static function getErrorCode() {
    // Returns a numerical error code if something went wrong, a zero otherwise.

    $ret = 0;
    if (self::hasError()) $ret = self::$errorCode;
    return $ret;
  }



  public static function hasError() {
    // Returns TRUE if the recent API operation caused an error.

    $ret = FALSE;
    if (isset(self::$errorCode)) $ret = (self::$errorCode !== 0);
    return $ret;
  }



  public static function authorize(array $permissions, $state = 'auth', $accessmode = 'offline') {
    // Tries to authorize a set of API permissions for the currently logged-in character.
    // Returns TRUE if the attempt was successful, FALSE otherwise.
    //
    // $permissions (string array): the API permissions ('character_read',
    // 'character_stats', ...) your application wishes to be granted by the user.
    // An empty array will cause the API to clear all current permissions on SWC's
    // side.
    //
    // $state (optional): a marker to recognize which part of your application sent
    // this request.
    // If omitted, $state defaults to 'auth'.
    //
    // $accessmode (optional):
    // - 'online' = one time permission, expires with the access token
    // - 'offline' = permission will persist, access token can be refreshed
    // If omitted, $accessmode defaults to 'offline'.
    //
    // CAVEAT: currently, the $permissions array can't be empty. If you wish to
    // disable API access for your user, request a single pointless permission
    // (e.g. 'character_stats' which wouldn't work without 'character_read').

    $data = array(
      'client_id'     => API_CLIENTID,
      'response_type' => 'code',
      'redirect_uri'  => API_CLIENTINTERFACE,
      'scope'         => implode(' ', $permissions),
      'state'         => $state,
      'access_type'   => $accessmode,
    );

    $uri = API_PATH_AUTHORIZE . '?' . http_build_query($data, '', '&');

    // redirects to SWC's authorization consent screen
    header('location: ' . $uri);
    header('accept: application/json');

    // SWC's consent screen calls your API_CLIENTINTERFACE with parameters
    // state (always): the same one you sent
    // code (optional): authorization code for requesting an access token
    // error (optional): error code
  }



  public static function requestAccessToken($authcode, $accessmode = 'offline') {
    // Tries to request an access token after successful authorization.
    // Returns an array with access token, refresh token, scope and unix expiration
    // timestamp if everything went well, FALSE otherwise.
    //
    // $authcode: what was sent as "code" via the SWC consent screen
    //
    // $accessmode:
    // - 'online' = one time permission, expires with the access token
    // - 'offline' = permission will persist, access token can be refreshed
    // If omitted, accessmode defaults to 'offline'.

    self::clearError();

    $data = array (
      'code'          => $authcode,
      'redirect_uri'  => API_CLIENTINTERFACE,
      'grant_type'    => 'authorization_code',
      'access_type'   => $accessmode,
      'client_id'     => API_CLIENTID,
      'client_secret' => API_CLIENTSECRET,
    );

    $response = self::apiRequest(API_PATH_TOKEN, $data, 'POST', 'JSON');

    // the request itself might've failed
    // a proper error message should already be in place
    if ($response === FALSE) return FALSE;

    // apparently not, so decode it
    $result = (object) json_decode($response);

    // the request worked, but something else was wrong
    if (isset($result->error)) return self::setError(990, 'swcapi::requestAccessToken: ' . $result->error);

    $ret['accesstoken']  = (isset($result->access_token)  ? $result->access_token        : '');
    $ret['refreshtoken'] = (isset($result->refresh_token) ? $result->refresh_token       : '');
    $ret['scope']        = (isset($result->scope)         ? $result->scope               : '');
    $ret['expires']      = (isset($result->expires_in)    ? time() + $result->expires_in : 0);
    return $ret;
  }



  public static function revokeAccess($refreshtoken = '') {
    // Tries to revoke the current access token.
    // Returns TRUE if everything went well, FALSE otherwise.
    //
    // $refreshtoken: the user's current refresh token.
    //
    // Obviously, this won't work in online access mode, since there won't be a refresh
    // token.
    //
    // CAVEAT: currently, this will remove ALL access tokens for your application,
    // not just the one for the single user owning that refresh token.
    // After next sync, this will most probably work properly.

    if ('' == $refreshtoken) return self::setError(810, 'swcapi::revokeAccess: refresh token is empty');

    $data = array(
      'client_id' => API_CLIENTID,
      'token'     => $refreshtoken,
    );

    $response = self::apiRequest(API_PATH_REVOKE, $data, 'POST', 'HTML');

    // the request itself might've failed
    // a proper error message should already be in place
    if ($response === FALSE) return FALSE;

    return TRUE;
  }



  //////////////////////////////////////////////////////////////////////////////



  protected static function apiRequest($path, $data, $method, $responseformat) {
    $uri = $path;

    // only accepting JSON and XML output formats ATM
    if ($responseformat == 'JSON') {
      $resultType = 'application/json';
    } elseif ($responseformat == 'XML') {
      $resultType = 'application/xml';
    } elseif ($responseformat == 'HTML') {
      $resultType = 'text/html';
    } else {
      return self::setError(801, 'swcapi::apiRequest: Invalid response format [' . $responseformat . ']');
    }
    $head = array('accept: ' . $resultType);
    $body = http_build_query($data, '', '&');

    // only accepting POST and GET methods ATM
    if ($method == 'POST') {
      $head[] = 'content-type: application/x-www-form-urlencoded';
      $head[] = 'content-length: ' . strlen($body);
    } elseif ($method == 'GET') {
      if ($body <> '') $uri .= '?' . $body;
      $head[] = 'content-type: utf-8; charset=utf-8';
    } else {
      return self::setError(802, 'swcapi::apiRequest: Invalid send method [' . $method . ']');
    }

    // set up curl request 
    set_time_limit(300);
    $curl = curl_init();
    if ($method == 'POST') {
      curl_setopt($curl, CURLOPT_POST, TRUE);
      curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
    }
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
    curl_setopt($curl, CURLOPT_HEADER, TRUE);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $head);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
    // 200 seconds for a response seems awfully long, but sometimes it DOES take that long
    curl_setopt($curl, CURLOPT_TIMEOUT, 200);
    curl_setopt($curl, CURLOPT_URL, $uri);
    curl_setopt($curl, CURLOPT_VERBOSE, TRUE);

    // execute the curl request
    $response        = curl_exec($curl);

    // chop up the response into header ...
    $headerSize      = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    $curlHeader      = substr($response, 0, $headerSize);
    // ... and content
    $curlContent     = substr($response, $headerSize);
    // if the content part is empty, substr returns FALSE
    if ($curlContent === FALSE) $curlContent = '';
    $curlInfo        = curl_getinfo($curl);
    curl_close($curl);
    // sometimes there's no response at all, which we'll handle as a fictional response code -1
    $curlHttpCode    = (isset($curlInfo['http_code'])    ? $curlInfo['http_code']    : -1);
    // sometimes there's no response content type, either
    $curlContentType = (isset($curlInfo['content_type']) ? $curlInfo['content_type'] : 'n/a');


    // translate HTTP result codes into clear text error messages for your convenience
    if ($curlHttpCode == -1) {
      return self::setError(901, 'swcapi::apiRequest: curl_exec failed');
    } elseif ($curlHttpCode == 0) {
      return self::setError(902, 'swcapi::apiRequest: SWC server failed to respond');
    } elseif ($curlHttpCode == 200) {
      // theoretically, all is well at this point, except...
      if ($curlContentType !== $resultType) {
        return self::setError(903, 'swcapi::apiRequest: unexpected response content type [' . $curlContentType . ']');
      }
    } elseif ($curlHttpCode == 400) {
      return self::setError(400, 'swcapi::apiRequest: Bad request (invalid parameters)');
    } elseif ($curlHttpCode == 401) {
      return self::setError(401, 'swcapi::apiRequest: Unauthorized (lack of permissions)');
    } elseif ($curlHttpCode == 403) {
      return self::setError(403, 'swcapi::apiRequest: Forbidden (lack of permissions)');
    } elseif ($curlHttpCode == 404) {
      return self::setError(404, 'swcapi::apiRequest: Not found (or lack of authorization)');
    } elseif ($curlHttpCode == 500) {
      return self::setError(500, 'swcapi::apiRequest: Server error (bug in SWC API)');
    } else {
      return self::setError($curlHttpCode, 'swcapi::apiRequest: HTTP ' . $curlHttpCode . ' (unknown error)');
    }
    return $curlContent;
  }



  protected static function clearError() {
    self::$errorCode = 0;
    self::$errorText = '';
  }



  protected static function setError($code, $text) {
    self::$errorCode = $code;
    self::$errorText = $text;
    return FALSE;
  }
}
