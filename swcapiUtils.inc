<?php //////////////////////////////////////////////////////////////////////////
// custom/api/swcapiUtils.inc: Technical layer for the SWC API
// TFMS (c) 2016 Olwin Froon, Trade Federation
////////////////////////////////////////////////////////////////////////////////
// of 160715: minor fix
// of 160714: initial spin-off
////////////////////////////////////////////////////////////////////////////////


// CONSTANTS TO BE SET BY YOUR CLIENT:
// define('API_CLIENTID',        '[your client ID as per SWC settings]');
// define('API_CLIENTSECRET',    '[your client secret as per SWC settings]');
// define('API_CLIENTINTERFACE', '[your callback URI]');




define('API_PATH_AUTHORIZE',    'http://www.swcombine.com/ws/oauth2/auth/');
define('API_PATH_REQUEST',      'http://www.swcombine.com/ws/v1.0/');
define('API_PATH_TOKEN',        'http://www.swcombine.com/ws/oauth2/token/');
define('API_TIMEOFFSET',         912668400);







class swcapi implements swcapiInterface {
  protected static $errorCode;
  protected static $errorText;



  public static function getError($clear = FALSE) {
    $ret = '';
    if (self::hasError()) $ret = self::$errorCode . ': ' . self::$errorText;
    if ($clear) self::clearError();
    return $ret;
  }



  public static function getErrorCode() {
    $ret = 0;
    if (self::hasError()) $ret = self::$errorCode;
    return $ret;
  }



  public static function hasError() {
    $ret = FALSE;
    if (isset(self::$errorCode)) $ret = (self::$errorCode !== 0);
    return $ret;
  }



  public static function init() {
    // dummy function to have the class loaded at all, will disappear as soon as possible
  }



  // try and authorize a set of API permissions for the character currently logged in 
  public static function authorize(array $permissions, $state = 'auth', $accessmode = 'offline') {
    // $permissions: array of valid API permissions (like character_read, character_stats etc)
    // $state: marker to recognize which part of your application sent this
    // $accessmode:
    // - 'online' = one time permission, expires with the access token
    // - 'offline' = permission will persist, access token can be refreshed
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



  // Request an access token after successful authorization
	public static function requestAccessToken($authcode, $accessmode = 'offline') {
    // $authcode: what was sent as "code" via the SWC consent screen
    // $accessmode:
    // - 'online' = one time permission, expires with the access token
    // - 'offline' = permission will persist, access token can be refreshed
    // returns an array with access token, refresh token (if applicable), scope
    // and unix expiration timestamp if everything went well, FALSE otherwise

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
		if (isset($result->error)) return self::setError(990, 'requestAccessToken: ' . $result->error);

    $ret['accesstoken']  = (isset($result->access_token)  ? $result->access_token        : '');
    $ret['refreshtoken'] = (isset($result->refresh_token) ? $result->refresh_token       : '');
    $ret['scope']        = (isset($result->scope)         ? $result->scope               : '');
    $ret['expires']      = (isset($result->expires_in)    ? time() + $result->expires_in : 0);
    return $ret;
  }



  //////////////////////////////////////////////////////////////////////////////



  protected static function apiRequest($path, $data, $method, $responseformat) {
    $uri = $path;

    // only accepting JSON and XML output formats ATM
    if ($responseformat == 'JSON') {
      $resultType = 'application/json';
    } elseif ($responseformat == 'XML') {
      $resultType = 'application/xml';
    } else {
      return self::setError(801, 'apiRequest: Invalid response format [' . $responseformat . ']');
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
      return self::setError(802, 'apiRequest: Invalid send method [' . $method . ']');
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

    // you might think that 200 seconds for a response seems awfully long,
    // but sometimes it DOES take that long
   	curl_setopt($curl, CURLOPT_TIMEOUT, 200);
   	curl_setopt($curl, CURLOPT_URL, $uri);
   	curl_setopt($curl, CURLOPT_VERBOSE, TRUE);

    // execute the curl request
  	$response    = curl_exec($curl);

    // chop up the response into header ...
    $headerSize  = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    $curlHeader  = substr($response, 0, $headerSize);

    // ... and content
    $curlContent = substr($response, $headerSize);
 		$curlInfo    = curl_getinfo($curl);
 		curl_close($curl);

    // sometimes there's no response at all, which we'll handle as a fictional response code -1
    $curlHttpCode    = (isset($curlInfo['http_code'])    ? $curlInfo['http_code']    : -1);

    // sometimes there's no response content type, either
    $curlContentType = (isset($curlInfo['content_type']) ? $curlInfo['content_type'] : 'n/a');

    // translate HTTP result codes into clear text for your convenience
    if ($curlHttpCode == -1) {
      return self::setError(901, 'apiRequest: curl_exec failed');
    } elseif ($curlHttpCode == 0) {
      return self::setError(902, 'apiRequest: SWC server failed to respond');
    } elseif ($curlHttpCode == 200) {
      if ($curlContentType !== $resultType) {
        return self::setError(903, 'apiRequest: unexpected response content type [' . $curlContentType . ']');
      } else {
        // all is well, let's break out of this thing
      }
    } elseif ($curlHttpCode == 400) {
      return self::setError(400, 'apiRequest: Bad request (invalid parameters)');
    } elseif ($curlHttpCode == 401) {
      return self::setError(401, 'apiRequest: Unauthorized (lack of permissions)');
    } elseif ($curlHttpCode == 403) {
      return self::setError(403, 'apiRequest: Forbidden (lack of permissions)');
    } elseif ($curlHttpCode == 404) {
      return self::setError(404, 'apiRequest: Not found (or lack of authorization)');
    } elseif ($curlHttpCode == 500) {
      return self::setError(500, 'apiRequest: Server error (bug in SWC API)');
    } else {
      return self::setError($curlHttpCode, 'apiRequest: HTTP ' . $curlHttpCode . ' (unknown error)');
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
