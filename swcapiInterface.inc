<?php //////////////////////////////////////////////////////////////////////////
// custom/api/swcapiInterface.inc: Technical layer for the SWC API
// TFMS (c) 2016 Olwin Froon, Trade Federation
////////////////////////////////////////////////////////////////////////////////
// of 160716: revokeAccess
// of 160715: initial spin-off
////////////////////////////////////////////////////////////////////////////////



interface swcapiInterface {

  public static function getError($clear);
    // Returns a string describing the nature of the recent error,
    // an empty string if nothing went wrong.
    //
    // $clear (optional): TRUE will reset the error marker afterwards.
    // If omitted, $clear defaults to FALSE.



  public static function getErrorCode();
    // Returns a numerical error code if something went wrong, a zero otherwise.



  public static function hasError();
    // Returns TRUE if the recent API operation caused an error.



  public static function authorize(array $permissions, $state, $accessmode);
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



  public static function requestAccessToken($authcode, $accessmode);
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



  public static function revokeAccess($refreshtoken);
    // Tries to revoke the current access token.
    // Returns TRUE if everything went well, FALSE otherwise.
    //
    // $refreshtoken: the user's current refresh token.
    //
    // Obviously, this won't work in online access mode, since there won't be a refresh
    // token.
  

}
