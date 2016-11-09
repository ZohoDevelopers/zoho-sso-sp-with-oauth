<?php

include 'oauth2_client.php';

parse_str($_SERVER['QUERY_STRING'], $query);
if (array_key_exists("code",$query))
{
  $oauth_client = new OAuth2Client();
  $oauth_client->code=$query['code'];
  $oauth_client->authorizationGrant();
  echo '<script>setTimeout(function(){ {parent.opener.postMessage("OAUTH_SUCCESS_' .$oauth_client->access_token.'", "*");}window.close();},3000);</script>' ;
}
else{
	echo 'code not received <br>' . $_SERVER['QUERY_STRING'];
}
?>
