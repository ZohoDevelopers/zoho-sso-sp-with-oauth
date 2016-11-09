<?php

include 'AuthnRequest.php';
include 'Acs.php';

if( isset($_POST['SAMLResponse']) )
{
  $response_obj = new Acs();
  $response = $response_obj->processSamlResponse($_POST);
  echo 'hello '.$response;
}
else{
	$authn_request = new AuthnRequest();
	$authn_request->initiateLogin();
}
?>