<?php
include 'Utilities.php';

class AuthnRequest {

  public function initiateLogin() {
  	
  	$ini_array = parse_ini_file("../config/saml_config.ini");
  	
  	$acs_url=$ini_array['acs_url'];
    $issuer = $ini_array['sp_entity_id'];
    $sso_url =$ini_array['idp_login_url'];

    $saml_request = Utilities::createAuthnRequest($acs_url, $issuer);
    $redirect = $sso_url . '?SAMLRequest=' . $saml_request;
    header('Location: ' . $redirect);
  }

}