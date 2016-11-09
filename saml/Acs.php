<?php

include 'Response.php';
include '../lib/xmlseclibs.php';

class Acs {
public function processSamlResponse($post) {

    $myfile = fopen("../resources/cert.pem", "r") or die("Unable to open file!");
    $cert_fingerprint = fread($myfile,filesize("../resources/cert.pem"));
    fclose($myfile);
    
    $ini_array = parse_ini_file("../config/saml_config.ini");
    
    $acs_url=$ini_array['acs_url'];
    $sp_entity_id = $ini_array['sp_entity_id'];
    $issuer =$ini_array['idp_login_url'];

if (array_key_exists('SAMLResponse', $post)) {
      $saml_response = $post['SAMLResponse'];
    }
    else {
      throw new Exception('Missing SAMLRequest or SAMLResponse parameter.');
    }

    $saml_response = base64_decode($saml_response);
    $document = new DOMDocument();
    $document->loadXML($saml_response);

    $saml_response_xml = $document->firstChild;

    $cert_fingerprint = XMLSecurityKey::getRawThumbprint($cert_fingerprint);
    $saml_response = new Response($saml_response_xml);
    $cert_fingerprint = preg_replace('/\s+/', '', $cert_fingerprint);
    $cert_fingerprint = iconv("UTF-8", "CP1252//IGNORE", $cert_fingerprint);
 
    $assertion_signature_data = current($saml_response->getAssertions())->getSignatureData();
      $valid_signature = Utilities::processResponse($acs_url, $cert_fingerprint, $assertion_signature_data, $saml_response);
      if (!$valid_signature) {
        echo 'Invalid Signature in SAML Assertion';
      }

    Utilities::validateIssuerAndAudience($saml_response, $sp_entity_id, $issuer, $acs_url);

    $username = current(current($saml_response->getAssertions())->getNameId());
    $attrs = current($saml_response->getAssertions())->getAttributes();
    return $username;
  }

}
