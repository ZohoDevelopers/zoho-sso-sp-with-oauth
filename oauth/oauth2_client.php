<?php

class OAuth2Client{

	public static $CLIENT_ID="client_id";
	public static $REDIRECT_URI="redirect_uri";
	public static $CLIENT_SECRET="client_secret";
	public static $RESPONSE_TYPE_CODE="response_type=code";
	public static $GRANT_TYPE_AUTHORIZATION_CODE="grant_type=authorization_code";

	private $authorize_url;
	private $access_token_url;
	private $refresh_token_url;
	private $revoke_token_url;

	private $client_id;
	private $client_secret;
	private $redirect_uri;

	private $code;
	private $access_token;
	private $refresh_token;
	private $expires_in;

	public function __construct(){
		$ini_array = parse_ini_file("../config/oauth_client_config.ini");
		
		$this->authorize_url=$ini_array['Authorize_Url'];
		$this->access_token_url=$ini_array['Access_Token_Url'];
		$this->refresh_token_url=$ini_array['Refresh_Token_Url'];
		$this->client_id=$ini_array['Client_Id'];
		$this->client_secret=$ini_array['Client_Secret'];
		$this->redirect_uri=$ini_array['Redirect_Uri'];
		//$this->revoke_token_url=$ini_array['Revoke_Token_Url'];
	
	}
	public function setCode($code) {
	      $this->code=$code;
  	}
  	public function __get($property) {
	    if (property_exists($this, $property)) {
	      return $this->$property;
	    }
  	}

  public function __set($property, $value) {
	    if (property_exists($this, $property)) {
	      $this->$property = $value;
	    }
	}
    public function getFullAuthorizeUrl(){
    	return $this->authorize_url .'&'.
    			self::$CLIENT_ID . '=' . $this->client_id . '&' .
    			self::$REDIRECT_URI . '=' . $this->redirect_uri . '&' .
    			self::$RESPONSE_TYPE_CODE;
    }

	public function authorizationGrant(){

	$curl = curl_init();

		$post_fields= 'code='. $this->code. '&'.
					self::$CLIENT_ID . '=' . $this->client_id . '&' .
					self::$CLIENT_SECRET . '=' . $this->client_secret . '&' .
    				self::$REDIRECT_URI . '=' . $this->redirect_uri . '&' .
    			self::$GRANT_TYPE_AUTHORIZATION_CODE;
		
		curl_setopt_array($curl, array(
		  CURLOPT_URL => $this->access_token_url,
		  CURLOPT_RETURNTRANSFER => true,
		  CURLOPT_ENCODING => "",
		  CURLOPT_MAXREDIRS => 10,
		  CURLOPT_TIMEOUT => 30,
		  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
		  CURLOPT_CUSTOMREQUEST => "POST",
		  CURLOPT_POSTFIELDS => $post_fields,
		  CURLOPT_HTTPHEADER => array(
		    "content-type: application/x-www-form-urlencoded"
		  ),
		));

		$response = curl_exec($curl);
		$err = curl_error($curl);

		curl_close($curl);

		if ($err) {
		  echo "cURL Error #:" . $err;
		} else {
			$response_obj=json_decode($response);
			
			if (array_key_exists("access_token",$response_obj))
			{
				$this->access_token=$response_obj->access_token;
			}
			if (array_key_exists("refresh_token",$response_obj))
			{
				$this->refresh_token=$response_obj->refresh_token;
			}
			if (array_key_exists("expires_in",$response_obj))
			{
				$this->expires_in=$response_obj->expires_in;
			}
		}
	}
}
