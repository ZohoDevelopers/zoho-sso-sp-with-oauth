## Upload the project on your server and configure the following files for OAuth and SAML.

### SAML Configuration

1. Open file `saml_config.ini` in the `config` folder. 
  ``` ini
      ; Enter SP details (Entity-Id,Acs Url) you would have to register this in zoho developer console

      sp_entity_id = "yoursite.com"
      acs_url = "https://yoursite.com/zohosp/saml/login.php"

      ; Copy The IdP details from Developer Console and paste it here.

      idp_login_url=""
      idp_logout_url=""
  ```

2. Get the details of the IdP (`idp_login_url` and `idp_loginout_url`) from Zoho Developer Console -> connected App SAML configuration Page, and fill them here.
  Set your site's domain and login path as `sp_entity_id` and `acs_url`.

3. Download the certificate from Partner Console's configuration page and save it as `cert.pem` in the `resources` folder.

More help on this at https://www.zoho.com/developer/help/extensions/custom-php-connected-app.html

### OAuth Configuration

1. Open file `oauth_config.ini` in the `config` folder. 

  ``` ini
  ; you can add other scopes in Authorize_url as per your need

  Authorize_Url = "https://accounts.zoho.com/oauth/v2/auth?scope=ZohoCRM.crmdataaccess.ALL&access_type=offline" 
  Access_Token_Url = "https://accounts.zoho.com/oauth/v2/token"
  Refresh_Token_Url = "https://accounts.zoho.com/oauth/v2/token"
  Refresh_Token_Url = ""
  Client_Id = ""
  Client_Secret = ""
  Redirect_Uri = "http://yoursite.com.com/zohosp/oauth/auth_redirect.php"
  ```

2. Set the `client_id` and `client_secret` that you received during your oauth client registration from Zoho Developer Console.

Find a live version of an oauth client at http://2814.cf/zohosp/oauth/auth_initiate.php

> **Note:** The OAuth2 is in beta yet.
For test purpose an api to get a lead is provided in the test folder, which uses the oauth token.

