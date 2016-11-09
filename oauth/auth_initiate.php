<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
</head>
<body>
<div style="margin:50px;text-align: center;">
<input type="button" name="" value="Authorize" onclick="window.open('<?php

include 'oauth2_client.php';

$oauth_client = new OAuth2Client();
echo $oauth_client->getFullAuthorizeUrl();

?>','windowname1', 'width=700, height=600, top=200, left=400')" >
</div>
<div style="margin:50px;text-align: center;">
  <p id="z-token"></p>
</div>
<div style="margin:50px;text-align: center;">
  <p id="z-info"></p>
</div>
<script type="text/javascript">
	function receiveMessage(e)
{
	if(e.data.indexOf('OAUTH_SUCCESS_')>-1)//No I18N
		{
		var access_token=e.data.replace("OAUTH_SUCCESS_","");//no i18n
	$('#z-token').html('Your Zoho OAuth Acess Token is  '+access_token);	
      $.ajax({
	   type: "GET",
	   url: "../test/get_zoho_leads.php",
	   data:"access_token="+access_token,
	   success: function(data) {
          $('#z-info').html('===================================<br>fetching a lead info from your crm Account . . .<br>======================================<br>'+data);
       console.log(data);
	   }
		});
		}
	
}
window.addEventListener("message", receiveMessage, false);
</script>
</body>
</html>