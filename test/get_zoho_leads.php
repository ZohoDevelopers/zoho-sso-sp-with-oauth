<?php

parse_str($_SERVER['QUERY_STRING'], $query);
$access_token=$query['access_token'];
$curl = curl_init();

curl_setopt_array($curl, array(
  CURLOPT_URL => "https://api.zoho.com/crm/v2/Leads",
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_ENCODING => "",
  CURLOPT_MAXREDIRS => 10,
  CURLOPT_TIMEOUT => 30,
  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
  CURLOPT_CUSTOMREQUEST => "GET",
  CURLOPT_HTTPHEADER => array(
    "Authorization: Zoho-oauthtoken ".$access_token
  ),
));

$response = curl_exec($curl);
$err = curl_error($curl);

curl_close($curl);

if ($err) {
  echo "cURL Error #:" . $err;
} else {
$response_obj=json_decode($response);
$to_send="Full Name : ". $response_obj->data[0]->Full_Name . '<br>';
$to_send=$to_send . "Created Time : ". $response_obj->data[0]->Created_Time . '<br>';
$to_send=$to_send . "Email : ". $response_obj->data[0]->Email . '<br>';
$to_send=$to_send . "Lead Owner : ". $response_obj->data[0]->Lead_Owner->name . '<br>';
  echo $to_send;
}