

<?php

// cd /Users/YOUSHA_1/Desktop/sbhs-oauth-api-demo
// php -S 192.168.1.101:8000
// php -S 153.107.45.141:8000
// php -S localhost:8000

 require 'lib/httpclient/http.php';
 require 'lib/oauth-api/oauth_client.php';
  // This OAuth client will store users access tokens by using a session cookie in their web
 // browser this should suffice for you writing interactive applications. An alternative is to
 // store the tokens in a database (see database_oauth_client.php and mysqli_oauth_client.php)
  $client = new OAuth_Client_Class;
  // Extend the length of time PHP will maintain the session information about the OAuth
 // token refresh tokens are valid for 90 days, so if you store them in a persistent fashion
 // you can continue to use the token without requiring the user to reauthenticate for much
 // longer than the two hours this session is configured to last for.
 // Note that you shouldn't store refresh tokens in cookies directly. Encrypt them or store
 // them in a key-value store (and set a persistent cookie a key you generate)
 ini_set('session.gc_maxlifetime', 7200);
  // Your configuration block. Register your app on the Student Portal.
 // Don't leak your Client Secret. If you do, make sure you regenerate it through the Portal.
 $client->redirect_uri  = 'https://localhost/sbhslogin/sbhsdemo.php';
 $client->client_id     = '01hy9zy7azf95bjyn0pn226sx5';
 $client->client_secret = 'jOxgsZ4UkCLe8b9-SKwSKftjNu3mQvR6-C2lx8GTqcApOx14jJNOD_RcNpDlbyHOQUMl4MTuNP50BK4O';


 // turn these off when you are happy with functionality
 $client->debug = 1;
 $client->debug_http = 0;


//session_start(); print_r($_SESSION); die();
  // --------------------------
 // Configuration for the SBHS API. You don't need to change this
 // the SBHS API base URL
 $api_url = 'https://student.sbhs.net.au/api/';
  // OAuth version 2 is used by the SBHS API
 $client->oauth_version = '2.0'; 
 // The OAuth standard refers to this as the "Authorization Endpoint" URL.
 // Also the parameters are recommended by the standard and in most other libraries
 // you will only need to provide the URL https://student.sbhs.net.au/api/authorize
 $client->dialog_url = 'https://student.sbhs.net.au/api/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}';
 // The OAuth standard also required a "Token Endpoint" URL where
 // tokens can be obtained. Here it's simply https://student.sbhs.net.au/api/token
 $client->access_token_url = 'https://student.sbhs.net.au/api/token';
 // -------------------------- 




  // --------------------------
 // Actually call the API. This is a demo, you will need to adapt the code
 // to actually do something useful/call more than one fixed function
  $apiResponse = '';
  if (($success = $client->Initialize())) {
    // ::Process() will attempt to retrieve an access token from the session. If it
   // can't it will contact redirect to the Authorization Endpoint to obtain one
   // from SBHS (SBHS will prompt for login and authorisation if required).    
   if (($success = $client->Process())) {
  
     // at this point the OAuth library should have retrieved a valid access token
     // (by calling the Authorization Endpoint if need be). So let's use the token
     // and call some APIs on behalf of the user who authorised us.
    
             
     if ($client->access_token) {
      
       // API function to call - get the user's timetable
       // API functions are documented on the Student Portal
       $function = 'details/userinfo.json';
      
       // call the function
       $success = $client->CallAPI($api_url . $function,
                                   'GET', array(),
                                   array(
                                     'FailOnAccessError' => true,
                                     'ResponseContentType' => 'unspecified'),
                                   $apiResponse);
                              
       // It is possible the token unexpectedly expired or was revoked. If so we only
       // find out at this point and we need to reset the access token and retry.
       // If you're building an app you should handle this scenario cleanly.
       if (!$success) {          
         if ($client->response_status == 401) {
           $client->ResetAccessToken();
          
           // In an actual app, refresh the page, or call $client->Process() again
           // In this demo, we'll just abort at this stage
         }
       }
     }
   }
   $client->Finalize($success);
 }

 if (isset($_GET['logout'])) {
  // Clear session data or access token
  session_destroy();
  // Redirect to logout confirmation page or any desired location
  header('Location: home.html');
  exit;
}
  // before we output anything, check if the OAuth client has written a response
 // if it has, it will have set its exit member instructing us to end without output
 if ($client->exit) {
   if ($client->debug) {
     echo $client->debug_output;
   }
   exit;
 }


 // if we arrive this far, we can print the response from the API
 if ($success) {
  // Decode API response
  $decodedResponse = json_decode($apiResponse);

  // Extract relevant student data
  $studentData = [
      'username' => $decodedResponse->username,
      'studentId' => $decodedResponse->studentId,
      'givenName' => $decodedResponse->givenName,
      'surname' => $decodedResponse->surname,
      'rollClass' => $decodedResponse->rollClass,
      'yearGroup' => $decodedResponse->yearGroup,
      'role' => $decodedResponse->role,
      'department' => $decodedResponse->department,
      'office' => $decodedResponse->office,
      'email' => $decodedResponse->email,
      'emailAliases' => $decodedResponse->emailAliases,
      'decEmail' => $decodedResponse->decEmail,
      'groups' => $decodedResponse->groups
  ];

  // Encode student data into JSON format
  $studentJSON = json_encode($studentData);


  // JavaScript code to store JSON data in local storage
  echo '<script>';
  echo 'localStorage.setItem("studentData", \'' . addslashes($studentJSON) . '\');';
  echo 'window.location.href = "profile.html";';
  echo '</script>';
}

?>




