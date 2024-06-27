<?php

class OAuth_Client_Class
{
    var $client_id = '';
    var $client_secret = '';
    var $redirect_uri = '';
    var $dialog_url = '';
    var $access_token_url = '';
    var $oauth_version = '2.0';
    var $debug = false;
    var $debug_http = false;
    var $exit = false;
    var $access_token = '';
    var $access_token_secret = '';
    var $access_token_expiry = '';
    var $access_token_type = '';
    var $refresh_token = '';
    var $authorization_error = '';
    var $access_token_error = '';
    var $response_status = 0;
    var $debug_output = '';

    function SetError($error)
    {
        $this->authorization_error = $error;
        if ($this->debug)
            $this->OutputDebug('Error: ' . $error);
        return false;
    }

    function OutputDebug($message)
    {
        if ($this->debug)
        {
            $message = 'OAuth client: ' . $message;
            $this->debug_output .= $message . "\n";
            error_log($message);
        }
        return true;
    }

    function GetAccessTokenURL(&$access_token_url)
    {
        $access_token_url = str_replace('{API_KEY}', $this->client_secret, $this->access_token_url);
        return true;
    }

    function GetRedirectURI(&$redirect_uri)
    {
        if (strlen($this->redirect_uri))
            $redirect_uri = $this->redirect_uri;
        else
            $redirect_uri = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        return true;
    }

    function GetStoredState(&$state)
    {
        if (!function_exists('session_start'))
            return $this->SetError('Session variables are not accessible in this PHP environment');
        if (session_id() === '' && !session_start())
            return $this->SetError('It was not possible to start the PHP session');
        if (isset($_SESSION['OAUTH_STATE']))
            $state = $_SESSION['OAUTH_STATE'];
        else
            $state = $_SESSION['OAUTH_STATE'] = time() . '-' . substr(md5(rand() . time()), 0, 6);
        return true;
    }

    function GetRequestState(&$state)
    {
        $state = (isset($_GET['state']) ? $_GET['state'] : null);
        return true;
    }

    function GetRequestCode(&$code)
    {
        $code = (isset($_GET['code']) ? $_GET['code'] : null);
        return true;
    }

    function GetRequestError(&$error)
    {
        $error = (isset($_GET['error']) ? $_GET['error'] : null);
        return true;
    }

    function SendAPIRequest($url, $method, $parameters, $oauth, $options, &$response)
    {
        $this->response_status = 0;
        $http = new http_class;
        $http->debug = ($this->debug && $this->debug_http);
        $http->log_debug = true;
        $http->sasl_authenticate = 0;
        $http->user_agent = 'PHP-OAuth-API (http://www.phpclasses.org/oauth-api $Revision: 1.107 $)';
        $http->redirection_limit = (isset($options['FollowRedirection']) ? intval($options['FollowRedirection']) : 0);
        $http->follow_redirect = ($http->redirection_limit != 0);
        if ($this->debug)
            $this->OutputDebug('Accessing the ' . $options['Resource'] . ' at ' . $url);
        $post_files = array();
        $method = strtoupper($method);
        $authorization = '';
        $type = (isset($options['RequestContentType']) ? strtolower(trim(strtok($options['RequestContentType'], ';'))) : (($method === 'POST' || isset($oauth)) ? 'application/x-www-form-urlencoded' : ''));
        if (isset($oauth))
        {
            $values = array(
                'oauth_consumer_key' => $this->client_id,
                'oauth_nonce' => md5(uniqid(rand(), true)),
                'oauth_signature_method' => 'HMAC-SHA1',
                'oauth_timestamp' => time(),
                'oauth_version' => '1.0',
            );
            $header_values = array_merge($values, $oauth, $parameters);
            $key = $this->client_secret . '&' . $this->access_token_secret;
            $sign = $method . '&' . urlencode($url) . '&' . urlencode(http_build_query($header_values));
            $values['oauth_signature'] = base64_encode(hash_hmac('sha1', $sign, $key, true));
            $post_values = $parameters;
        }
        else
        {
            $post_values = $parameters;
        }
        if (strlen($authorization) === 0 && !strcasecmp($this->access_token_type, 'Bearer'))
            $authorization = 'Bearer ' . $this->access_token;
        if (strlen($error = $http->GetRequestArguments($url, $arguments)))
            return $this->SetError('It was not possible to open the ' . $options['Resource'] . ' URL: ' . $error);
        if (strlen($error = $http->Open($arguments)))
            return $this->SetError('It was not possible to open the ' . $options['Resource'] . ' URL: ' . $error);
        $arguments['RequestMethod'] = $method;
        $arguments['PostValues'] = $post_values;
        $arguments['Headers']['Accept'] = (isset($options['Accept']) ? $options['Accept'] : '*/*');
        if (strlen($authorization))
            $arguments['Headers']['Authorization'] = $authorization;
        if (strlen($error = $http->SendRequest($arguments)) || strlen($error = $http->ReadReplyHeaders($headers)))
        {
            $http->Close();
            return $this->SetError('It was not possible to retrieve the ' . $options['Resource'] . ': ' . $error);
        }
        $error = $http->ReadWholeReplyBody($data);
        $http->Close();
        if (strlen($error))
        {
            return $this->SetError('It was not possible to access the ' . $options['Resource'] . ': ' . $error);
        }
        $this->response_status = intval($http->response_status);
        $response = json_decode($data, true);
        if ($this->response_status >= 200 && $this->response_status < 300)
            $this->access_token_error = '';
        else
        {
            $this->access_token_error = 'It was not possible to access the ' . $options['Resource'] . ': it was returned an unexpected response status ' . $http->response_status . ' Response: ' . $data;
            if ($this->debug)
                $this->OutputDebug('Could not retrieve the OAuth access token. Error: ' . $this->access_token_error);
        }
        return true;
    }

    function ProcessToken($code, $refresh)
    {
        if (!$this->GetRedirectURI($redirect_uri))
            return false;
        $authentication = $this->access_token_authentication;
        if ($refresh)
        {
            $values = array(
                'refresh_token' => $this->refresh_token,
                'grant_type' => 'refresh_token',
                'scope' => $this->scope,
            );
        }
        else
        {
            $values = array(
                'code' => $code,
                'redirect_uri' => $redirect_uri,
                'grant_type' => 'authorization_code'
            );
        }
        $options = array(
            'Resource' => 'OAuth ' . ($refresh ? 'refresh' : 'access') . ' token',
            'ConvertObjects' => true
        );
        switch (strtolower($authentication))
        {
            case 'basic':
                $options['AccessTokenAuthentication'] = $authentication;
                $values['redirect_uri'] = $redirect_uri;
                break;
            case '':
                $values['client_id'] = $this->client_id;
                $values['client_secret'] = $this->client_secret;
                break;
            default:
                return $this->SetError($authentication . ' is not a supported authentication mechanism to retrieve an access token');
        }
        if (!$this->GetAccessTokenURL($access_token_url))
            return false;
        if (!$this->SendAPIRequest($access_token_url, 'POST', $values, null, $options, $response))
            return false;
        if (strlen($this->access_token_error))
        {
            $this->authorization_error = $this->access_token_error;
            return true;
        }
        if (!isset($response['access_token']))
        {
            if (isset($response['error']))
            {
                $this->authorization_error = 'It was not possible to retrieve the access token: it was returned the error: ' . $response['error'];
                return true;
            }
            return $this->SetError('OAuth server did not return the access token');
        }
        $this->access_token = $response['access_token'];
        if (isset($response['expires_in']))
            $this->access_token_expiry = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $response['expires_in']);
        else
            $this->access_token_expiry = '';
        if (isset($response['token_type']))
            $this->access_token_type = $response['token_type'];
        if (isset($response['refresh_token']))
            $this->refresh_token = $response['refresh_token'];
        return true;
    }

    function Process()
    {
        if (strlen($this->access_token) || strlen($this->access_token_secret))
            return $this->SetError('The OAuth token was already set');
        if ($this->oauth_version == '2.0')
        {
            if ($this->debug)
                $this->OutputDebug('Checking if OAuth access token was already retrieved');
            if (!$this->RetrieveToken($valid))
                return false;
            if ($valid)
                return true;
            if ($this->debug)
                $this->OutputDebug('Checking the authentication state in URI ' . $_SERVER['REQUEST_URI']);
            if (!$this->GetStoredState($stored_state))
                return false;
            if (strlen($stored_state) == 0)
                return $this->SetError('It was not set the OAuth state');
            if (!$this->GetRequestState($state))
                return false;
            if ($state === $stored_state)
            {
                if ($this->debug)
                    $this->OutputDebug('Checking the authentication code');
                if (!$this->GetRequestCode($code))
                    return false;
                if (strlen($code) == 0)
                {
                    if (!$this->GetRequestError($this->authorization_error))
                        return false;
                    if (isset($this->authorization_error))
                    {
                        if ($this->debug)
                            $this->OutputDebug('Authorization failed with error code ' . $this->authorization_error);
                        switch ($this->authorization_error)
                        {
                            case 'invalid_request':
                            case 'unauthorized_client':
                            case 'access_denied':
                            case 'unsupported_response_type':
                            case 'invalid_scope':
                            case 'server_error':
                            case 'temporarily_unavailable':
                            case 'user_denied':
                                return true;
                            default:
                                return $this->SetError('It was returned an unknown OAuth error code');
                        }
                    }
                    return $this->SetError('It was not returned the OAuth dialog code');
                }
                if (!$this->ProcessToken($code, false))
                    return false;
            }
            else
            {
                if (!$this->GetRedirectURI($redirect_uri))
                    return false;
                if (!$this->GetDialogURL($url, $redirect_uri, $stored_state))
                    return false;
                if ($this->debug)
                    $this->OutputDebug('Redirecting to OAuth Dialog ' . $url);
                $this->Redirect($url);
                $this->exit = true;
            }
        }
        return true;
    }

    function RetrieveToken(&$valid)
    {
        $valid = false;
        if (!$this->GetAccessToken($access_token))
            return false;
        if (isset($access_token['value']))
        {
            $this->access_token = $access_token['value'];
            $this->access_token_expiry = '';
            $expired = (isset($access_token['expiry']) && strcmp($this->access_token_expiry = $access_token['expiry'], gmstrftime('%Y-%m-%d %H:%M:%S')) < 0);
            if ($expired)
            {
                if ($this->debug)
                    $this->OutputDebug('The OAuth access token expired in ' . $this->access_token_expiry);
            }
            if (isset($access_token['type']))
                $this->access_token_type = $access_token['type'];
            if (isset($access_token['secret']))
                $this->access_token_secret = $access_token['secret'];
            if (isset($access_token['refresh']))
                $this->refresh_token = $access_token['refresh'];
            else
                $this->refresh_token = '';
            $valid = true;
        }
        return true;
    }

    function GetAccessToken(&$access_token)
    {
        if (!function_exists('session_start'))
            return $this->SetError('Session variables are not accessible in this PHP environment');
        if (session_id() === '' && !session_start())
            return $this->SetError('It was not possible to start the PHP session');
        if (isset($_SESSION['OAUTH_ACCESS_TOKEN']))
            $access_token = $_SESSION['OAUTH_ACCESS_TOKEN'];
        else
            $access_token = array();
        return true;
    }

    function StoreAccessToken($access_token)
    {
        if (!function_exists('session_start'))
            return $this->SetError('Session variables are not accessible in this PHP environment');
        if (session_id() === '' && !session_start())
            return $this->SetError('It was not possible to start the PHP session');
        $_SESSION['OAUTH_ACCESS_TOKEN'] = $access_token;
        return true;
    }

    function ResetAccessToken()
    {
        if (!$this->GetAccessTokenURL($access_token_url))
            return false;
        if ($this->debug)
            $this->OutputDebug('Resetting the access token status for OAuth server located at ' . $access_token_url);
        if (!function_exists('session_start'))
            return $this->SetError('Session variables are not accessible in this PHP environment');
        if (session_id() === '' && !session_start())
            return $this->SetError('It was not possible to start the PHP session');
        if (isset($_SESSION['OAUTH_ACCESS_TOKEN']))
            unset($_SESSION['OAUTH_ACCESS_TOKEN']);
        return true;
    }

    function Initialize()
    {
        return true;
    }

    function Finalize($success)
    {
        return $success;
    }

    function Redirect($url)
    {
        header('HTTP/1.0 302 OAuth Redirection');
        header('Location: ' . $url);
    }
}

?>
