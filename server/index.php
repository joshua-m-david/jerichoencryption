<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2024  Joshua M. David
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


/**
 * This file acts as a controller, which bootstraps the PHP API, receives requests from the client application,
 * validates the authentication and responds accordingly to the client with an authenticated response if the request
 * validated successfully. No need for autoloaders etc because we will require just what is needed.
 */

use Jericho\Api;
use Jericho\Converter;
use Jericho\Database;
use Jericho\NetworkCipher;
use Jericho\RequestAuth;
use Jericho\ResponseAuth;


// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Load common constants
require_once 'library/constants/common-constants.php';

// Load data storage classes
require_once 'library/data-classes/response.php';
require_once 'library/data-classes/transaction-query.php';
require_once 'library/data-classes/validated-request.php';

// Load helper classes
require_once 'library/helper-classes/converter.php';
require_once 'library/helper-classes/database.php';
require_once 'library/helper-classes/network-cipher.php';

// Load code for libraries
require_once 'library/request-auth.php';
require_once 'library/api.php';
require_once 'library/response-auth.php';


// Get the absolute path to the live configuration file e.g. /var/www/html/config/config.json
$configFilePath = realpath(__DIR__ . '/config/config.json');

// Load the JSON file configuration and decode it into an array
$converter = new Converter();
$config = $converter->loadAndDecodeConfig($configFilePath);
$databaseConfig = $config['databaseConfig'];
$groupConfigs = $config['groupConfigs'];
$applicationConfig = $config['applicationConfig'];

// Initialise the database class and the request authentication
$db = new Database($databaseConfig);
$networkCipher = new NetworkCipher($converter);
$requestAuth = new RequestAuth($db, $converter, $networkCipher);

// Get the raw request data which is sent as a Base64 string in the body of the POST request
$rawPostBodyDataBase64 = file_get_contents('php://input');

// Work out the current UNIX timestamp
$currentTimestamp = time();

// Authenticate and decrypt the API request from the client.
$validatedRequest = $requestAuth->performClientRequestAuthenticationAndDecryption(
	$groupConfigs, $rawPostBodyDataBase64, $currentTimestamp
);

// Initialise the response authentication class
$responseAuth = new ResponseAuth($converter, $networkCipher);

// If the validation failed
if ($validatedRequest->success === false)
{
	// Output an error response which will usually be just random data of variable length and a HTTP/1.1 200 response.
	// If the config has the debugging option turned on then the error message will be displayed after the 200 code.
	$responseAuth->outputErrorResponse($validatedRequest->errorMessage, $applicationConfig);
}

// Initialise the core API to perform the API action
$api = new Api($db);

// The validation succeeded, so perform the API Action and get back data for the response
$response = $api->performRequestedApiAction($validatedRequest);

// Get group encryption and MAC keys
$encryptionKeyHex = $validatedRequest->currentGroupConfig['derivedEncryptionKey'];
$macKeyHex = $validatedRequest->currentGroupConfig['derivedMacKey'];

// Get random padding for the response
$responsePaddingHex = $responseAuth->getAuthenticatedResponsePadding();

// Generate a random response nonce so it's different to the request nonce.
// This avoids re-using nonces for a different message encryption.
$responseNonceHex = $responseAuth->generateNonce();

// Get the Request MAC, which we will include in the Response MAC calculation
$requestMacHex = $validatedRequest->mac;

// Serialise the response into a canonical byte order that can be encrypted
$serialisedResponseBase64 = $responseAuth->serialiseEncryptAndAuthenticateResponse(
	$encryptionKeyHex, $macKeyHex, $responsePaddingHex, $responseNonceHex, $response, $requestMacHex
);

// Send an authenticated response back to client
$responseAuth->outputAuthenticatedResponse($serialisedResponseBase64);
