<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2015  Joshua M. David
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */

/**
 * API library functions across the application
 */
class Api
{
	// Database object
	private $db;
	
	// Configuration
	private $users;
	private $serverKey;
	private $applicationConfig;
	
	// Whitelist of valid usernames
	private $userList = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf'];
	
	// Whitelist of API actions
	private $apiActions = ['sendMessage', 'receiveMessages', 'testConnection'];
	
	// Number of seconds after a request has been sent that the request is valid for
	public $validityWindow = 60;
	
	// Number of seconds that nonces are kept for in the database, after this they are deleted
	public $nonceExpiryTime = 120;
	
	// Schedule the cleanup task to run after this many seconds
	public $cleanupSchedule = 120;
	
	// Variables from the request after they have been checked and filtered for bad input
	private $validatedRequestUser = null;
	private $validatedRequestMac = null;
	private $validatedRequestTimestamp = null;
	private $validatedRequestNonce = null;
	private $validatedRequestAction = null;
	private $validatedRequestDataJson = null;
	private $validatedRequestData = null;
		
	/**
	 * Constructor takes the initialised database and configurations using dependency injection
	 * @param Database &$db The database object
	 * @param array &$numberOfUsers The number of valid chat group users
	 * @param string &$serverKey The server key as a hexadecimal string
	 * @param array &$applicationConfig Some application settings
	 */
	public function __construct(&$db, &$numberOfUsers, &$serverKey, &$applicationConfig)
	{
		$this->db = $db;
		$this->serverKey = $serverKey;
		$this->applicationConfig = $applicationConfig;
				
		// Set the number of valid chat users based on the config
		$this->users = $this->setChatGroupUsers($numberOfUsers);
	}
			
	/**
	 * Connects to the database
	 */
	public function connectToDatabase()
	{
		// Try connecting to the database
		$connectionSuccess = $this->db->connect();
		
		// If the connect fails then send an error response to the client
		if ($connectionSuccess === false)
		{
			$this->outputErrorResponse('Database connection failed, check your configuration. ' . $this->db->getErrorMsg());
		}
	}
	
	/**
	 * Checks if the request from the client is valid by using the authentication protocol. The goals of which are:
	 *  - Authenticate all API requests to the server to verify they are from the legitimate user.
	 *  - Authenticate all API responses from the server to verify the response came from the legitimate server not an attacker.
	 *  - Disallow one user to spoof another user's requests to the server.
	 *  - Avert passive MITM attacks where an attacker tries to snoop the API credentials in transit.
	 *  - Avert active MITM attacks where an attacker attempts to send fake requests to the server or impersonate the server responses. 
	 *  - Avert replay attacks and reject a request/response if the MAC does not match.
	 *  - Prevent one request to the server being replayed with a different action being perfomed by the attacker
	 */
	public function performClientRequestAuthentication()
	{
		// Get the request data which is sent as a Base64 string in the POST request
		$rawDataBase64 = $this->getDataKeyIfExists('data', $_POST);
		
		
		// Check to make sure the request does not exceed a reasonable byte length. This is used to mitigate 
		// a potential DOS attack which could make the server do lots of request validation at once. An attacker 
		// could potentially send lots of requests and force the server to do a computationally expensive task 
		// (e.g. hashing for the MAC) on large data to authenticate multiple requests which would slow the server.
		$validLength = (strlen($rawDataBase64) <= 975) ? true : false;
			
		// If it is an invalid length
		if ($validLength === false)
		{
			$this->outputErrorResponse('Request is too large.');
		}
		
		
		// Validate and decode the Base64 data
		$data = $this->validateAndDecodeBase64($rawDataBase64);
	
		// If the data is invalid throw an error response
		if ($data === false)
		{
			$this->outputErrorResponse('Malformed Base64 in request.');
		}
		
		
		// Get the JSON data and MAC
		$dataJson = $data['dataJson'];
		$mac = $data['mac'];
		
		// Remove non-hexadecimal characters and validate the MAC of the user and whole JSON data packet
		$mac = $this->filterNonHexadecimalChars($mac);
		$validMac = $this->validateDataMac($dataJson, $this->serverKey, $mac);
		
		// If the MAC is invalid throw an error response
		if ($validMac === false)
		{
			$this->outputErrorResponse('MAC not accepted, invalid request.');
		}
		
		
		// Decode the JSON to an associative array
		$data = json_decode($dataJson, true);
		
		// If the JSON could not be decoded correctly throw an error response
		if ($data === null)
		{
			$this->outputErrorResponse('Decoding of request data failed.');
		}
		
		
		// Remove all non a-z chars, check the user against the whitelist and active user list
		$user = $this->getDataKeyIfExists('user', $data);
		$user = $this->filterNonLowercaseAlphabeticalChars($user);
		$validUser = $this->validateUser($user);
		
		// If the user is invalid throw an error response
		if ($validUser === false)
		{
			$this->outputErrorResponse('Invalid request user.');
		}
		
		
		// Get the timestamp, remove characters that are not 0-9, then check the timestamp is within the allowed time window
		$timestamp = $this->getDataKeyIfExists('timestamp', $data);
		$timestamp = $this->filterNonIntegers($timestamp);
		$validTimestamp = $this->validateDataTimestamp($timestamp);
		
		// If the timestamp is invalid this could indicate the message was intentionally delayed or replayed so throw an error response
		if ($validTimestamp === false)
		{
			$this->outputErrorResponse('Invalid timestamp in request.');
		}

		
		// Get the nonce, remove non hexadecimal chars, validate the nonce and add it to the database so it can't be reused
		$nonce = $this->getDataKeyIfExists('nonce', $data);
		$nonce = $this->filterNonHexadecimalChars($nonce);
		$validNonce = $this->validateDataNonce($nonce);
		$nonceAdded = $this->addSentNonceToDatabase($nonce, $timestamp);
		
		// If the nonce is invalid this could indicate a replay attack so throw an error response
		if (($validNonce === false) || ($nonceAdded === false))
		{
			$this->outputErrorResponse('Invalid nonce in request.');
		}
		
		
		// Get the API action, remove characters that are not a-z or a hyphen, then validate the api action against the whitelist
		// If an attacker changes the API action to be performed then it will fail the MAC verification above
		$apiAction = $this->getDataKeyIfExists('apiAction', $data);
		$apiAction = $this->filterNonAlphabeticalChars($apiAction);
		$validApiAction = $this->validateApiAction($apiAction);
		
		// If the API action is invalid this could indicate an attacker trying to perform some other task so throw an error response
		if ($validApiAction === false)
		{
			$this->outputErrorResponse('Invalid API request action.');
		}
		
		
		// Set the variables to the class after they have been checked and filtered for bad input
		// The data array will still have a few variables that need checking depending on the API action
		$this->validatedRequestUser = $user;
		$this->validatedRequestMac = $mac;
		$this->validatedRequestTimestamp = $timestamp;
		$this->validatedRequestNonce = $nonce;
		$this->validatedRequestAction = $apiAction;
		$this->validatedRequestDataJson = $dataJson;
		$this->validatedRequestData = $data;
	}
		
	/**
	 * Performs the requested API action
	 */
	public function performRequestedApiAction()
	{		
		// Store the sent message in the database and mark it as from the user making the request
		if ($this->validatedRequestAction === 'sendMessage')
		{
			// Get the message from the request
			$message = $this->getDataKeyIfExists('msg', $this->validatedRequestData);
			$message = $this->filterNonHexadecimalChars($message);
			
			// Insert the message into the database	
			$jsonResult = $this->saveMessageToDatabase($this->validatedRequestUser, $message);
		}
		
		// If the user is requesting to download their messages
		else if ($this->validatedRequestAction === 'receiveMessages')
		{
			// Get the unread messages for this user
			$jsonResult = $this->getMessagesForUser($this->validatedRequestUser);			
		}
				
		// If the user is testing the connection from the client
		else if ($this->validatedRequestAction === 'testConnection')
		{
			// Test the server authentication and connection to the database
			$jsonResult = $this->testDatabaseConnection();
		}
		
		// Output response
		$this->outputJson($jsonResult);
	}
	
	/**
	 * Validate and decode the Base64 data
	 * @param string $rawDataBase64 The Base64 request data
	 * @return array|boolean Returns an array with keys 'dataJson' and 'mac' or false if the data is invalid
	 */
	public function validateAndDecodeBase64(&$rawDataBase64)
	{
		try {						
			// Remove any characters that aren't valid Base64 characters
			$dataBase64Filtered = $this->filterNonBase64Chars($rawDataBase64);

			// Decode the data from Base64
			$dataString = base64_decode($dataBase64Filtered, true);

			// If it failed to decode, output error response
			if ($dataString === false)
			{
				return false;
			}

			// Get the data and the MAC
			$dataLength = strlen($dataString);
			$macIndexStart = $dataLength - 128;						// Index of where the MAC begins in the string
			$dataJson = substr($dataString, 0, $macIndexStart);		// Get everything except the last 128 hex chars
			$mac = substr($dataString, $macIndexStart, 128);		// Get last 128 hex symbols from the end of the string
		}
		catch (Exception $exception)
		{
			// Catch any malformed data or errors
			return false;
		}
		
		// If the data or MAC is missing
		if (($dataJson === false) || ($dataJson === '') || ($mac === false) || ($mac === ''))
		{			
			return false;
		}
		
		// Return the correctly decoded data
		return array(
			'dataJson' => $dataJson,
			'mac' => $mac
		);
	}
		
	/**
	 * Checks that the data in the array before using it, or returns an error to the client
	 * @param string $key The array key to check
	 * @param array &$dataArray The data array to check if the key exists in it
	 */
	public function getDataKeyIfExists($key, &$dataArray)
	{
		// If the key does not exist in the JSON data packet
		if (isset($dataArray[$key]) === false)
		{
			// Return error
			return false;
		}
		
		// Return the key
		return $dataArray[$key];
	}
	
	/**
	 * Removes anything not valid Base64 characters (a-z, A-Z, 0-9, +, /, or =)
	 * @param string $input
	 * @return string
	 */
	public function filterNonBase64Chars($input)
	{
		return preg_replace('/[^A-Za-z0-9+\/=]/', '', $input);
	}
	
	/**
	 * Remove everything except a-f and 0-9 lowercase hexadecimal chars
	 * @param string $input
	 * @return string
	 */
	public function filterNonHexadecimalChars($input)
	{
		return preg_replace("/[^a-f0-9]/", '', $input);
	}
	
	/**
	 * Remove everything except a-z lowercase chars
	 * @param string $input
	 * @return string
	 */
	public function filterNonLowercaseAlphabeticalChars($input)
	{
		return preg_replace("/[^a-z]/", '', $input);
	}
	
	/**
	 * Remove everything except a-z  chars
	 * @param string $input
	 * @return string
	 */
	public function filterNonAlphabeticalChars($input)
	{
		return preg_replace("/[^A-Za-z]/", '', $input);
	}
	
	/**
	 * Remove everything except 0-9 integers
	 * @param string $input
	 * @return string
	 */
	public function filterNonIntegers($input)
	{
		return preg_replace("/[^0-9]/", '', $input);
	}
		
	/**
	 * Delete read messages and old nonces from the database every cleanup interval
	 * @return boolean Whether the cleanup task ran or not
	 */
	public function performCleanup()
	{
		// Get the current UNIX timestamp
		$currentTimestamp = time();
		
		// Find out when the cleanup task was last run
		$result = $this->db->select('SELECT cleanup_last_run FROM settings');
		
		// Make sure rows were returned
		if (($result !== false) && ($this->db->getNumRows() === 1))
		{
			// Get when the cleanup was last run, and the time when another cleanup should be run again
			$cleanupLastRun = $result[0]['cleanup_last_run'];
			$cleanupWaitTimestamp = ($cleanupLastRun + $this->cleanupSchedule);
						
			// If the cleanup needs to be run again
			if ($currentTimestamp >= $cleanupWaitTimestamp)
			{
				// Cleanup messages that have been read by everyone in the group				
				$cleanupReadMessages = $this->cleanupReadMessages();
				
				// Cleanup old nonces that are no longer inside the time window
				$cleanupOldNonces = $this->cleanupOldNonces($currentTimestamp);
				
				// Update the last time the cleanup was run
				$updatedLastCleanupTime = $this->updateLastCleanupTime($currentTimestamp);
				
				// Check if cleanup was run successfully
				if ($cleanupReadMessages && $cleanupOldNonces && $updatedLastCleanupTime)
				{
					return true;
				}
			}
		}
		
		// Cleanup not run
		return false;
	}
	
	/**
	 * Updates the database with when the cleanup was last run
	 * @param integer $currentTimestamp
	 * @return boolean
	 */
	public function updateLastCleanupTime($currentTimestamp)
	{
		// Run the query
		$result = $this->db->update('UPDATE settings SET cleanup_last_run = ' . $currentTimestamp);
				
		// If the query failed
		if ($result === 1)
		{
			return true;
		}
		
		return false;
	}
	
	/**
	 * Removes read messages from the database if everyone in the group has read the message.
	 * It does this by reading the read_by_alpha, read_by_bravo etc flags in the row to see if the user has retrieved them.
	 * @return boolean Whether the query ran successfully or not
	 */
	public function cleanupReadMessages()
	{
		// Start delete query
		$query = 'DELETE FROM messages WHERE ';

		// Build remainder of query
		for ($i = 0, $numOfUsers = count($this->users); $i < $numOfUsers; $i++)
		{
			// Check the read flag for each user
			$query .= 'read_by_' . $this->users[$i] . ' = 1';

			// If there are more users continue adding to query
			if ($i < $numOfUsers - 1)
			{
				$query .= ' AND ';
			}
		}
				
		// Run delete query
		$result = $this->db->update($query);
		
		// If query failed return false
		if ($result === false)
		{
			return false;
		}
		
		// Success
		return true;
	}
	
	/**
	 * Removes old nonces that are no longer inside the acceptable timestamp window
	 * @param integer $currentTimestamp The current timestamp
	 */
	public function cleanupOldNonces($currentTimestamp)
	{		
		// Any nonces older than this timestamp get removed
		$oldestAllowedTimestamp = $currentTimestamp - $this->nonceExpiryTime;
		
		// Cleanup old nonces
		$query = 'DELETE FROM nonces WHERE nonce_sent_timestamp <= :oldest_allowed_timestamp';
		$params = array(
			'oldest_allowed_timestamp' => $oldestAllowedTimestamp
		);

		// Execute the query
		$result = $this->db->preparedUpdate($query, $params);
				
		// If the query failed then return false. Don't check for number of rows deleted 
		// because sometimes there may not be any nonces to delete from the database.
		if ($result === false)
		{
			return false;
		}
		
		// Otherwise success
		return true;
	}
	
	/**
	 * Validates the API action that the user wanted to do matches what is in the data packet
	 * @param string $apiAction
	 * @param boolean Whether the API request from the client is valid or not
	 */
	public function validateApiAction($apiAction)
	{
		// If the action is not in the whitelist
		if (in_array($apiAction, $this->apiActions, true) === false)
		{
			// Invalid action
			return false;
		}
		
		// Valid
		return true;
	}
	
	/**
	 * Adds the sent nonce to the database so it can't be reused again with the allowed time window
	 * @param string $nonce A unique 512 bit nonce (as 128 hexadecimal symbols) sent from the client per request
	 * @param integer $sentTimestamp What time the data packet was sent by the client
	 * @return boolean Whether the nonce was added to the database or not
	 */
	public function addSentNonceToDatabase($nonce, $sentTimestamp)
	{
		// Add the nonce to the database so we know it has been used, the timestamp is used by the cleanup process to remove old nonces
		$query = 'INSERT INTO nonces (nonce_sent_timestamp, nonce) VALUES (:nonce_sent_timestamp, :nonce)';
		$params = array(
			'nonce_sent_timestamp' => $sentTimestamp,
			'nonce' => $nonce
		);
		
		// Execute the query
		$result = $this->db->preparedUpdate($query, $params);
		
		// Check if failed to add
		if (($result === false) || ($this->db->getNumRows() < 1))
		{			
			return false;
		}
		
		// Success
		return true;
	}
	
	/**
	 * Validates the received nonce against nonces that have already been sent. The nonce is 
	 * used to reject duplicate messages/replay attacks received within same timestamp window. 
	 * Sent nonces are kept on the server for 14 seconds and then discarded when the cleanup is run.
	 * A delay longer than this will obviously not be accepted due to the time delay.
	 * @param string $nonce A unique 512 bit nonce (as 128 hexadecimal symbols) sent from the client per request
	 * @return boolean Whether the nonce is valid or not
	 */
	public function validateDataNonce($nonce)
	{
		// Select the message from the database using a prepared statement
		$query = 'SELECT nonce '
		       . 'FROM nonces '
		       . 'WHERE nonce = :nonce';
		$params = array('nonce' => $nonce);
		
		// Execute the query
		$result = $this->db->preparedSelect($query, $params);
				
		// If the nonce is already in the database then this request is invalid
		if (($result === false) || ($this->db->getNumRows() >= 1))
		{
			// Nonce already exists
			return false;
		}
		
		return true;
	}
	
	/**
	 * Check that the timestamp of the data packet is within the allowed time window to prevent replay attacks
	 * @param integer $sentTimestamp What time the data packet was sent by the client
	 * @return boolean Whether the timestamp is valid or not
	 */
	public function validateDataTimestamp($sentTimestamp)
	{
		// Get the current UNIX timestamp and the allowed time window
		$currentTimestamp = time();
		$maxPastAllowedTimeVariation = ($currentTimestamp - $this->validityWindow);
		$maxFutureAllowedTimeVariation = ($currentTimestamp + $this->validityWindow);
		
		// Check the timestamp of the data is within the allowed time window
		if (($sentTimestamp < $maxPastAllowedTimeVariation) || ($sentTimestamp > $maxFutureAllowedTimeVariation))
		{
			// Not valid
			return false;
		}
		
		return true;
	}
	
	/**
	 * Validates the data packet sent from the client with the Skein-512 hash using the shared key as the key
	 * @param string $dataJson The data from the client
	 * @param string $key The server key for this user as a hexadecimal string
	 * @param string $receivedMac The MAC created by the client for the data
	 * @return boolean Whether the received request is valid or not
	 */
	public function validateDataMac($dataJson, $key, $receivedMac)
	{
		// If the MAC is not 512 bits (128 hex symbols) return error immediately
		if (strlen($receivedMac) !== 128)
		{
			return false;
		}
		
		// Calculate what the MAC received should be equal to by converting the JSON data to hexadecimal, 
		// then converting the key and JSON data to binary and calculating the MAC using Hash(K, M)
		$dataJsonHex = bin2hex($dataJson);
		$binaryKeyAndMessage = pack("H*", $key . $dataJsonHex);
		$calculatedMac = skein_hash_hex($binaryKeyAndMessage);
		
		// Calculate if the hashes match using a constant time comparison to prevent timing attacks
		return $this->constantTimeStringCompare($receivedMac, $calculatedMac);
	}
		
	/**
	 * Based on the number of active chat group users set by the user in 
	 * the configuration, add the user callsigns to the list of valid users. 
	 * The valid number of users is at least two and a maximum of seven.
	 * @param string $numberOfUsers The number of chat group users
	 * @return array Returns the valid chat group users e.g. ['alpha', 'bravo', charlie']
	 */
	public function setChatGroupUsers($numberOfUsers)
	{
		$validUsers = [];
		
		// If the user has misconfigured the number of chat group users then default to two valid users
		if ((is_int($numberOfUsers) === false) || ($numberOfUsers < 2) || ($numberOfUsers > 7))
		{
			$numberOfUsers = 2;
		}
		
		// Add the user callsigns from the whitelist to the list of active user callsigns
		for ($i = 0; $i < $numberOfUsers; $i++)
		{
			$validUsers[] = $this->userList[$i];
		}
		
		return $validUsers;
	}
	
	/**
	 * Checks the user from POST is a valid user by checking against the whitelist
	 * @param string $user The user e.g. alpha, bravo, charlie etc
	 * @return boolean
	 */
	public function validateUser($user)
	{	
		// If the user is not in the whitelist or in the group's list of active users
		if ((in_array($user, $this->userList, true) === false) || (in_array($user, $this->users) === false))
		{
			return false;
		}
		
		return true;
	}
	
	/**
	 * Test the database connection from the client
	 * @return array Response array to be sent to the client with JSON
	 */
	public function testDatabaseConnection()
	{
		// Initialise response
		$jsonResult = array(
			'success' => false,
			'statusMessage' => ''
		);

		// Get the test message from the database
		$result = $this->db->select('SELECT test_connection FROM settings WHERE test_connection = 1');

		// If the database correctly inserted the row return success
		if (($result !== false) && ($this->db->getNumRows() >= 1))
		{
			// Prepare output
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Server and database connection successful.';
		}
		else if ($result === false)
		{
			// Query failure
			$jsonResult['statusMessage'] = 'Database query failed. ' . $this->db->getErrorMsg();
		}
		else {
			// No test message in database
			$jsonResult['statusMessage'] = 'Could not find the test record in the database. ' . $this->db->getErrorMsg();
		}

		return $jsonResult;
	}
	
	/**
	 * Saves the message to the database. The other user can check the database and retrieve the message.
	 * @param string $from Which user the message is from e.g. alpha, bravo etc
	 * @param string $message The encrypted message and MAC concatenated together
	 * @return array The JSON response params to send to the client
	 */
	public function saveMessageToDatabase($from, $message)
	{
		// Insert the message into the database using a prepared statement
		$readByUser = 'read_by_' . $from;
		$query = 'INSERT INTO messages (from_user, message, ' . $readByUser . ') VALUES (:from_user, :message, :' . $readByUser . ')';
		$params = array(
			'from_user' => $from,
			'message' => $message,
			$readByUser => 1
		);
		
		// Execute the query
		$result = $this->db->preparedUpdate($query, $params);
						
		// If the database correctly inserted the row return success
		if (($result !== false) && ($this->db->getNumRows() === 1))
		{
			// Message saved successfully
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Sent';
		}
		else {
			// Insert failed
			$jsonResult['success'] = false;
			$jsonResult['statusMessage'] = 'Database insert failed. ' . $this->db->getErrorMsg();
		}
		
		return $jsonResult;
	}
	
	/**
	 * Get messages from the database for a user
	 * @param string $requestFrom Who the request is from that is asking for new messages
	 * @return array Returns an array of parameters for the response
	 */
	public function getMessagesForUser($requestFrom)
	{
		// Select the message from the database using a prepared statement
		$query = 'SELECT message_id, from_user, message '
		       . 'FROM messages '
		       . 'WHERE from_user != :from_user AND read_by_' . $requestFrom . ' != 1';
		$params = array(
			'from_user' => $requestFrom
		);

		// Execute the query
		$result = $this->db->preparedSelect($query, $params);
		
		// Initialise response
		$jsonResult = array(
			'success' => false,
			'statusMessage' => ''
		);
		
		// If the database correctly selected the row/s
		if (($result !== false) && ($this->db->getNumRows() >= 1))
		{
			$messages = array();
			$transactionQueries = array();

			// Format the database results into an array of messages		
			foreach($result as $val)
			{
				// Set params to send back
				$messageData = array(
					'from' => $val['from_user'],
					'msg' => $val['message']
				);

				// Add message to array of messages
				array_push($messages, $messageData);

				// Create a new query to update the messages on the server now that they have been retrieved by that user
				$deleteSql = 'UPDATE messages SET read_by_' . $requestFrom . ' = 1 WHERE message_id = :message_id';
				$params = array('message_id' => $val['message_id']);
				$query = new Query($deleteSql, $params);

				// Add to list of queries to run in the transaction
				array_push($transactionQueries, $query);
			}

			// Update the messages from the database in a transaction
			$this->db->preparedTransaction($transactionQueries);

			// Prepare output
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Messages received successfully.';
			$jsonResult['messages'] = $messages;
		}
		else if ($result === false)
		{
			// Query failure
			$jsonResult['statusMessage'] = 'Database query failed. ' . $this->db->getErrorMsg();
		}
		else {
			// No messages for the user
			$jsonResult['statusMessage'] = 'No messages in database.';
		}
		
		return $jsonResult;
	}
	
	/**
	 * Generates a random 512 bit nonce (this method is used for unit testing purposes only)
	 * @return string Returns a random string of 128 hexadecimal symbols (512 bits) in length
	 */
	public function generateNonce()
	{		
		// Get 64 random bytes and convert them to hexadecimal
		$cryptoStrong = null;
		$randomBytes = openssl_random_pseudo_bytes(64, $cryptoStrong);
		
		// Convert the bytes to hexadecimal
		$randomBytesHexHashed = hash('whirlpool', $randomBytes);
		
		// The openssl_random_pseudo_bytes function returns a flag saying whether the bytes 
		// were generated with a CSPRNG or not. This can be checked with the unit tests
		return array(
			'nonce' => $randomBytesHexHashed,
			'cryptoStrong' => $cryptoStrong
		);
	}
		
	/**
	 * Output a 404 Not Found error. If attackers fail any part of the authentication protocol 
	 * it will send a 404 error meaning it can't find the file. This means an attacker won't 
	 * know if the file is actually there or not. The error message is only displayed in debug 
	 * mode which needs to be manually enabled.
	 * @param string $headerErrorMessage The real error to be displayed only in debug/testing mode
	 */
	public function outputErrorResponse($headerErrorMessage)
	{
		// Common headers
		header('Access-Control-Allow-Origin: *');
		
		// If in debug mode, show the real error response in the header
		if ($this->applicationConfig['testResponseHeaders'] === true)
		{
			header('HTTP/1.1 404 ' . $headerErrorMessage);
			exit;
		}
		else {
			// Otherwise in production normally just output a 404 error and stop execution
			header('HTTP/1.1 404 Not Found');
			exit;
		}
	}
	
	/**
	 * Output the data for the client to parse. The response is authenticated by a MAC using Skein-512 hash 
	 * and the user's key to ensure no-one can impersonate the server responses without the correct key. 
	 * A random 512 bit nonce and timestamp help prevent duplicate messages/replay attacks.
	 */
	public function outputJson($jsonResult)
	{
		// Set JSON and CORS headers to allow JavaScript on the client to make XMLHttpRequests to the server
		// https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
		header('Access-Control-Allow-Origin: *');
		header('Access-Control-Allow-Methods: POST');
		header('Content-Type: text/plain');
		
		// Convert data to JSON so it can be authenticated all at once
		$responseDataJson = json_encode($jsonResult);
		
		// MAC the response. The user's request MAC is included in the MAC response so an 
		// attacker cannot respond to one request with a different response that the server made
		$responseMac = $this->createMac($this->serverKey, $responseDataJson, $this->validatedRequestMac);
				
		// Encode to Base64
		$response = base64_encode($responseDataJson . $responseMac);
		
		// Output the response as plain Base64 string
		echo $response;
		exit;
	}
		
	/**
	 * Create a MAC for the response back to the client using Skein-512 hash algorithm
	 * @param string $data The data to be sent back in the response
	 * @param string $key The server key for this user as a hexadecimal string
	 * @return string Returns a 512 bit hash digest in hexadecimal
	 */
	public function createMac($serverKey, $responseDataJson, $requestMac)
	{
		// Convert the JSON to hexadecimal before hashing
		$responseDataJsonHex = bin2hex($responseDataJson);
		
		// Convert to binary
		$binaryKeyAndData = pack("H*", $serverKey . $responseDataJsonHex . $requestMac);
		
		// Perform the MAC in format Hash(K, M)
		$mac = skein_hash_hex($binaryKeyAndData);
		
		return $mac;
	}
		
	/**
	 * Compare two strings to see if they match and prevent timing attacks. This uses the idea described here:
	 * https://www.isecpartners.com/blog/2011/february/double-hmac-verification.aspx
	 * @param string $stringA
	 * @param string $stringB
	 * @return boolean Returns true if the strings match, false if not
	 */
	public function constantTimeStringCompare($stringA, $stringB)
	{
		// Return false early if the strings are not the same length.
		// The length is not secret so no weakness in failing fast here
		if (strlen($stringA) !== strlen($stringB))
		{
			return false;
		}
		
		// Convert to binary
		$binaryKeyAndStringA = pack("H*", $this->serverKey . $stringA);
		$binaryKeyAndStringB = pack("H*", $this->serverKey . $stringB);
		
		// Perform a hash using skein-512 to randomise the byte order of the strings. This prevents a 
		// timing attack when an attacker submits arbitrary data to the server to guess the server key.
		// Skein is a secure MAC in the format Hash(K, M) so does not need HMAC. 
		$hashStringA = skein_hash_hex($binaryKeyAndStringA);
		$hashStringB = skein_hash_hex($binaryKeyAndStringB);
		
		// Compare the strings normally
		return ($hashStringA === $hashStringB);
	}
}