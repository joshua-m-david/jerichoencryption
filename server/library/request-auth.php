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


namespace Jericho;

use Jericho\Converter;
use Jericho\CommonConstants;
use Jericho\Database;
use Jericho\NetworkCipher;

use \Exception;


/**
 * Request authentication functionality
 */
class RequestAuth
{
	/**
	 * @var Database The Database object which allows database operations
	 */
	private $db;

	/**
	 * @var Converter The common conversion functions for conversion etc
	 */
	private $converter;

	/**
	 * @var NetworkCipher The encryption and decryption helper functions
	 */
	private $networkCipher;

	/**
	 * Constructor takes the initialised helper objects using dependency injection
	 * @param Database $db The database object (not actually connected to DB yet)
	 * @param Converter $converter The common conversion functions
	 * @param NetworkCipher $networkCipher The encryption and decryption helper functions
	 */
	public function __construct($db, $converter, $networkCipher)
	{
		$this->db = $db;
		$this->converter = $converter;
		$this->networkCipher = $networkCipher;
	}

	/**
	 * Checks if the request from the client is valid by using the authentication protocol. The goals of which are:
	 *  - Authenticate all API requests to the server to verify they are from a legitimate user.
	 *  - Authenticate all API responses from the server to verify the response came from the legitimate server not an
	 *    attacker.
	 *  - Disallow a user of one group to spoof another user's requests from another group to the server.
	 *  - Avert passive MITM attacks where an attacker tries to snoop the API credentials in transit.
	 *  - Avert active MITM attacks where an attacker attempts to send fake requests to the server or impersonate the
	 *    server responses.
	 *  - Avert replay attacks and reject a request/response if the MAC does not match.
	 *  - Prevent one request to the server being replayed with a different action being performed by the attacker.
	 *  - Encrypt all metadata and data so that the only information going to and from the server appears to be
	 *    random data and useless for a network observer.
	 *
	 * @param array $groupConfigs Configuration settings for each chat group
	 * @param string $rawPostBodyDataBase64 The raw request data from the body of the POST request as a Base64 string
	 * @param int $currentTimestamp The current UNIX timestamp as calculated by the server
	 * @return ValidatedRequest Returns the result of the validation
	 */
	public function performClientRequestAuthenticationAndDecryption($groupConfigs, $rawPostBodyDataBase64, $currentTimestamp)
	{
		// Check the length of the Base64 string is in expected range
		if ($this->validateRequestLength($rawPostBodyDataBase64) === false)
		{
			// Error message responses are only output in debug mode, not in production
			return new ValidatedRequest(false, 'Request is not a valid length.');
		}


		// Validate and decode the Base64 data to binary
		$dataBinary = $this->validateAndDecodeBase64($rawPostBodyDataBase64);

		// If the data is invalid return an error response
		if ($dataBinary === false)
		{
			return new ValidatedRequest(false, 'Request contains malformed Base64 data.');
		}


		// Validate and decode the binary data to hexadecimal and parse the parts
		$dataHex = $this->encodeBinaryToHexAndValidate($dataBinary);

		// If the hex data is invalid return an error response
		if ($dataHex === false)
		{
			return new ValidatedRequest(false, 'Request contains malformed hexadecimal data.');
		}


		// Parse the hexadecimal data to get the nonce
		$nonceHex = $this->parseNonceFromHex($dataHex);

		// If the nonce is invalid return an error response
		if ($nonceHex === false)
		{
			return new ValidatedRequest(false, 'Request nonce could not be found or parsed.');
		}


		// Parse the hexadecimal data to get the MAC
		$macHex = $this->parseMacFromHex($dataHex);

		// If the MAC is invalid return an error response
		if ($macHex === false)
		{
			return new ValidatedRequest(false, 'Request MAC could not be found or parsed.');
		}


		// Parse the hexadecimal data to get the ciphertext (encrypted data)
		$ciphertextHex = $this->parseCiphertextFromHex($dataHex);

		// If the ciphertext is invalid return an error response
		if ($ciphertextHex === false)
		{
			return new ValidatedRequest(false, 'Request ciphertext could not be found or parsed.');
		}


		// Find the group configuration for this message and encryption key by validating the
		// request with different group keys to find out which key produces a correct MAC
		$currentGroupConfig = $this->findGroupByMacValidation(
			$groupConfigs, $nonceHex, $ciphertextHex, $macHex, $currentTimestamp
		);

		// If the MAC is invalid for any group return an error response
		if ($currentGroupConfig === false)
		{
			return new ValidatedRequest(false, 'Chat group not found, request MAC is invalid or request data altered.');
		}


		// Decrypt the payload data
		$derivedEncryptionKeyHex = $currentGroupConfig['derivedEncryptionKey'];
		$decryptedPayloadHex = $this->networkCipher->encryptOrDecryptPayload($derivedEncryptionKeyHex, $nonceHex, $ciphertextHex);


		// Get the UNIX timestamp from the serialised payload
		$payloadSentTimestamp = $this->getTimestampFromPlaintextPayload($decryptedPayloadHex);

		// Check if timestamp is invalid (last check before needing to hit the database to check if the nonce is valid)
		$validTimestamp = $this->validatePayloadTimestamp($payloadSentTimestamp, $currentTimestamp);

		// If the timestamp is invalid this could indicate the message was intentionally delayed or replayed so return an error response
		if ($validTimestamp === false)
		{
			return new ValidatedRequest(false, 'Invalid sent timestamp in request, sync client and system clocks with NTP.');
		}

		// Update the database name so it can connect to the database for that group
		$this->db->updateConfigDatabaseName($currentGroupConfig['groupDatabaseName']);

		// Connect to the database after the timestamp validated as we will need to check nonces etc
		$connectionSuccess = $this->connectToDatabase();

		// If the connect fails then return an error response
		if ($connectionSuccess === false)
		{
			return new ValidatedRequest(false, 'Database connection failed, check your configuration. ' . $this->db->getErrorMsg());
		}


		// Check if the nonce is valid
		$nonceValid = $this->validateDataNonce($nonceHex);

		// If the nonce is invalid this could indicate a replay attack so return an error response
		if ($nonceValid === false)
		{
			return new ValidatedRequest(false, 'Invalid nonce in request.');
		}


		// Add the sent nonce to the database so it can't be reused again within the current time interval
		$nonceAdded = $this->addSentNonceToDatabase($nonceHex, $currentTimestamp);

		// If the nonce failed to be saved to the database, return an error response
		if ($nonceAdded === false)
		{
			return new ValidatedRequest(false, 'Sent nonce could not be added to the database.');
		}


		// Get the API Action from the payload, which will also help decide whether to
		// continue looking for message packets or not in the request.
		$apiAction = $this->getApiActionFromPlaintextPayload($decryptedPayloadHex);
		$apiActionValidated = $this->validateApiAction($apiAction);

		// If the API Action was not valid, return an error response
		if ($apiActionValidated === false)
		{
			return new ValidatedRequest(false, 'Invalid API Action in request.');
		}


		// Get the From User (who sent the packet)
		$fromUser = $this->getFromUserFromPlaintextPayload($decryptedPayloadHex);

		// Get the valid chat group users
		$numOfUsersInGroup = $currentGroupConfig['groupNumberOfUsers'];
		$validChatGroupUsers = $this->getChatGroupUsers($numOfUsersInGroup);

		// Validate if the From User is in the list of valid group users
		$fromUserValidated = $this->validateUser($fromUser, $validChatGroupUsers);

		// If the user is invalid return an error response
		if ($fromUserValidated === false)
		{
			return new ValidatedRequest(false, 'Invalid request user.');
		}


		// Initialise Message Packets to empty array for 'receive' and 'test' API Action requests
		$messagePackets = [];

		// Check if there are messages being sent, otherwise don't worry about parsing messages
		if ($apiAction === CommonConstants::API_ACTION_SEND)
		{
			// Get the Message Packets from the payload
			$messagePackets = $this->getMessagesFromPlaintextPayload($decryptedPayloadHex);

			// If the Message Packets could not be parsed correctly, return an error response
			if ($messagePackets === false)
			{
				return new ValidatedRequest(false, 'Invalid length message packet or packets.');
			}
		}

		// Prepare success response
		$success = true;
		$errorMessage = '';

		// Request has been validated, set values to be used when processing the API action
		return new ValidatedRequest(
			$success,
			$errorMessage,
			$apiAction,
			$fromUser,
			$messagePackets,
			$currentGroupConfig,
			$macHex
		);
	}

	/**
	 * Checks to make sure the raw request data is at least the size of the minimum valid request size and does not
	 * exceed the maximum length. This is used to quickly throw away invalid requests and mitigate a potential DOS
	 * attack which could make the server do lots of request validation/computation at once. Without this, an
	 * attacker could potentially send lots of requests and force the server to do a computationally expensive task
	 * (e.g. hashing for the MAC) on large data to authenticate multiple requests which would slow the server.
	 * @param string $rawPostBodyDataBase64 The raw POST body data, presumed to be in Base64 for a valid request
	 * @return boolean Returns false if the length is not in the expected range or some error occurred
	 */
	public function validateRequestLength($rawPostBodyDataBase64)
	{
		// Use try/catch block to fail if the raw data is something unexpected
		try {
			// Check if the data is a string
			if (!is_string($rawPostBodyDataBase64))
			{
				return false;
			}

			// Get the length of the Base64 string
			$dataLengthInBase64 = strlen($rawPostBodyDataBase64);

			// Convert the minimum valid request bit length (constant) to the Base64 length for comparison
			$minValidLengthInBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::REQUEST_MIN_VALID_BITS_LENGTH);
			$minValidLengthInBase64 = $this->converter->convertNumOfBytesToNumOfBase64Chars($minValidLengthInBytes);

			// Convert the maximum valid request bit length (constant) to the Base64 length for comparison
			$maxValidLengthInBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::REQUEST_MAX_VALID_BITS_LENGTH);
			$maxValidLengthInBase64 = $this->converter->convertNumOfBytesToNumOfBase64Chars($maxValidLengthInBytes);

			// Check the length is in the expected range
			if ($dataLengthInBase64 < $minValidLengthInBase64 || $dataLengthInBase64 > $maxValidLengthInBase64)
			{
				return false;
			}

			return true;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}


	/**
	 * Connects to the database
	 * @return boolean Returns true if the database connected successfully, or false if not
	 */
	public function connectToDatabase()
	{
		return $this->db->connect();
	}

	/**
	 * Validates and decodes the raw Base64 data that was sent in the request. This is the first line of defense
	 * and we don't want some malicious input to cause some unexpected exception or buffer overflow exploit which
	 * could reveal server secrets or crash the server.
	 * @param string $rawDataBase64 The Base64 request data
	 * @return string|false Returns the decoded Base64 string as binary data, or false if the Base64 is invalid
	 */
	public function validateAndDecodeBase64($rawDataBase64)
	{
		// Use try/catch block to fail on any unexpected or malformed data
		try {
			// Checks for any characters that are not valid Base64 characters
			$containsValidBase64Chars = (bool) preg_match('/^[a-zA-Z0-9\/+]*={0,2}$/', $rawDataBase64);

			// If the chars are invalid, return failure
			if ($containsValidBase64Chars === false)
			{
				return false;
			}

			// Decode the data from Base64 (uses strict mode but it's not infallible)
			$decodedDataBinary = base64_decode($rawDataBase64, true);

			// If it failed to decode, return failure
			if ($decodedDataBinary === false)
			{
				return false;
			}

			return $decodedDataBinary;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}

	/**
	 * Converts the request binary data to a hexadecimal string and validates the encoded result
	 * @param string $dataBinary The request data decoded from Base64 in binary format
	 * @return string|false Returns the data as a hexadecimal string, or false on failure
	 */
	public function encodeBinaryToHexAndValidate($dataBinary)
	{
		// Use try/catch block to fail if decoding doesn't work
		try {
			// Convert the binary data into hexadecimal
			$dataHex = bin2hex($dataBinary);

			// Check if the string contains chars outside of 0-9, a-f
			if (!ctype_xdigit($dataHex))
			{
				return false;
			}

			// Check the string is an even number of hex symbols (full bytes)
			if (strlen($dataHex) % 2 !== 0)
			{
				return false;
			}

			return $dataHex;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}

	/**
	 * Get the request nonce from the hexadecimal data string. The request sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param string $dataHex The request data encoded in hexadecimal format
	 * @return string|false Returns the nonce as a hexadecimal string, or false on failure
	 */
	public function parseNonceFromHex($dataHex)
	{
		try {
			// Get the nonce portion (first 64 bytes)
			$nonceIndexStart = 0;
			$nonceHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_NONCE_BITS_LENGTH);
			$nonceHex = substr($dataHex, $nonceIndexStart, $nonceHexLength);

			// Check if the parsed nonce is the correct length
			if ($nonceHex === false || (strlen($nonceHex) !== $nonceHexLength))
			{
				return false;
			}

			return $nonceHex;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}

	/**
	 * Get the request MAC digest from the hexadecimal data string. The request sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param string $dataHex The request data encoded in hexadecimal format
	 * @return string|false Returns the MAC as a hexadecimal string, or false on failure
	 */
	public function parseMacFromHex($dataHex)
	{
		try {
			// Get the total data length and MAC length in hexadecimal symbols
			$dataLength = strlen($dataHex);
			$macHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_MAC_BITS_LENGTH);

			// Get the MAC portion (end 64 bytes)
			$macIndexStart = $dataLength - $macHexLength;
			$maxHex = substr($dataHex, $macIndexStart, $macHexLength);

			// Check if the parsed MAC is the correct length
			if ($maxHex === false || (strlen($maxHex) !== $macHexLength))
			{
				return false;
			}

			return $maxHex;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}

	/**
	 * Get the request ciphertext data from the hexadecimal data string. The request sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param string $dataHex The request data encoded in hexadecimal format
	 * @return string|false Returns the ciphertext as a hexadecimal string, or false on failure
	 */
	public function parseCiphertextFromHex($dataHex)
	{
		try {
			// Get the data length, nonce length and MAC length in hexadecimal symbols
			$dataLength = strlen($dataHex);
			$nonceHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_NONCE_BITS_LENGTH);
			$macHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_MAC_BITS_LENGTH);
			$ciphertextHexLength = $dataLength - $nonceHexLength - $macHexLength;

			// Get the encrypted data portion (variable length bytes in the middle)
			$ciphertextIndexStart = $nonceHexLength;
			$ciphertextHex = substr($dataHex, $ciphertextIndexStart, $ciphertextHexLength);
			$actualCiphertextLength = strlen($ciphertextHex);

			// Convert length in bits to length in hexadecimal symbols
			$minCiphertextHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_MIN_CIPHERTEXT_BITS_LENGTH);
			$maxCiphertextHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_MAX_CIPHERTEXT_BITS_LENGTH);

			// Check if the encrypted data is between the minimum and maximum length
			if ($ciphertextHex === false || ($actualCiphertextLength < $minCiphertextHexLength) || ($actualCiphertextLength > $maxCiphertextHexLength))
			{
				return false;
			}

			// Check if the ciphertext length is an odd number of bytes (must be even to allow for successful decryption)
			if ($actualCiphertextLength % 2 !== 0)
			{
				return false;
			}

			return $ciphertextHex;
		}
		catch (Exception $exception)
		{
			return false;
		}
	}

	/**
	 * Derives an encryption and MAC key from the server key. The method it uses is similar to KDF1 and
	 * KDF2 where the master key is hashed with a counter e.g. Hash(Server Key || 32 bit counter).
	 * @param string serverKeyHex The server key (512 bits) as a hexadecimal string
	 * @return array Returns array with key names 'encryptionKey' and 'macKey' (both are 512 bit keys in hex)
	 */
	public function deriveEncryptionAndMacKeys($serverKeyHex)
	{
		// Set the 32 bit counters for encryption and MAC in hexadecimal
		$encryptionKeyCounterHex = '00000000';
		$macKeyCounterHex = '00000001';

		// Convert the server key and counters concatenated together from hexadecimal to binary
		$encryptionHashDataBinary = $this->converter->convertHexToBinaryData($serverKeyHex . $encryptionKeyCounterHex);
		$macHashDataBinary = $this->converter->convertHexToBinaryData($serverKeyHex . $macKeyCounterHex);

		// Derive Encryption and MAC keys
		$encryptionKeyHex = skein_hash_hex($encryptionHashDataBinary);
		$macKeyHex = skein_hash_hex($macHashDataBinary);

		return [
			'encryptionKey' => $encryptionKeyHex,
			'macKey' => $macKeyHex
		];
	}

	/**
	 * Serialises the payload for MAC which includes the timestamp (closest x minutes)
	 * @param string nonceHex The nonce (512 bits) as a hexadecimal string
	 * @param string encryptedPayloadHex The encrypted network payload as a hexadecimal string
	 * @param string groupIdentifierHex The group identifier (64 bits) as a hexadecimal string
	 * @return string Returns the serialised data ready to be authenticated with the MAC (as a hexadecimal string) in
	 *                 canonical order: group id || nonce || timestamp interval || encrypted payload
	 */
	public function serialiseDataForAuthentication($nonceHex, $encryptedPayloadHex, $groupIdentifierHex)
	{

		// Serialise into canonical order for MAC
		$serialisedDataHex = $groupIdentifierHex
		                   . $nonceHex
		                   . $encryptedPayloadHex;

		return $serialisedDataHex;
	}

	/**
	 * Compare two strings to see if they match and prevent timing attacks. This uses the idea described here:
	 * https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy
	 * @param string $stringA The first string to compare
	 * @param string $stringB The second string to compare
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

		// Get a random 512 bits from /dev/urandom to use as the MAC key
		$randomKeyBytes = random_bytes(64);
		$randomKeyBytesHex = bin2hex($randomKeyBytes);

		// Convert to binary
		$binaryKeyAndStringA = $this->converter->convertHexToBinaryData($randomKeyBytesHex . $stringA);
		$binaryKeyAndStringB = $this->converter->convertHexToBinaryData($randomKeyBytesHex . $stringB);

		// Perform a hash using skein-512 to randomise the byte order of the strings. This prevents a timing attack
		// when an attacker submits arbitrary data to the server to guess the server key. Skein is a secure MAC in the
		// format Hash(K || M) so does not need HMAC. One hash invocation is also faster than two with HMAC.
		$hashStringA = skein_hash_hex($binaryKeyAndStringA);
		$hashStringB = skein_hash_hex($binaryKeyAndStringB);

		// Compare the strings normally
		return ($hashStringA === $hashStringB);
	}

	/**
	 * Validates the raw data packet sent from the client with the Skein-512 hash using the shared key as the key
	 * @param string $dataHex The hexadecimal data to be authenticated (i.e. already concatenated in canonical order)
	 * @param string $keyHex The server key for this user as a hexadecimal string
	 * @param string $receivedMacHex The MAC created by the client for the data
	 * @return boolean Whether the received request is valid or not
	 */
	public function validateDataMac($dataHex, $keyHex, $receivedMacHex)
	{
		// Convert the key and data from hexadecimal to binary
		$binaryKeyAndData = $this->converter->convertHexToBinaryData($keyHex . $dataHex);

		// Calculate the MAC using Hash(K || M). Skein is a secure MAC in the format Hash(K || M) so does not need HMAC
		$calculatedMacHex = skein_hash_hex($binaryKeyAndData);

		// Calculate if the hashes match using a constant time comparison to prevent timing attacks
		return $this->constantTimeStringCompare($receivedMacHex, $calculatedMacHex);
	}

	/**
	 * Finds the chat group corresponding to the message sent by trying each group key against the sent MAC
	 * @param array $groupConfigs The group configs as an array loaded from config.json
	 * @param string $nonceHex The request nonce as a hexadecimal string
	 * @param string $ciphertextHex The request ciphertext as a hexadecimal string
	 * @param string $macHex The request MAC as a hexadecimal string
	 * @return array|false Returns the detected current group config with additional keys 'derivedEncryptionKey' and
	 *                     'derivedMacKey', or false if it could not find the group
	 */
	public function findGroupByMacValidation($groupConfigs, $nonceHex, $ciphertextHex, $macHex)
	{
		$currentGroupConfig = false;

		// Try different groups to find the group the message is for
		foreach ($groupConfigs as $groupConfig)
		{
			// Get group identifier (64 bits) and the group server key (512 bits)
			$groupIdentifierHex = $groupConfig['groupId'];
            $groupServerKeyHex = $groupConfig['groupServerKey'];

			// Serialise the data to be authenticated
			$serialisedDataHex = $this->serialiseDataForAuthentication(
				$nonceHex, $ciphertextHex, $groupIdentifierHex
			);

			// Derive encryption and MAC keys from the group server key. Maybe it is faster to just store the
			// encryption and MAC keys separately in config to avoid this calculation, but certainly it is not
			// easier to copy 2 keys to the client instead of one for the server config, so 1 key is preferred.
			$derivedKeys = $this->deriveEncryptionAndMacKeys($groupServerKeyHex);
			$derivedEncryptionKeyHex = $derivedKeys['encryptionKey'];
			$derivedMacKeyHex = $derivedKeys['macKey'];

			// Validate the data and MAC received against the server computed MAC to see if the request is valid
			$validMac = $this->validateDataMac($serialisedDataHex, $derivedMacKeyHex, $macHex);

			// If the MAC was valid for a group
			if ($validMac)
			{
				// Save the group config and derived keys to avoid re-computation
				$currentGroupConfig = $groupConfig;
				$currentGroupConfig['derivedEncryptionKey'] = $derivedEncryptionKeyHex;
				$currentGroupConfig['derivedMacKey'] = $derivedMacKeyHex;

				// Break out of the loop early to save further computation
				break;
			}
		}

		return $currentGroupConfig;
	}

	/**
	 * Gets the UNIX timestamp from the hexadecimal string plaintext payload, the serialised format being:
	 *
	 * Padding Length in bytes (2 bytes) ||
	 * Padding (variable bytes) ||
	 * Message Packets (variable bytes) ||
	 * Current UNIX Timestamp (5 bytes) ||
	 * From User (1 byte) ||
	 * API Action (1 byte)
	 *
	 * @param string $decryptedPayloadHex The serialised plaintext payload as a hexadecimal string
	 * @return int Returns the UNIX timestamp as an integer
	 */
	public function getTimestampFromPlaintextPayload($decryptedPayloadHex)
	{
		// Get start index of the message packets portion and the fixed length portions
		$timestampLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_TIMESTAMP_BITS_LENGTH);
		$fromUserLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::FROM_USER_BITS_LENGTH);
		$apiActionLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_API_ACTION_BITS_LENGTH);

		// Find the start of the timestamp by removing the lengths of the Timestamp, From User and API Action
		$lengthOfHexPayload = strlen($decryptedPayloadHex);
		$startOfTimestampIndex = $lengthOfHexPayload - $timestampLengthInHex - $fromUserLengthInHex - $apiActionLengthInHex;

		// Get just the timestamp in hexadecimal
		$timestampHex = substr($decryptedPayloadHex, $startOfTimestampIndex, $timestampLengthInHex);

		// Convert to an integer UNIX timestamp which will remove any padding at the front
		$timestamp = $this->converter->convertHexToInt($timestampHex);

		return $timestamp;
	}

	/**
	 * This checks that the timestamp of the data packet is within the allowed time window to prevent replay attacks.
	 * The aim is to have a good buffer here to account for any time synchronisation differences between the client and
	 * real NTP time and also the server and NTP time. Either could be minutes out of sync. The server will be
	 * reasonably accepting and will accept a request 5 minutes older than the time it currently thinks it is, NB: it
	 * should be syncing daily to an NTP server in the installation script cron. This will also accept a request 5
	 * minutes into the future. The 10 minute window is no security risk as we store the nonce for this request in the
	 * database for an hour so the packet cannot be replayed.
	 *
	 * @param int $payloadSentTimestamp The UNIX timestamp of when the data packet was encrypted and sent by the client
	 * @param int $currentTimestamp The current UNIX timestamp to compare against
	 * @return boolean Whether the timestamp is valid or not
	 */
	public function validatePayloadTimestamp($payloadSentTimestamp, $currentTimestamp)
	{
		// Get the allowed time window
		$maxPastAllowedTimeVariation = ($currentTimestamp - CommonConstants::REQUEST_VALID_WINDOW_SECONDS);
		$maxFutureAllowedTimeVariation = ($currentTimestamp + CommonConstants::REQUEST_VALID_WINDOW_SECONDS);

		// Check the timestamp of the data is within the allowed time window
		if (($payloadSentTimestamp < $maxPastAllowedTimeVariation) || ($payloadSentTimestamp > $maxFutureAllowedTimeVariation))
		{
			// Not valid
			return false;
		}

		return true;
	}

	/**
	 * Validates the received nonce against nonces that have already been sent. The nonce is used to reject duplicate
	 * messages/replay attacks received within same timestamp interval. Sent nonces are kept on the server for 1 hour
	 * and then discarded when the cleanup is run. A delay longer than this will not be accepted due to the time delay.
	 * @param string $nonceHex A unique 512 bit nonce (as 128 hexadecimal symbols) sent from the client each request
	 * @return bool Returns true if the nonce is valid (not found in the database), or false if not valid (it was
	 *              found in the database, indicating a replay/duplicate)
	 */
	public function validateDataNonce($nonceHex)
	{
		// Select the message from the database using a prepared statement
		$query = 'SELECT nonce '
		       . 'FROM nonces '
		       . 'WHERE nonce = :nonce';
		$params = array('nonce' => $nonceHex);

		// Execute the query
		$result = $this->db->preparedSelect($query, $params);

		// If the nonce is already in the database then this request is invalid
		if (($result === false) || ($this->db->getNumRows() >= 1))
		{
			return false;
		}

		return true;
	}

	/**
	 * Adds the sent nonce to the database so it can't be reused again with the allowed time window
	 * @param string $nonce A unique 512 bit nonce (as 128 hexadecimal symbols) sent from the client per request
	 * @param int $sentTimestamp What time the data packet was sent by the client
	 * @return bool Whether the nonce was added to the database or not
	 */
	public function addSentNonceToDatabase($nonce, $sentTimestamp)
	{
		// Add the nonce to the database so we know it has been used. The
		// timestamp is used by the cleanup process to remove old nonces.
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
	 * Gets the API Action short code out of the plaintext payload i.e. s/r/t and converts it to the API action to be
	 * performed i.e. send/receive/test.
	 * @param string $decryptedPayloadHex The serialised plaintext payload as a hexadecimal string
	 * @return string Returns the API Action as a string i.e. send/receive/test
	 */
	public function getApiActionFromPlaintextPayload($decryptedPayloadHex)
	{
		// Find where the API Action portion of the payload starts
		$lengthOfApiActionInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_API_ACTION_BITS_LENGTH);
		$lengthOfPayload = strlen($decryptedPayloadHex);
		$startIndexOfApiAction = $lengthOfPayload - $lengthOfApiActionInHex;

		// Get the API Action and convert it to an ASCII string e.g. r,s,t (receive, send, test)
		$apiActionHex = substr($decryptedPayloadHex, $startIndexOfApiAction, $lengthOfApiActionInHex);
		$apiActionShortCode = hex2bin($apiActionHex);

		// Convert short code e.g. r/s/t to value receive/send/test
		$apiAction = CommonConstants::VALID_API_ACTIONS[$apiActionShortCode] ?? false;

		return $apiAction;
	}

	/**
	 * Validates the API action that the user wanted to do matches what is in the data packet
	 * @param string $apiAction The API Action i.e. send/receive/test
	 * @param boolean Whether the API request from the client is valid or not
	 */
	public function validateApiAction($apiAction)
	{
		// If the action is not in the whitelist
		if (in_array($apiAction, CommonConstants::VALID_API_ACTIONS, true) === false)
		{
			// Invalid action
			return false;
		}

		// Valid
		return true;
	}

	/**
	 * Gets the From User short code out of the plaintext payload (which group user sent the packet)
	 * e.g. a/b/c etc and converts it to the From User i.e. alpha/bravo/charlie etc.
	 * @param string $decryptedPayloadHex The serialised plaintext payload as a hexadecimal string
	 * @return string Returns the From User as a string i.e. alpha/bravo/charlie etc
	 */
	public function getFromUserFromPlaintextPayload($decryptedPayloadHex)
	{
		// Find where the From User portion of the payload starts
		$lengthOfApiActionInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_API_ACTION_BITS_LENGTH);
		$lengthOfFromUserInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::FROM_USER_BITS_LENGTH);
		$lengthOfPayload = strlen($decryptedPayloadHex);
		$startIndexOfFromUser = $lengthOfPayload - $lengthOfApiActionInHex - $lengthOfFromUserInHex;

		// Get the From User short code and convert it to an ASCII string e.g. a,b,c etc
		$fromUserHex = substr($decryptedPayloadHex, $startIndexOfFromUser, $lengthOfFromUserInHex);
		$fromUserShortCode = hex2bin($fromUserHex);

		// Convert short code e.g. a/b/c to alpha/bravo/charlie etc
		$fromUser = CommonConstants::VALID_USER_LIST[$fromUserShortCode] ?? false;

		return $fromUser;
	}

	/**
	 * Based on the number of active chat group users set by the user in the configuration, add the user callsigns to
	 * the list of valid users. The valid number of users is at least two and a maximum of seven.
	 * @param string $numOfUsers The number of chat group users
	 * @return array Returns the valid chat group users e.g. ['alpha', 'bravo', 'charlie']
	 */
	public function getChatGroupUsers($numOfUsers)
	{
		// If the user has misconfigured the number of chat group users then default to 2 valid users
		if ((is_int($numOfUsers) === false) || ($numOfUsers < CommonConstants::MIN_NUM_OF_USERS) || ($numOfUsers > CommonConstants::MAX_NUM_OF_USERS))
		{
			$numOfUsers = CommonConstants::MIN_NUM_OF_USERS;
		}

		// Get the possible users as a flat array e.g. ['alpha', 'bravo', 'charlie']
		// then get only the valid number of users for this chat group
		$allPossibleUsers = array_values(CommonConstants::VALID_USER_LIST);
		$validUsers = array_slice($allPossibleUsers, 0, $numOfUsers);

		return $validUsers;
	}

	/**
	 * Checks the user in the request is a valid user by checking against the valid group users
	 * @param string $user The user e.g. alpha, bravo, charlie etc
	 * @param array $validGroupUsers The valid chat group users e.g. ['alpha', 'bravo', 'charlie']
	 * @return boolean Returns true if the user is valid, false if not
	 */
	public function validateUser($user, $validGroupUsers)
	{
		// If the user is not in the group's list of valid users
		if (in_array($user, $validGroupUsers, true) === false)
		{
			return false;
		}

		return true;
	}

	/**
	 * Gets the client side encrypted Message Packets out of the serialised plaintext payload. The format being:
	 *
	 * Padding Length Identifier in bytes (2 bytes) ||
	 * Padding (variable bytes) ||
	 * Message Packets (variable bytes) ||
	 * Current UNIX Timestamp (5 bytes) ||
	 * From User (1 byte) ||
	 * API Action (1 byte)
	 *
	 * @param string $decryptedPayloadHex The serialised plaintext payload as a hexadecimal string
	 * @return array|false Returns an array of Message Packets, or false if not all could be parsed correctly
	 */
	public function getMessagesFromPlaintextPayload($decryptedPayloadHex)
	{
		// Get the hexadecimal length of the payload, Padding Length Identifier and other fixed length portions
		$lengthOfHexPayloadInHex = strlen($decryptedPayloadHex);
		$lengthOfPaddingLengthIdentifierInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::PADDING_LENGTH_IDENTIFIER_BITS_LENGTH);
		$lengthOfTimestampInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_TIMESTAMP_BITS_LENGTH);
		$lengthOfFromUserInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::FROM_USER_BITS_LENGTH);
		$lengthOfApiActionInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::REQUEST_API_ACTION_BITS_LENGTH);

		// Get the Padding Length Identifier in hexadecimal, then convert that to get the length of the padding
		$paddingLengthIdentifierHex = substr($decryptedPayloadHex, 0, $lengthOfPaddingLengthIdentifierInHex);
		$lengthOfPaddingInBytes = $this->converter->convertHexToInt($paddingLengthIdentifierHex);
		$lengthOfPaddingInHex = $this->converter->convertNumOfBytesToNumOfHexSymbols($lengthOfPaddingInBytes);

		// Calculate the length of the Message Packets portion of the payload by removing the lengths of everything else
		$lengthOfMessagePacketsPortion = $lengthOfHexPayloadInHex
		 - $lengthOfPaddingLengthIdentifierInHex
		 - $lengthOfPaddingInHex
		 - $lengthOfTimestampInHex
		 - $lengthOfFromUserInHex
		 - $lengthOfApiActionInHex;

		// Get start index of the Message Packets portion, then get the Message Packets concatenated together
		$startOfMessagePacketsIndex = $lengthOfPaddingLengthIdentifierInHex + $lengthOfPaddingInHex;
		$messagePacketsHex = substr($decryptedPayloadHex, $startOfMessagePacketsIndex, $lengthOfMessagePacketsPortion);

		// If there's no Message Package data then it failed extraction. It should be able to get at least one Message
		// Packet for a 'send' packet, otherwise the function should not have been called for 'receive' or 'test' packets.
		if ($lengthOfMessagePacketsPortion <= 0)
		{
			return false;
		}

		// Initialise store of Message Packets to empty array
		$messagePackets = [];

		// Find how many Message Packets there are concatenated together
		$messagePacketLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::MESSAGE_PACKET_BITS_LENGTH);
		$numOfMessagePackets = round($lengthOfMessagePacketsPortion / $messagePacketLengthInHex);

		// For the number of Message Packets found
		for ($i = 0, $startIndex = 0; $i < $numOfMessagePackets; $i++, $startIndex += $messagePacketLengthInHex)
		{
			// Get the Message Packet
			$messagePacket = substr($messagePacketsHex, $startIndex, $messagePacketLengthInHex);
			$messagePacketLength = strlen($messagePacket);

			// If it was not extracted from the concatenated string correctly, or the length is incorrect, then
			// return that the extraction failed, because it should be able to always get full length Message Packets
			if (($messagePacket === false) || ($messagePacketLength !== $messagePacketLengthInHex))
			{
				return false;
			}

			// Add to store
			$messagePackets[] = $messagePacket;
		}

		return $messagePackets;
	}
}