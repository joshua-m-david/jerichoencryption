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

use Jericho\CommonConstants;
use Jericho\Converter;
use Jericho\NetworkCipher;


/**
 * Response serialisation, encryption and authentication functionality
 */
class ResponseAuth
{
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
	 * @param Converter $converter The common conversion functions
	 * @param NetworkCipher $networkCipher The encryption and decryption helper functions
	 */
	public function __construct($converter, $networkCipher)
	{
		$this->converter = $converter;
		$this->networkCipher = $networkCipher;
	}


	/**
	 * Generates a random 512 bit nonce
	 * @return string Returns a random string of 128 hexadecimal symbols (512 bits) in length
	 */
	public function generateNonce()
	{
		// Get length of nonce in bytes
		$nonceLengthInBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::RESPONSE_NONCE_BITS_LENGTH);

		// Get 64 random bytes and convert them to hexadecimal
		$randomBytes = random_bytes($nonceLengthInBytes);

		// Convert from binary to hex
		$randomBytesHex = bin2hex($randomBytes);

		return $randomBytesHex;
	}

	/**
	 * Output a HTTP/1.1 200 OK header response. If attackers fail any part of the authentication protocol
	 * it will send this code, meaning it succeeded. This means an attacker won't know if they actually
	 * made a successful request or not. However the client will know if something failed because the
	 * response won't be authenticated with a valid MAC.
	 *
	 * NB: The error message in the header (instead of OK) is only displayed in debug mode which needs to be manually
	 * enabled in the group server configuration.
	 *
	 * @param string $headerErrorMessage The real error to be displayed only in debug/testing mode
	 * @param array $applicationConfig Some general application settings
	 */
	public function outputErrorResponse($headerErrorMessage, $applicationConfig)
	{
		// Set common headers
		header('Access-Control-Allow-Origin: *');

		// If in debug mode, show the real error response in the header
		if ($applicationConfig['testResponseHeaders'])
		{
			// Detect some error where no error message was included
			if (!$headerErrorMessage) {
				$headerErrorMessage = 'Error response, but no error message';
			}

			// Some errors e.g. DB errors might have new lines but these can't be added to the header so remove them
			$headerErrorMessage  = str_replace("\n", '', $headerErrorMessage);

			// Output standard 200 success header
			header("HTTP/1.1 200 $headerErrorMessage");
		}
		else {
			// Otherwise in production normally just output a 200 header
			header('HTTP/1.1 200 OK');
		}

		// Get a random number of bytes and convert them to Base64 so that an outside observer has no idea whether the
		// request was actually validated successfully or not. The length of the random data looks to be a valid length
		// with what a valid response might be.
		$randomBytes = $this->getRandomBytesForErrorResponse();
		$randomBytesBase64 = base64_encode($randomBytes);

		// Output random data to the body in Base64 then stop execution of the script
		echo $randomBytesBase64;
		exit;
	}

	/**
	 * Gets a random number of bytes for the error response, based on the minimum and maximum constants
	 * @return string Returns a string of random bytes
	 */
	public function getRandomBytesForErrorResponse()
	{
		// Get min and max from constants
		$minNumOfBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::ERROR_RESPONSE_MIN_RANDOM_BITS);
		$maxNumOfBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::ERROR_RESPONSE_MAX_RANDOM_BITS);

		// Generate a cryptographically secure psuedo-random integer in the min-max range, inclusive
		$randomInt = random_int($minNumOfBytes, $maxNumOfBytes);

		// Get random bytes (the number of bytes being based on the random number generated above)
		$randomBytes = random_bytes($randomInt);

		return $randomBytes;
	}

	/**
	 * Overall function to serialise, encrypt and authenticate the response, then finally convert it to Base64 ready to
	 * be returned to the client.
	 * @param string $encryptionKeyHex The group's derived encryption key
	 * @param string $macKeyHex The group's derived MAC key
	 * @param string $responsePaddingHex The random padding of random length to be added to the response
	 * @param string $responseNonceHex The random nonce to be used in the encryption of the response
	 * @param Response $response The response code, User Message Packets etc
	 * @param string $requestMacHex The MAC sent in the request, to be included in the Response MAC calculation
	 * @return string Returns the final Base64 encoded encrypted, authenticated, serialised data to be sent to the client
	 */
	public function serialiseEncryptAndAuthenticateResponse($encryptionKeyHex, $macKeyHex, $responsePaddingHex, $responseNonceHex, $response, $requestMacHex)
	{
		// Serialise the response into a canonical byte order that can be encrypted
		$serialisedResponseHex = $this->serialiseResponse($response, $responsePaddingHex);

		// Encrypt the serialised response data
		$encryptedSerialisedResponseHex = $this->encryptSerialisedResponse($encryptionKeyHex, $responseNonceHex, $serialisedResponseHex);

		// Authenticate the response
		$responseMac = $this->authenticateResponse($macKeyHex, $requestMacHex, $responseNonceHex, $encryptedSerialisedResponseHex);

		// Serialise the final response data and Base64 encode it
		$serialisedResponseBase64 = $this->serialiseAndEncodeResponse($responseNonceHex, $encryptedSerialisedResponseHex, $responseMac);

		return $serialisedResponseBase64;
	}

	/**
	 * Gets a random number of bytes for the padding in the authenticated response, based on the minimum and maximum padding constants
	 * @return string Returns a string of random bytes in hexadecimal
	 */
	public function getAuthenticatedResponsePadding()
	{
		// Get min and max random bytes
		$minRandomBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::RESPONSE_MIN_PADDING_BITS);
		$maxRandomBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::RESPONSE_MAX_PADDING_BITS);

		// Get a random number between the min and max number of bytes
		$randomNumOfBytes = random_int($minRandomBytes, $maxRandomBytes);

		// Get the random padding bytes of the specified random length and convert to a hexadecimal string
		$paddingBytes = random_bytes($randomNumOfBytes);
		$paddingBytesHex = bin2hex($paddingBytes);

		return $paddingBytesHex;
	}

	/**
	 * Sends back in hexadecimal concatenated together:
	 *
	 * Padding (variable bytes between min and max constants) ||
	 * User Message Packets (0 to variable number of bytes)
	 * (
	 *     From User (first letter lowercase) (1 byte) || OTP Encrypted Message Packet (384 bytes) ||
	 *     From User (first letter lowercase) (1 byte) || Second OTP Encrypted Message Packet (384 bytes) || ...
	 * )
	 * Number of Messages (2 bytes) ||
	 * Response Code (1 byte)
	 *
	 * @param Response $response The response object from performing the API request
	 * @param String $paddingBytesHex The random length padding bytes in hexadecimal
	 * @return string Returns the serialised response data in hexadecimal
	 */
	public function serialiseResponse($response, $paddingBytesHex)
	{
		$serialisedMessageDataHex = '';

		// For each User Message Packet
		foreach ($response->userMessagePackets as $userMessagePacket)
		{
			// Get the From User e.g. 'alpha', 'bravo' and the Message Packet (in hex)
			$fromUser = $userMessagePacket['fromUser'];
			$messagePacket = $userMessagePacket['messagePacket'];

			// Get the From User short code e.g. 'a', 'b', then convert to hex and pad to 2 hex symbols (1 byte length)
			$fromUserLetter = substr($fromUser, 0, 1);
			$fromUserLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::FROM_USER_BITS_LENGTH);
			$fromUserLetterPaddedHex = $this->converter->convertTextToHex($fromUserLetter, $fromUserLengthInHex);

			// Append the From User and Message Packet together sequentially with other messages
			$serialisedMessageDataHex .= $fromUserLetterPaddedHex . $messagePacket;
		}

		// Convert to hex and pad to 4 hex symbols (2 bytes length) if necessary
		$numOfMessages = count($response->userMessagePackets);
		$numOfMessagesLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH);
		$numOfMessagesPaddedHex = $this->converter->convertIntToHex($numOfMessages, $numOfMessagesLengthInHex);

		// Convert the Response Code (padded to 1 byte length) to hex
		$responseCodeLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::RESPONSE_CODE_BITS_LENGTH);
		$responseCodePaddedHex = $this->converter->convertIntToHex($response->responseCode, $responseCodeLengthInHex);

		// Concatenate the hex into canonical order
		$serialisedResponse = $paddingBytesHex
		                    . $serialisedMessageDataHex
		                    . $numOfMessagesPaddedHex
		                    . $responseCodePaddedHex;

		return $serialisedResponse;
	}

	/**
	 * Encrypt the serialised plaintext part of the response
	 * @param string $groupDerivedEncryptionKeyHex The derived encryption key from the group key
	 * @param string $responseNonceHex The random response nonce
	 * @param string $serialisedResponseHex The serialised plaintext response data
	 * @return string Returns the encrypted data portion of the response
	 */
	public function encryptSerialisedResponse($groupDerivedEncryptionKeyHex, $responseNonceHex, $serialisedResponseHex)
	{
		$encryptedSerialisedData = $this->networkCipher->encryptOrDecryptPayload($groupDerivedEncryptionKeyHex, $responseNonceHex, $serialisedResponseHex);

		return $encryptedSerialisedData;
	}

	/**
	 * Authenticates the response from the server. Uses the Request MAC in the MAC calculation so the response can't be
	 * replayed for other requests.
	 * @param string $groupDerivedMacKeyHex The MAC key for this chat group in hexadecimal
	 * @param string $requestMacHex The MAC sent in the request in hexadecimal
	 * @param string $responseNonceHex The nonce for the response in hexadecimal
	 * @param string $encryptedSerialisedDataHex The encrypted serialised response data in hexadecimal
	 * @return string Returns the MAC for the response as a 512 bit string in hexadecimal
	 */
	public function authenticateResponse($groupDerivedMacKeyHex, $requestMacHex, $responseNonceHex, $encryptedSerialisedDataHex)
	{
		// Serialise the data to be authenticated
		$dataToAuthenticateHex = $requestMacHex . $responseNonceHex . $encryptedSerialisedDataHex;

		// Append the Key and Data together (K || M)
		$keyAndDataToBeAuthenticated = $groupDerivedMacKeyHex . $dataToAuthenticateHex;

		// Convert hex to binary
		$dataToHashBinary = $this->converter->convertHexToBinaryData($keyAndDataToBeAuthenticated);

		// Hash the data i.e. H(K || M) which is a secure MAC for Skein
		$responseMacHex = skein_hash_hex($dataToHashBinary);

		return $responseMacHex;
	}

	/**
	 * Serialise the final response data and Base64 encode it in preparation to be returned in the HTTP response
	 * @param string $responseNonceHex The nonce for the response
	 * @param string $encryptedSerialisedResponseHex The encrypted part of the response
	 * @param string $responseMac The MAC for the response
	 * @return string Returns the full, final response data as Base64
	 */
	public function serialiseAndEncodeResponse($responseNonceHex, $encryptedSerialisedResponseHex, $responseMac)
	{
		// Serialise the data
		$serialisedResponseHex = $responseNonceHex . $encryptedSerialisedResponseHex . $responseMac;

		// Convert hex to binary
		$serialisedResponseBinary = $this->converter->convertHexToBinaryData($serialisedResponseHex);

		// Encode to Base64
		$base64EncodedResponse = base64_encode($serialisedResponseBinary);

		return $base64EncodedResponse;
	}

	/**
	 * Output the data for the client to parse. The response is authenticated by a MAC using Skein-512 hash
	 * and the user's key to ensure no-one can impersonate the server responses without the correct key.
	 * A random 512 bit nonce and timestamp help prevent duplicate messages/replay attacks.
	 * @param string $base64EncodedResponse The Base64 encoded data to be output in the response
	 */
	public function outputAuthenticatedResponse($base64EncodedResponse)
	{
		// Set CORS headers to allow JavaScript on the client to make Fetch or XMLHttpRequests to the server
		// https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
		header('Access-Control-Allow-Origin: *');

		// Output a normal HTTP 200 header
		header('HTTP/1.1 200 OK');

		// Output the response as plain Base64 string
		echo $base64EncodedResponse;
		exit;
	}
}
