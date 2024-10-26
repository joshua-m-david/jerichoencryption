/*!
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

// Use ECMAScript 5's strict mode
'use strict';

/**
 * These functions additionally encrypt data packets for the client-server network protocol using Skein-512 in CTR mode
 * and authenticate using Skein-512 in MAC mode. This protocol secures the connection between the client and the server
 * to 100% disguise meta data so it appears as completely random data and also allows end-to-end OTP encrypted message
 * packets to be deposited on the server and picked up by other users for decryption on their local devices.
 *
 * Dependencies:
 * `common` namespace functions
 * `CryptoJS` Hexadecimal parsing function
 * `CryptoJS` Base64 encoding function
 */
var networkCrypto = {

	/**
	 * @type {Number} How many bits are produced by the Skein-512 hash function (64 bytes)
	 */
	skeinOutputBitLength: 512,

	/**
	 * @type {Number} The length of the counter in bits (8 bytes)
	 */
	counterBitLength: 64,

	/**
	 * @type {Number} Minimum length of the network packet padding in bits (1 Message Packet = 384 bytes)
	 */
	minPaddingBitLength: common.totalPadSizeBinary,

	/**
	 * @type Number Maximum length of the network packet padding in bits. Equivalent to 3 Message Packets including
	 *              Pad Identifier (3 x 1536 bits = 576 bytes)
	 */
	maxPaddingBitLength: common.totalPadSizeBinary * 3,

	/**
	 * @type Number Maximum length of the portion of the packet which identifies the length of the padding in bits (2 bytes)
	 */
	paddingLengthIdentifierBitLength: 16,

	/**
	 * @type String The API action for sending messages (serialises to an 's' in the network packet)
	 */
	apiActionSend: 's',

	/**
	 * @type String The API action for checking the server to receive messages (serialises to an 'r' in the network packet)
	 */
	apiActionReceive: 'r',

	/**
	 * @type String The API action for sending a test request to the server (serialises to a 't' in the network packet)
	 */
	apiActionTest: 't',

	/**
	 * @type Number The bit length of the response Skein-512 MAC digest (64 bytes)
	 */
	RESPONSE_MAC_BITS_LENGTH: 512,

	/**
	 * @type Number The bit length of the response Nonce (64 bytes)
	 */
	RESPONSE_NONCE_BITS_LENGTH: 512,

	/**
	 * @type Number The length of the Response Code portion of the response packet in bits (1 byte)
	 */
	RESPONSE_CODE_BITS_LENGTH: 8,

	/**
	 * @type Number The length of the Number of Messages portion of the response packet in bits (2 bytes)
	 */
	RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH: 16,

	/**
	 * @type Number The bit length of the From User short code (a = alpha, b = bravo etc) portion of the packet (1 byte)
	 */
	RESPONSE_FROM_USER_BITS_LENGTH: 8,

	/**
	 * @type Number The bit length of a client encrypted OTP Message Packet, including the pad identifier (384 bytes)
	 */
	RESPONSE_MESSAGE_PACKET_BITS_LENGTH: common.totalPadSizeBinary,

	/**
	 * @type Number The bit length of a User Message Packet in a response, calculated as:
	 *              From User (1 byte) || Message Packet (384 bytes) = User Message Packet (385 bytes)
	 */
	RESPONSE_USER_MESSAGE_PACKET_BITS_LENGTH: 8 + 1536,


	/******************************
	 * Success codes (range 0 - 99)
	 ******************************/

	/**
	 * @type Number This is the generic response success code
	 */
	RESPONSE_SUCCESS: 0,

	/**
	 * @type Number This is the response code when it made a successful receive messages API request but there were no
	 *              messages to collect, which is normal behaviour if nobody sent any messages.
	 */
	RESPONSE_SUCCESS_NO_MESSAGES: 1,


	/*************************************************
	 * Error codes for server issues (range 100 - 149)
	 *************************************************/

	/**
	 * @type Number The DB query failed
	 */
	RESPONSE_ERROR_DB_QUERY_FAILED: 100,

	/**
	 * @type Number Could not find the test record in the database
	 */
	RESPONSE_ERROR_DB_NO_TEST_RECORD: 101,

	/**
	 * @type Number Invalid or not implemented API action
	 */
	RESPONSE_ERROR_INVALID_API_ACTION: 102,

	/**
	 * @type Number No messages were sent in the request
	 */
	RESPONSE_ERROR_NO_MESSAGES_SENT: 103,

	/**
	 * @type Number The number of messages inserted in the DB did not match the number of messages that were sent in the request
	 */
	RESPONSE_ERROR_MESSAGES_INSERTED_MISMATCH: 104,


	/***************************************************************
	 * Error codes reserved for client side errors (range 150 - 199)
	 ***************************************************************/

	/**
	 * @type Number The From User was not valid in the response (something is wrong with the server or group configuration)
	 */
	RESPONSE_ERROR_CLIENT_DECODING_FROM_USER: 151,

	/**
	 * @type Number Something error happened with the client Fetch operation (code not in 200-299 range)
	 */
	RESPONSE_ERROR_NETWORK_RESPONSE_FAILURE: 152,

	/**
	 * @type Number Some exception happened with the client Fetch operation
	 */
	RESPONSE_ERROR_NETWORK_FETCH_EXCEPTION: 153,

	/**
	 * @type Number The Response MAC could not be found or parsed from the response
	 */
	RESPONSE_ERROR_MAC_NOT_PARSABLE: 154,

	/**
	 * @type Number The MAC validation failed
	 */
	RESPONSE_ERROR_INVALID_MAC: 155,

	/**
	 * @type Number The Response Data portion is insufficient minimum length for a valid response
	 */
	RESPONSE_ERROR_RESPONSE_DATA_BELOW_MIN_LENGTH: 156,

	/**
	 * @type Number An exception happened when trying to get the Response Data without the MAC appended from the full raw response data
	 */
	RESPONSE_ERROR_EXCEPTION_PARSING_RESPONSE_DATA: 157,

	/**
	 * @type Number There was some exception decoding the response or when validating the response
	 */
	RESPONSE_ERROR_DECODING_OR_VALIDATION_EXCEPTION: 158,



	/**
	 * @type Number int The minimum size response, calculated as:
	 *
	 * Nonce (64 bytes) ||
	 * Padding (385 bytes) - The size of 1 User Message Packet so an observer always thinks 1 message was returned ||
	 * User Message Packets (0 bytes) - Some responses might not contain message packets, i.e. no messages to retrieve, or just a response code ||
	 * Number of Messages (2 bytes) ||
	 * Response Code (1 byte) ||
	 * MAC (64 bytes)
	 *
	 * NB: There is no Padding Length Identifier in the response (it's not needed to decode the message)
	 */
	RESPONSE_MIN_RANDOM_BITS: 512 + // Nonce
		(8 + 1536) +                // Padding of 1 User Message Packet (1 byte for From User + 384 pad bytes)
		0 +                         // User Message Packets (none)
		16 +                        // Number of Messages
		8 +                         // Response Code
		512,                        // MAC

	/**
	 * Serialise the payload into canonical format ready for sending.
	 * All data is converted to hexadecimal for consistency.
	 * @param {String} fromUser The user i.e. alpha, bravo etc
	 * @param {String} apiAction The action to perform i.e. s for send, r for receive (use constant apiActionSend/Receive)
	 * @param {String} paddingHex The random padding bytes as hexadecimal symbols
	 * @param {Number} currentTimestamp The current UNIX timestamp as an integer
	 * @param {Array} messagePackets An array of Message Packets. Each Message Packet contains the full OTP encrypted
	 *                               and MACed message packets (as hex) including the pad identifier (384 bytes). This
	 *                               can be an array of one element for one message, or an empty array if sending a
	 *                               receive request.
	 * @returns {String} Returns a string of hexadecimal symbols ready to be encrypted and sent
	 */
	serialisePayloadForEncryption: function(fromUser, apiAction, paddingHex, currentTimestamp, messagePackets)
	{
		// Calculate the padding's length in hex then in bytes e.g. 'abcdef' has length of 6 in hex (3 bytes).
		// Calculating mathematically means the whole padding doesn't need to be converted to bytes to get the length.
		const lengthOfPaddingInHexSymbols = paddingHex.length;
		const lengthOfPaddingInBytes = common.convertNumOfHexSymbolsToNumOfBytes(lengthOfPaddingInHexSymbols);

		// Get the maximum length of the padding length identifier portion in hex i.e. 4 hex symbols (2 bytes)
		const maxPaddingLengthIdentifierHexLength = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.paddingLengthIdentifierBitLength);

		// Convert the length of the padding in bytes to be represented in hex e.g. 03
		const paddingLengthInBytesHex = common.convertIntegerToHex(lengthOfPaddingInBytes);

		// Store the padding length as a fixed 2 byte length e.g. 0003 so it's possible to remove the padding correctly
		const paddingLengthInBytesPaddedHex = common.leftPadding(paddingLengthInBytesHex, '0', maxPaddingLengthIdentifierHexLength);

		// From User - a for alpha, b for bravo etc (1 byte)
		const fromUserShortened = fromUser.substring(0, 1);
		const fromUserShortenedHex = common.convertTextToHexadecimal(fromUserShortened);
		const fromUserShortenedPaddedHex = common.leftPadding(fromUserShortenedHex, '0', 2);

		// API Action - s for send, r for receive (1 byte)
		const apiActionShortened = apiAction;
		const apiActionShortenedHex = common.convertTextToHexadecimal(apiActionShortened);
		const apiActionShortenedPaddedHex = common.leftPadding(apiActionShortenedHex, '0', 2);

		// Convert timestamp to hex (4+ bytes), pad up to 5 bytes if necessary to be future proof
		const currentTimestampHex = common.convertIntegerToHex(currentTimestamp);
		const currentTimestampPaddedHex = common.leftPadding(currentTimestampHex, '0', 10);

		// Concatenate the Message Packets including pad identifiers (192 bytes each)
		const messagePacketsHex = messagePackets.join('');

		// Serialise into canonical order
		const serialisedPayloadHex = paddingLengthInBytesPaddedHex +    // 2 bytes
				                     paddingHex +                       // variable bytes
		                             messagePacketsHex +                // variable bytes
									 currentTimestampPaddedHex +        // 5 bytes
		                             fromUserShortenedPaddedHex +       // 1 byte
		                             apiActionShortenedPaddedHex;       // 1 byte

		return serialisedPayloadHex;
	},

	/**
	 * Generates a keystream to encrypt a network payload based on the exact payload length
	 * @param {String} keyHex The key to encrypt with e.g. 512 random bits as a hexadecimal string
	 * @param {String} nonceHex The nonce e.g. 512 random bits as a hexadecimal string
	 * @param {String} payloadHex The payload (or message) as a hexadecimal string to be encrypted
	 * @returns {String} Returns the keystream as a hexadecimal string
	 */
	generateKeystream: function(keyHex, nonceHex, payloadHex)
	{
		// How many bytes and hash calls are required to encrypt the message
		const numOfHexSymbolsRequired = payloadHex.length;
		const numOfBitsRequired = common.convertNumOfHexSymbolsToNumOfBits(numOfHexSymbolsRequired);
		const numOfHashCallsRequired = Math.ceil(numOfBitsRequired / networkCrypto.skeinOutputBitLength);

		// Get the counter length in hex e.g. 16
		const counterHexLength = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.counterBitLength);

		// Set to store the keystream as hex
		let keystreamHex = '';

		// Generate the keystream
		for (let i = 0; i < numOfHashCallsRequired; i++)
		{
			// Get the counter in hex e.g. 0000000000000000, 0000000000000001 etc
			const counterHex = common.leftPadding(i, '0', counterHexLength);

			// Set the data to be hashed
			const dataToHash = keyHex + nonceHex + counterHex;

			// Hash the data and append it to the keystream generated so far
			keystreamHex += common.secureHash('skein-512', dataToHash);
		}

		// Get the length of the keystream in bits
		const keystreamBitsLength = common.convertNumOfHexSymbolsToNumOfBits(keystreamHex.length);

		// If too many bits were generated
		if (keystreamBitsLength > numOfBitsRequired)
		{
			// Truncate the output to the correct length
			keystreamHex = keystreamHex.substr(0, numOfHexSymbolsRequired);
		}

		return keystreamHex;
	},

	/**
	 * Encrypt or decyrypt the network payload
	 * @param {String} keyHex The key to encrypt/decrypt with e.g. 512 random bits as a hexadecimal string
	 * @param {String} nonceHex The nonce e.g. 512 random bits as a hexadecimal string
	 * @param {String} payloadHex The payload (or message) as a hexadecimal string to be encrypted/decrypted
	 * @returns {String} Returns the encrypted/decrypted payload as a hexadecimal string
	 */
	encryptOrDecryptPayload: function(keyHex, nonceHex, payloadHex)
	{
		// Create the keystream then encrypt/decrypt the payload
		const keystreamHex = networkCrypto.generateKeystream(keyHex, nonceHex, payloadHex);
		const dataHex = common.xorHex(keystreamHex, payloadHex);

		return dataHex;
	},

	/**
	 * Serialises the payload for MAC which includes the timestamp (closest 5mins)
	 * @param {String} nonceHex The nonce (512 bits) as a hexadecimal string
	 * @param {String} encryptedPayloadHex The encrypted network payload as a hexadecimal string
	 * @param {String} groupIdentifierHex The group identifier (64 bits) as a hexadecimal string
	 * @returns {String} Returns the serialised data ready to be MACed (as a hexadecimal string)
	 */
	serialiseDataForAuthentication: function(nonceHex, encryptedPayloadHex, groupIdentifierHex)
	{
		// Serialise into canonical order for MAC
		const serialisedDataHex = groupIdentifierHex +
		                          nonceHex +
		                          encryptedPayloadHex;

		return serialisedDataHex;
	},

	/**
	 * Derives an encryption and MAC key from the server key. The method it uses is similar to KDF1 and
	 * KDF2 where the master key is hashed with a counter e.g. Hash(Server Key || 32 bit counter).
	 * @param {String} serverGroupKeyHex The server key (512 bits) as a hexadecimal string
	 * @returns {Object} Returns object with key names 'encryptionKey' and 'macKey' (both are 512 bit keys in hex)
	 */
	deriveEncryptionAndMacKeys: function(serverGroupKeyHex)
	{
		// Derive Encryption and MAC keys
		var encryptionKey = common.secureHash('skein-512', serverGroupKeyHex + '00000000');
		var macKey = common.secureHash('skein-512', serverGroupKeyHex + '00000001');

		return {
			encryptionKey: encryptionKey,
			macKey: macKey
		};
	},

	/**
	 * Gets random bytes to be added to the payload to be encrypted to disguise the true length of the payload.
	 * Currently retrieves a random number of bytes between 0 and 576 bytes
	 * @returns {String} Returns the random bytes as a hexadecimal string
	 */
	getPaddingBytes: function()
	{
		// Convert the min and max length of the padding to length in bytes.
		// This is so the random bits generated are a multiple of bytes.
		const minPaddingBytes = common.convertNumOfBitsToNumOfBytes(networkCrypto.minPaddingBitLength);
		const maxPaddingBytes = common.convertNumOfBitsToNumOfBytes(networkCrypto.maxPaddingBitLength);

		// Get a random number between 0 and 576 bytes, then convert that to the number of bits
		const numOfPaddingBytesToGenerate = common.getRandomIntInRange(minPaddingBytes, maxPaddingBytes);
		const numOfPaddingBitsToGenerate = common.convertNumOfBytesToNumOfBits(numOfPaddingBytesToGenerate);

		// Get the random bits and convert to hexadecimal
		const paddingBytesHex = common.getRandomBits(numOfPaddingBitsToGenerate, 'hexadecimal');

		/*/ Testing max padding
		const maxPaddingBits = common.convertNumOfBytesToNumOfBits(maxPaddingBytes);
		const paddingBytesHex = common.getRandomBits(maxPaddingBits, 'hexadecimal');
		//*/

		/*/ Testing min padding
		const minPaddingBits = common.convertNumOfBytesToNumOfBits(minPaddingBytes);
		const paddingBytesHex = common.getRandomBits(minPaddingBits, 'hexadecimal');
		//*/

		return paddingBytesHex;
	},

	/**
	 * Computes the MAC of the request by computing a hash of Skein-512(K || data). The function will use Skein-512 as
	 * a MAC to authenticate data being sent/received to/from the server. On the server side the key and data is input
	 * into the hash as binary so this means the MAC from JavaScript and MAC from PHP will match.
	 * @param {String} macKeyHex The MAC key (512 bits) as a hexadecimal string
	 * @param {String} serialisedDataToBeAuthenticatedHex The data to be authenticated as a hexadecimal string
	 * @returns {String} Returns the computed MAC (512 bit digest) as a hexadecimal string
	 */
	computeMac: function(macKeyHex, serialisedDataToBeAuthenticatedHex)
	{
		const dataToHashHex = macKeyHex + serialisedDataToBeAuthenticatedHex;
		const computedMacHex = common.secureHash('skein-512', dataToHashHex);

		return computedMacHex;
	},

	/**
	 * Serialises the nonce, encrypted and authenticated data into its final order for sending in the API request.
	 * Then it Base64 encodes the data as a single string so it is ready to be sent. To an outside observer the
	 * entire packet should appear to consist of 100% random data.
	 * @param {String} nonceHex The nonce (512 bits) as a hexadecimal string
	 * @param {String} encryptedPayloadHex The encrypted network payload as a hexadecimal string
	 * @param {String} computedMacHex The computed MAC (512 bit digest) as a hexadecimal string
	 * @returns {String} Returns the canonical order for the network packet in Base64 format
	 */
	serialiseAndEncodeRequestData: function(nonceHex, encryptedPayloadHex, computedMacHex)
	{
		// Concatenate the data in canonical format
		const serialisedDataHex = nonceHex + encryptedPayloadHex + computedMacHex;

		// Convert from hexadecimal into WordArray objects for CryptoJS to use, then convert to Base64
		const serialisedDataWords = CryptoJS.enc.Hex.parse(serialisedDataHex);
		const serialisedDataBase64 = CryptoJS.enc.Base64.stringify(serialisedDataWords);

		return serialisedDataBase64;
	},

	/**
	 * Overall function to prepare the request to be sent
	 * @param {String} encryptionKeyHex The encryption key (512 bits) derived from the server key as a hexadecimal string
	 * @param {String} macKeyHex The MAC key (512 bits) derived from the server key as a hexadecimal string
	 * @param {String} groupIdentifierHex The group identifier (64 bits) as a hexadecimal string
	 * @param {String} nonceHex The nonce (512 bits) as a hexadecimal string
	 * @param {String} paddingHex The padding for the request as a hexadecimal string
	 * @param {String} fromUser The user sending the message/request/packet e.g. alpha, bravo etc
	 * @param {String} apiAction The API action i.e. send, receive
	 * @param {Number} currentTimestamp The current UNIX timestamp as an integer
	 * @param {Array} messagePackets The message packets to be sent (or an empty array if not sending a message)
	 * @returns {String} Returns the entire encrypted and authenticated payload ready for sending to server as Base64
	 */
	encryptAndAuthenticateRequest: function(encryptionKeyHex, macKeyHex, groupIdentifierHex, nonceHex, paddingHex, fromUser, apiAction, currentTimestamp, messagePackets)
	{
		// Serialise data to be encrypted and encrypt it
		const serialisedPayloadHex = networkCrypto.serialisePayloadForEncryption(fromUser, apiAction, paddingHex, currentTimestamp, messagePackets);
		const encryptedPayloadHex = networkCrypto.encryptOrDecryptPayload(encryptionKeyHex, nonceHex, serialisedPayloadHex);

		// Serialise data to be authenticated and compute the MAC
		const serialisedDataToBeAuthenticatedHex = networkCrypto.serialiseDataForAuthentication(nonceHex, encryptedPayloadHex, groupIdentifierHex);
		const computedMacHex = networkCrypto.computeMac(macKeyHex, serialisedDataToBeAuthenticatedHex);

		// Serialise the data into it's final state to be sent
		const encryptedAndAuthenticatedDataBase64 = networkCrypto.serialiseAndEncodeRequestData(nonceHex, encryptedPayloadHex, computedMacHex);

		// Return the encrypted and authenticated payload ready for sending to server
		return encryptedAndAuthenticatedDataBase64;
	},

	/**
	 * Initial function to decode, parse and verify the response from the server, failing and returning early on MAC
	 * failure. This validates the server response to make sure it came back from the real server. It also checks
	 * that the response it sent was a direct response to the request it was sent. It does this by performing a MAC
	 * using the Skein-512 hash algorithm on the request data and the response data with the server group key then
	 * comparing that with the MAC sent back from the server.
	 * @param {String} macKeyHex The MAC key (512 bits) derived from the server key as a hexadecimal string
	 * @param {String} responseDataBase64 The raw response body sent back by the server as Base64
	 * @param {String} requestMacHex The MAC digest from the request in hexadecimal, this is used in the response MAC
	 *                               calculation to ensure it is a response to this exact request.
	 * @returns {Object} Returns an object with three keys:
	 *     - valid {Boolean) Returns true if the response was verified successfully, or false if not
	 *     - errorCode {Number} The error code (if applicable)
	 *     - responseDataHex {String} The decoded response as a hexadecimal string (if there was no failure)
	 */
	verifyResponse: function(macKeyHex, responseDataBase64, requestMacHex)
	{
		try {
			// Decode response from Base64 to hexadecimal and get the Response MAC
			const responseDataHex = common.convertBase64ToHexadecimal(responseDataBase64);
			const responseMacHex = networkCrypto.parseMacFromHex(responseDataHex);

			// Check the MAC was parsed successfully, if not return an error
			if (!responseMacHex)
			{
				return {
					valid: false, errorCode: networkCrypto.RESPONSE_ERROR_MAC_NOT_PARSABLE
				};
			}

			// Remove the MAC from the response data
			const responseDataWithoutMac = networkCrypto.parseResponseDataWithoutMacFromHex(responseDataHex);

			// If parsing the response data without the MAC failed
			if (!responseDataWithoutMac.valid)
			{
				return {
					valid: false, errorCode: responseDataWithoutMac.errorCode
				};
			}

			const responseDataWithoutMacHex = responseDataWithoutMac.responseDataWithoutMacHex;
			const macIsVerified = networkCrypto.verifyResponseMac(macKeyHex, requestMacHex, responseDataWithoutMacHex, responseMacHex);

			// If verification failed, return an error
			if (!macIsVerified)
			{
				return {
					valid: false, errorCode: networkCrypto.RESPONSE_ERROR_INVALID_MAC
				};
			}

			// Return the valid result and decoded response data (to save unencoding from Base64 again)
			return {
				valid: true, responseDataHex: responseDataHex
			};
		}
		catch (exception)
		{
			// Log to console (useful for client side debugging)
			console.error('Exception verifying response', exception.toString(), exception);

			// Return an error if something goes wrong parsing/decoding the response
			return {
				valid: false, errorCode: networkCrypto.RESPONSE_ERROR_DECODING_OR_VALIDATION_EXCEPTION
			};
		}
	},

	/**
	 * Get the request or response MAC digest from the hexadecimal data. The request or response sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param {String} dataHex The serialised data encoded in hexadecimal format
	 * @return {String|false} Returns the MAC as a hexadecimal string, or false on parsing failure. NB: it's only
	 *                        possible to have a parsing failure if validating the response from the server.
	 */
	parseMacFromHex: function(dataHex)
	{
		try {
			// Get the length of the MAC in hex
			const expectedMacLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_MAC_BITS_LENGTH);

			// Take off the last 128 hex chars of the response which is the MAC
			const dataHexLength = dataHex.length;
			const macStartPos = dataHexLength - expectedMacLengthInHex;
			const macHex = dataHex.substring(macStartPos);
			const macLengthInHex = macHex.length;

			// Check the length is correct
			if (macLengthInHex !== expectedMacLengthInHex)
			{
				console.error('Length of Response MAC incorrect (actual, expected)', macLengthInHex, expectedMacLengthInHex);
				return false;
			}

			return macHex;
		}
		catch (exception)
		{
			console.error('Exception checking the Response MAC', exception);
			return false;
		}
	},

	/**
	 * Get the Response Data without the MAC appended from the full response data as hexadecimal. The response sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param {String} responseDataHex The serialised data encoded in hexadecimal format
	 * @return {Object} Returns the Nonce || Encrypted Data as a hexadecimal string, or false on parsing failure
	 */
	parseResponseDataWithoutMacFromHex: function(responseDataHex)
	{
		try {
			// Get the length of the MAC in hexadecimal and the minimum length of the Nonce || Encrypted Data
			const macLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_MAC_BITS_LENGTH);
			const minResponseLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_MIN_RANDOM_BITS);
			const minNonceAndEncryptedDataLengthInHex = minResponseLengthInHex - macLengthInHex;

			// Get the length of the Response Data in hexadecimal
			const responseDataHexLength = responseDataHex.length;

			// Find the start position of the Response MAC
			const macStartPos = responseDataHexLength - macLengthInHex;

			// Remove response MAC, so we just have the Reponse Nonce || Encrypted Serialised Data
			const responseDataWithoutMacHex = responseDataHex.substring(0, macStartPos);

			// Check the minimum length of a response
			if (responseDataWithoutMacHex.length < minNonceAndEncryptedDataLengthInHex)
			{
				return {
					valid: false, errorCode: networkCrypto.RESPONSE_ERROR_RESPONSE_DATA_BELOW_MIN_LENGTH
				};
			}

			// Successfully parsed
			return {
				valid: true,
				responseDataWithoutMacHex: responseDataWithoutMacHex
			};
		}
		catch (exception)
		{
			return {
				valid: false, errorCode: networkCrypto.RESPONSE_ERROR_EXCEPTION_PARSING_RESPONSE_DATA
			};
		}
	},

	/**
	 * Verifies the Response MAC by calculating it locally with the MAC Key and other data
	 * @param {String} macKeyHex The MAC key (64 bytes) derived from the server key as a hexadecimal string
	 * @param {String} requestMacHex The MAC digest from the request in hexadecimal, this is used in the response MAC
	 *                               calculation to ensure the response is to this exact request and not another.
	 * @param {String} responseDataWithoutMacHex The response data without the MAC appended as a hexadecimal string
	 * @param {String} responseMacHex The Response MAC digest (64 bytes) which is appended to the end of the response
	 * @returns {Boolean} Returns true if the MAC matched, false if not
	 */
	verifyResponseMac: function(macKeyHex, requestMacHex, responseDataWithoutMacHex, responseMacHex)
	{
		// Prepare the data to be hashed (Request MAC || Reponse Nonce || Encrypted Serialised Data)
		const serialisedDataHex = requestMacHex + responseDataWithoutMacHex;

		// Compute the MAC
		const computedMacHex = networkCrypto.computeMac(macKeyHex, serialisedDataHex);

		// Return true/false if the MAC matched (no timing safe comparison needed here as we are computing locally)
		return (computedMacHex === responseMacHex);
	},

	/**
	 * Decrypt the response
	 * @param {String} encryptionKeyHex The Encryption Key (64 bytes) as a hexadecimal string
	 * @param {String} responseDataHex The full Response Data as a hexadecimal string
	 * @returns {String} The decrypted payload as a hexadecimal string (not deserialised yet)
	 */
	decryptResponse: function(encryptionKeyHex, responseDataHex)
	{
		// Get the Nonce and Encrypted Data
		const nonceHex = networkCrypto.parseNonceFromHex(responseDataHex);
		const encryptedDataHex = networkCrypto.parseEncryptedDataFromResponseData(responseDataHex);

		// Decrypt the data
		const decryptedDataHex = networkCrypto.encryptOrDecryptPayload(encryptionKeyHex, nonceHex, encryptedDataHex);

		return decryptedDataHex;
	},

	/**
	 * Parse the nonce from the Response Data. The response sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param {String} responseDataHex The Response Data as a hexadecimal string
	 * @returns {String} Returns the Nonce as a hexadecimal string
	 */
	parseNonceFromHex: function(responseDataHex)
	{
		// Get the number of hex symbols to take off the front of the response
		const numOfHexSymbols = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_NONCE_BITS_LENGTH);
		const nonce = responseDataHex.slice(0, numOfHexSymbols);

		return nonce;
	},

	/**
	 * Parse the variable length Encrypted Data from the middle of the Response Data. The response sequence is:
	 *
	 *     Nonce (64 bytes) || Encrypted Data (variable bytes) || MAC (64 bytes)
	 *
	 * @param {String} responseDataHex The Response Data as a hexadecimal string
	 * @returns {String} Returns the Encrypted Data as a hexadecimal string
	 */
	parseEncryptedDataFromResponseData: function(responseDataHex)
	{
		// Get the number of hex symbols for the Nonce and MAC so we can slice from the start and end position
		const nonceLengthInHexSymbols = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_NONCE_BITS_LENGTH);
		const macLengthInHexSymbols = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_MAC_BITS_LENGTH);

		// Get just the variable length Encrypted Data in the middle
		const encryptedDataHex = responseDataHex.slice(nonceLengthInHexSymbols, -macLengthInHexSymbols);

		return encryptedDataHex;
	},

	/**
	 * Deserialise the data. The format of the serialised data is:
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
	 * @param {String} decryptedDataHex The decrypted payload as a hexadecimal string (not deserialised yet)
	 * @returns {Object} Returns an object, with keys: {Number} responseCode and {Array} messagePackets (optional)
	 */
	deserialiseDecryptedData: function(decryptedDataHex)
	{
		// Get the response code byte from the end of the serialised data
		const responseCodeLengthInHexSymbols = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_CODE_BITS_LENGTH);
		const responseCodeHex = decryptedDataHex.slice(-responseCodeLengthInHexSymbols);
		const responseCode = common.convertBinaryToInteger(common.convertHexadecimalToBinary(responseCodeHex));

		// For all other error response codes, just return the response code
		if (responseCode !== networkCrypto.RESPONSE_SUCCESS)
		{
			return {
				responseCode: responseCode
			};
		}

		// If this is a successful response
		if (responseCode === networkCrypto.RESPONSE_SUCCESS)
		{
			// Get the Number of Messages from near the end of the serialised data
			const numOfMessagesLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH);
			const numOfMessagesStartIndex = (numOfMessagesLengthInHex + responseCodeLengthInHexSymbols);
			const numOfMessagesHex = decryptedDataHex.slice(-numOfMessagesStartIndex, -responseCodeLengthInHexSymbols);
			const numOfMessages = common.convertBinaryToInteger(common.convertHexadecimalToBinary(numOfMessagesHex));

			// If there are no messages (e.g. send message request), we can return early
			if (numOfMessages === 0)
			{
				return {
					responseCode: responseCode
				};
			}

			// Count number of User Message Packets in hex symbols to remove from the end of the string
			const userMessagePacketLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_USER_MESSAGE_PACKET_BITS_LENGTH);
			const allUserMessagePacketsLengthInHex = numOfMessages * userMessagePacketLengthInHex;

			// Get the User Message Packets from the response
			const messagesStartIndex = (allUserMessagePacketsLengthInHex + numOfMessagesLengthInHex + responseCodeLengthInHexSymbols);
			const messagesEndIndex = (numOfMessagesLengthInHex + responseCodeLengthInHexSymbols);
			const userMessagePacketsHex = decryptedDataHex.slice(-messagesStartIndex, -messagesEndIndex);

			// Get length of From User in hex
			const fromUserLengthInHex = common.convertNumOfBitsToNumOfHexSymbols(networkCrypto.RESPONSE_FROM_USER_BITS_LENGTH);

			// Prepare array of message packets to be returned
			let messagePackets = [];

			// For each message packet
			for (let i = 0, startIndex = 0; i < numOfMessages; i++, startIndex += userMessagePacketLengthInHex)
			{
				// Get the From User (i.e. 'alpha', 'bravo' etc
				const endIndex = startIndex + userMessagePacketLengthInHex;
				const userMessagePacketHex = userMessagePacketsHex.slice(startIndex, endIndex);
				const fromUserHex = userMessagePacketHex.slice(0, fromUserLengthInHex);
				const fromUserLetter = common.convertHexadecimalToText(fromUserHex);
				const fromUser = common.userListKeyedShort[fromUserLetter];

				// If the From User was not valid, then return an error (something is very wrong with the server)
				if (fromUser === undefined)
				{
					return {
						responseCode: networkCrypto.RESPONSE_ERROR_CLIENT_DECODING_FROM_USER
					};
				}

				// Get just the Message Packet from the User Message Packet (From User (1 byte) || Message Packet (192 bytes))
				const messageStartIndex = fromUserLengthInHex;
				const messageEndIndex = fromUserLengthInHex + common.totalPadSizeHex;
				const messagePacket = userMessagePacketHex.slice(messageStartIndex, messageEndIndex);

				// Update array to be returned
				messagePackets.push({
					fromUser: fromUser,
					messagePacket: messagePacket
				});
			}

			// Return success Response Code and the OTP encrypted Message Packets
			return {
				responseCode: responseCode,
				messagePackets: messagePackets
			};
		}
	},

	/**
	 * Gets a readable status message based on the response/error code
	 * @param {Number} code A numeric code (reference constants in the networkCrypto class)
	 * @returns {String} The status message
	 */
	getStatusMessage: function(code)
	{
		switch (code)
		{
			case networkCrypto.RESPONSE_SUCCESS:
				return 'Server request and response successful.';

			case networkCrypto.RESPONSE_SUCCESS_NO_MESSAGES:
				return 'Server request and response successful, no messages to receive at this time.';

			case networkCrypto.RESPONSE_ERROR_DB_QUERY_FAILED:
				return 'Database query failed, check server logs.';

			case networkCrypto.RESPONSE_ERROR_DB_NO_TEST_RECORD:
				return 'Could not find the test record in the database.';

			case networkCrypto.RESPONSE_ERROR_INVALID_API_ACTION:
				return 'Invalid or not implemented API action.';

			case networkCrypto.RESPONSE_ERROR_NO_MESSAGES_SENT:
				return 'No messages were sent in the send message request.';

			case networkCrypto.RESPONSE_ERROR_MESSAGES_INSERTED_MISMATCH:
				return 'The number of messages inserted in the DB did not match the number of messages that were sent in the request.';

			case networkCrypto.RESPONSE_ERROR_CLIENT_DECODING_FROM_USER:
				return 'The From User was not valid in the response (something is wrong with the server or group configuration).';

			case networkCrypto.RESPONSE_ERROR_NETWORK_RESPONSE_FAILURE:
				return 'Error occurred with the client Fetch API operation.';

			case networkCrypto.RESPONSE_ERROR_NETWORK_FETCH_EXCEPTION:
				return 'An exception happened with the client Fetch API operation.';

			case networkCrypto.RESPONSE_ERROR_MAC_NOT_PARSABLE:
				return 'The Response MAC could not be found or parsed from the response.';

			case networkCrypto.RESPONSE_ERROR_INVALID_MAC:
				return 'The MAC validation failed.';

			case networkCrypto.RESPONSE_ERROR_RESPONSE_DATA_BELOW_MIN_LENGTH:
				return 'The Response Data portion is insufficient minimum length for a valid response.';

			case networkCrypto.RESPONSE_ERROR_DECODING_OR_VALIDATION_EXCEPTION:
				return 'An exception happened trying to get the Response Data without the MAC from the raw response data.';

			case networkCrypto.RESPONSE_ERROR_DECODING_OR_VALIDATION_EXCEPTION:
				return 'There was some exception decoding the response or when validating the response.';

			default:
				return `Unspecified error code ${code}.`;
		}
	},

	/**
	 * Gets a helpful message that can be appended to most network errors to help the user troubleshoot the problem
	 * @returns {String} The message
	 */
	getNetworkTroubleshootingText()
	{
		return 'Check: '
		     + '1) you are connected to the network, '
		     + '2) the client/server configurations are correct, and '
		     + '3) client/server system clocks are up to date. '
		     + 'If everything is correct, the data may have been tampered with by an attacker.';
	}
};
