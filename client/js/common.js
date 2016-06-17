/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2016  Joshua M. David
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
 * Various and common functions used by multiple pages
 */
var common = {
	
	// Current program version as an indicator to the user and to help with automatic importing from old versions later
	programVersion: '1.5.2',
	
	// Define lengths of message attributes in bytes
	padIdentifierSize: 7,		// Size of the pad identifier in bytes. The first 7 bytes of pad are used only to identify which pad was used
	messageSize: 115,			// The max length of a plaintext message in bytes
	messageLengthSize: 1,		// An attribute to define how long the actual message was in bytes without any padding
	messageTimestampSize: 5,	// The UNIX timestamp of when the message was sent
	macSize: 64,				// The Message Authentication Code
	totalMessagePartsSize: 121,	// The total length of the message parts in bytes (message + message length + timestamp)
	totalPadSize: 192,			// The total length of each pad in bytes
	
	// Hexadecimal representation for above variables
	padIdentifierSizeHex: 14,
	messageSizeHex: 230,
	messageLengthSizeHex: 2,
	messageTimestampSizeHex: 10,
	macSizeHex: 128,
	totalMessagePartsSizeHex: 242,
	totalPadSizeHex: 384,
	
	// Binary representation for above variables
	padIdentifierSizeBinary: 56,
	messageSizeBinary: 920,
	messageLengthSizeBinary: 8,
	messageTimestampSizeBinary: 40,
	macSizeBinary: 512,
	totalMessagePartsSizeBinary: 968,
	totalPadSizeBinary: 1536,
	
	// Salt length
	saltLength: 192,
	saltLengthHex: 384,
	saltLengthBinary: 1536,	
	
	// Hash and MAC algorithms to be used
	macAlgorithms: ['skein-512', 'keccak-512'],
	
	// Allowed printable ASCII chars from hexadecimal 21 - 7E (decimal 32 - 126)
	allPossibleChars: [
		' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 
		'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 
		'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'
	],
	
	// List of possible users
	userList: ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf'],
	
	// Start timer
	startTime: null,
	
	// A timer for hiding the status messages
	statusTimeoutId: null,
		
	/**
	 * Pad a message with random numbers up to the length of the message. Random bits will be added to the 
	 * right of the message. This is so that all messages will be the same length to make cryptanalysis difficult.
	 * @param {String} plaintextMessageBinary The plaintext message in binary to be padded
	 * @return {Object} Returns the 'actualMessageLength' as an integer representing the length of message in bytes and 
	 *                  the 'plaintextWithPaddingBinary' as a binary string with length that should be the same as the 
	 *                  maximum message length.
	 */
	padMessage: function(plaintextMessageBinary)
	{
		// Get the current message length
		var currentBinaryMessageLength = plaintextMessageBinary.length;		
		var paddingInfo = {
			actualMessageLength: null,
			plaintextWithPaddingBinary: null
		};
		
		// If the message is somehow bigger than the allowed message size (maybe they bypassed the 
		// text field maxlength), then truncate it up to the maximum message size
		if (currentBinaryMessageLength > this.messageSizeBinary)
		{
			paddingInfo.actualMessageLength = this.messageSize;
			paddingInfo.plaintextWithPaddingBinary = plaintextMessageBinary.substr(0, this.messageSizeBinary);
		}
		
		// If it is already the max length just return it
		else if (currentBinaryMessageLength === this.messageSizeBinary)
		{
			paddingInfo.actualMessageLength = this.messageSize;
			paddingInfo.plaintextWithPaddingBinary = plaintextMessageBinary;
		}		
		else {
			// Determine how much padding required
			var numOfPaddingBitsRequired = this.messageSizeBinary - currentBinaryMessageLength;
			
			// Get random padding bits
			var randomPaddingBitsBinary = common.getRandomBits(numOfPaddingBitsRequired, 'binary');
			
			// Add the padding onto the end of the existing plaintext
			var plaintextWithPaddingBinary = plaintextMessageBinary + randomPaddingBitsBinary;
			
			// Set actual message length to a count of the bytes
			paddingInfo.actualMessageLength = currentBinaryMessageLength / 8;
			paddingInfo.plaintextWithPaddingBinary = plaintextWithPaddingBinary;
		}
		
		return paddingInfo;
	},
	
	/**
	 * Get the current UNIX timestamp in UTC
	 * @return {Number} The current timestamp in seconds as an integer
	 */
	getCurrentUtcTimestamp: function()
	{
		// Get current timestamp and convert from milliseconds to seconds
		var currentTimestampMilliseconds = Date.now();
		var currentTimestampSeconds = currentTimestampMilliseconds / 1000; 
				
		// Remove any numbers after the decimal point 
		return Math.floor(currentTimestampSeconds);
	},
	
	/**
	 * Gets the current local date and time
	 * @return {String} Returns the formatted string
	 */
	getCurrentLocalDateTime: function()
	{
		// Get the current date
		var dateObj = new Date();
		
		// Format it
		return {
			'date': this.formatDateFromDateObject(dateObj),
			'time': this.formatTimeFromDateObject(dateObj)
		};
	},
	
	/**
	 * Gets the current local time
	 * @return {String} Returns the string in format: 19:37:21
	 */
	getCurrentLocalTime: function()
	{
		return this.formatTimeFromDateObject(new Date());
	},
	
	/**
	 * Gets the current date from a UTC timestamp
	 * @param {Number} timestamp A UNIX timestamp
	 * @return {String} Returns the string in format: Mon 14 Jul 2014 19:37:21
	 */
	getCurrentLocalDateTimeFromUtcTimestamp: function(timestamp)
	{
		// Make sure the timestamp contains positive integers only
		if (/^\d+$/.test(timestamp))
		{
			// Convert to an integer
			timestamp = parseInt(timestamp);
		}
		else {
			// If the timestamp contains invalid characters (indication of tampering) then use the current time
			// A warning will still be shown to the user that tampering has occurred.
			timestamp = this.getCurrentUtcTimestamp();
		}
		
		// Multiply by 1000 because Date object uses milliseconds
		var date = new Date(timestamp * 1000);
		
		// Return date and time formatted
		return {
			date: common.formatDateFromDateObject(date),
			time: common.formatTimeFromDateObject(date)
		};
	},
		
	/**
	 * Formats the current local date from a date object
	 * @param {date} date A JavaScript date object
	 *  @return {String} Returns the string in format: 21 JUL 14
	 */
	formatDateFromDateObject: function(date)
	{
		// Short names for days and months
		var monthNamesShort = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
		
		// Build string		
		var dateTime = date.getDate() + ' ' + monthNamesShort[date.getMonth()].toUpperCase() + ' ' + date.getFullYear().toString().substr(2,2);
		
		return dateTime;
	},
	
	/**
	 * Gets the current local time from a date object passed in
	 * @param {date} date A JavaScript date object
	 * @return {String} Returns the string in format: 19:37:21
	 */
	formatTimeFromDateObject: function(date)
	{	
		return this.leftPadding(date.getHours(), '0', 2) + ':' + this.leftPadding(date.getMinutes(), '0', 2) + ':' + this.leftPadding(date.getSeconds(), '0', 2);
	},
	
	/**
	 * Returns the full one-time pad without the pad identifier at the front
	 * @param {String} pad The full one-time pad in hexadecimal
	 * @returns {String}
	 */
	getPadWithoutPadIdentifier: function(pad)
	{
		return pad.substr(common.padIdentifierSizeHex);
	},
	
	/**
	 * Gets the index of a random MAC algorithm to use to create and verify the MAC for each message. It uses the 
	 * last byte of the one-time pad, converts it to an integer value, then uses that number mod the number of 
	 * MAC algorithms available. That will return an integer from 0, 1 which references the index of the algorithm 
	 * in an array.
	 * @param {String} pad The one-time pad for this message in hexadecimal
	 * @return {Number} Returns a number (the array index) referencing the algorithm in the macAlgorithms array
	 */
	getRandomMacAlgorithmIndex: function(pad)
	{
		// Get the last two hexadecimal chars (last byte) of the pad
		var startIndex = pad.length - 2;
		var lastByteOfPadHex = pad.substr(startIndex);
				
		// Convert those two hexadecimal symbols to an integer
		var randomInt = parseInt(lastByteOfPadHex, 16);
				
		// Get a random number between 0 and the number of MAC algorithms which will reference the index in the array
		var randomMacIndex = randomInt % this.macAlgorithms.length;
		
		// Return the array index
		return randomMacIndex;
	},
	
	/**
	 * Returns the portion of the pad that will be used to encrypt or decrypt the MAC
	 * @param {String} pad The full pad in hexadecimal
	 * @returns {String} The pad to use to encrypt the MAC
	 */
	getPadPartForMac: function(pad)
	{
		// Get the last x hexadecimal symbols of the pad
		var startIndex = common.totalPadSizeHex - common.macSizeHex;
		var padForMac = pad.substr(startIndex);
		
		return padForMac;
	},
		
	/**
	 * Generate a Message Authentication Code for the message. This is to 
	 * verify the data integrity and the authentication of each message sent.
	 * @param {Number} macAlgorithmIndex The MAC algorithm to use
	 * @param {String} pad The pad (key) as hexadecimal
	 * @param {String} ciphertextMessage The ciphertext (message) as hexadecimal
	 * @return {String} The MAC of the message and pad as hexadecimal
	 */
	createMessageMac: function(macAlgorithmIndex, pad, ciphertextMessage)
	{
		// Get which algorithm to use and generate the MAC
		var macAlgorithm = this.macAlgorithms[macAlgorithmIndex];
		
		// The new SHA3 competition algorithms Skein and Keccak are secure in the simple format of Hash(K | M) for a MAC. 
		// They have length extension attack prevention built in and do not need more complicated constructions like HMAC.
		var inputMessageHex = pad + ciphertextMessage;
				
		// Run the MAC algorithm
		return common.secureHash(macAlgorithm, inputMessageHex);		
	},
	
	/**
	 * Encrypt or decrypt the MAC with part of the one-time pad
	 * @param {String} padForMac Part of the pad to use for encrypting/decrypting the MAC in hexadecimal
	 * @param {String} mac The MAC or ciphertext MAC as hexadecimal
	 * @returns {String} Returns the encrypted or decrypted MAC in hexadecimal
	 */		
	encryptOrDecryptMac: function(padForMac, mac)
	{
		// Convert the pad and MAC to binary
		var padForMacBinary = common.convertHexadecimalToBinary(padForMac);
		var macBinary = common.convertHexadecimalToBinary(mac);	
		
		// Perform the encryption/decryption then convert the result back to hexadecimal
		var xoredMacBinary = common.xorBits(padForMacBinary, macBinary);
		var xoredMacHex = common.convertBinaryToHexadecimal(xoredMacBinary);
		
		return xoredMacHex;
	},
	
	/**
	 * Function for the receiver of a message to validate the message received by comparing the MAC. Then they can 
	 * check the integrity and authentication of the message by comparing the MAC to what was sent with the message. 
	 * The sender and receiver have a shared secret which is the one-time pad and the algorithm to be used to verify 
	 * the MAC is encoded with the message.
	 * @param {Number} macAlgorithmIndex The array index of MAC algorithm to use
	 * @param {String} pad The full pad as a hexadecimal string
	 * @param {String} ciphertextMessage The ciphertext of the message as a hexadecimal string	 
	 * @param {String} mac The plaintext MAC to be checked as a hexadecimal string
	 * @return {Boolean} Returns true if valid, false if not 
	 */
	validateMac: function(macAlgorithmIndex, pad, ciphertextMessage, mac)
	{		
		// Recreate the MAC, if it matches the one sent, then message hasn't been altered
		var macToTest = this.createMessageMac(macAlgorithmIndex, pad, ciphertextMessage);
		
		// Return true if passed check
		return (macToTest === mac) ? true : false;
	},
	
	/**
	 * Prepares the message parts to be encrypted. It simply makes sure everything is in binary the appends the 
	 * plaintext, message length and message timestamp together. The message parts should now be ready to be encrypted.
	 * @param {String} plaintextMessageWithPaddingBinary The plaintext and any padding in binary
	 * @param {Number} messageLength The length of the actual message minus padding
	 * @param {Number} messageTimestamp The current UNIX timestamp in UTC
	 * @return {String} Returns binary string of all message parts
	 */
	prepareMessageForEncryption: function(plaintextMessageWithPaddingBinary, messageLength, messageTimestamp)
	{
		// Convert the message length and timestamp to binary
		var messageLengthBinary = this.convertIntegerToBinary(messageLength, this.messageLengthSizeBinary);
		var messageTimestampBinary = this.convertIntegerToBinary(messageTimestamp, this.messageTimestampSizeBinary);
				
		// Concatenate the plaintext, length and timestamp
		var messagePartsBinary = plaintextMessageWithPaddingBinary + messageLengthBinary + messageTimestampBinary;
		
		// Return the plaintext, length and timestamp
		return messagePartsBinary;
	},
	
	/**
	 * To reduce crib attacks on the timestamp or length fields which contain consistently guessable data from message 
	 * to message, the message parts are dynamically reversed depending on the second last byte in the pad for each 
	 * message. The occassional reversal of the bits from message to message means that an attacker can not know 
	 * with absolute certainty which bits are where in the message thus making cryptanalysis extremely difficult.
	 * @param {String} pad The one-time pad in hexadecimal
	 * @param {String} messagePartsBinary The message parts in binary
	 * @returns {String}
	 */
	reverseMessageParts: function(pad, messagePartsBinary)
	{
		// Get the second last byte of the pad
		var lengthOfPad = pad.length;
		var startIndex = lengthOfPad - 4;
		var endIndex = lengthOfPad - 2;
		var secondLastByteOfPadHex = pad.substring(startIndex, endIndex);
		
		// Convert those two hexadecimal symbols to an integer
		var randomInt = parseInt(secondLastByteOfPadHex, 16);
						
		// Get a random number between 0 and 1 inclusive. A zero will leave the message parts as is, a one will reverse the message parts
		var reverseMessage = randomInt % 2;
				
		// Reverse the message parts
		if (reverseMessage === 1)
		{
			return messagePartsBinary.split('').reverse().join('');
		}
		
		// Otherwise leave message parts in original order
		return messagePartsBinary;
	},
	
	/**
	 * Return the pad identifier part which helps identify which pad to use for decryption. The first x characters of the pad are 
	 * not XORed with the plaintext as these are used to help identify which pad should be used to decrypt the message. If we 
	 * simply used a numeric key to identify which pad to decrypt with then that would leak how many messages have been sent so far.
	 * @param {String} binary Pass in a pad in binary, or a full encrypted message in binary to retrieve the pad identifier
	 * @return {String} Returns just the message parts without the pad identifier
	 */
	getPadIdentifier: function(binary)
	{
		return binary.substr(0, this.padIdentifierSizeBinary);
	},
		
	/**
	 * Get the pad message parts from the pad. After that it can be XORed (pad message parts XOR plaintext message parts)
	 * @param {String} binaryPad Pass in a pad in binary
	 * @return {String} Returns just the message parts without the pad identifier
	 */
	getPadMessageParts: function(binaryPad)
	{
		return binaryPad.substr(this.padIdentifierSizeBinary, this.totalMessagePartsSizeBinary);
	},
	
	/**
	 * This function does a bitwise exclusive or (XOR) operation on two bitstreams. This can be used to encrypt or 
	 * decrypt data by doing a XOR on the key and the plaintext. The two bitstreams should be of the same length.
	 * @param {String} bitsA The first stream of bits e.g.  '01010101'
	 * @param {String} bitsB The second stream of bits e.g. '00001111'
	 * @returns {String} A binary string containing the XOR of the first and second bitstreams e.g. '01011010'
	 */
	xorBits: function(bitsA, bitsB)
	{
		// Get the lengths of the two bitstreams
		var lengthBitsA = bitsA.length;
		var lengthBitsB = bitsB.length;
		
		// If the lengths of each stream of bits is different then this could be a serious problem e.g. the whole 
		// message does not get encrypted properly. This is added as a basic defense against possible coding error
		if (lengthBitsA !== lengthBitsB)
		{
			throw new Error('Serious failure, trying to XOR bitstreams of different lengths!\n' + new Error().stack);
		}
		
		var output = '';

		// For each binary character in the message
		for (var i = 0; i < lengthBitsA; i++)
		{
			// Get binary number of the two bitstreams at the same position
			var binaryDigitA = bitsA.charAt(i);
			var binaryDigitB = bitsB.charAt(i);

			// XOR the binary character of the pad and binary text character together and append to output
			output += (binaryDigitA ^ binaryDigitB);
		}

		return output;
	},
	
	/**
	 * A function to XOR two hexadecimal strings together
	 * @param {String} hexStringA The first string of hexadecimal symbols e.g. 'a7d9'
	 * @param {String} hexStringB The second string of hexadecimal symbols e.g. 'c72a'
	 * @returns {String} The result of the strings XORed together e.g. '60f3'
	 */
	xorHex: function(hexStringA, hexStringB)
	{
		// Convert the hexadecimal to binary
		var bitsA = common.convertHexadecimalToBinary(hexStringA);
		var bitsB = common.convertHexadecimalToBinary(hexStringB);
		
		// XOR the bit strings together and convert back to hexadecimal
		var xoredBits = common.xorBits(bitsA, bitsB);
		var xoredBitsHex = common.convertBinaryToHexadecimal(xoredBits);
		
		return xoredBitsHex;
	},
	
	/**
	 * Concatenates the pad identifier and ciphertext to make the full encrypted message
	 * After this the encrypted message can be converted to hexadecimal and is ready for sending
	 * @param {String} binaryPadIdentifier The pad identifier
	 * @param {String} binaryEncryptedMessageParts The encrypted message parts
	 * @return {String} Returns the complete encrypted message including pad identifier and encrypted message parts
	 */
	combinePadIdentifierAndCiphertext: function(binaryPadIdentifier, binaryEncryptedMessageParts)
	{
		return binaryPadIdentifier + binaryEncryptedMessageParts;
	},
	
	/**
	 * Get the separate message parts (plaintext with padding, the actual message length and the message timestamp)
	 * @param {String} decryptedUnreversedMessagePartsBinary The plaintext message parts joined together
	 * @return {Array} Returns the message parts separated out into an array with keys 'messagePlaintextWithPaddingBinary', 'messageLength', 'messageTimestamp'
	 */
	getSeparateMessageParts: function(decryptedUnreversedMessagePartsBinary)
	{
		// Get the message, length and timestamp portions from the message parts
		var messagePlaintextWithPaddingBinary = decryptedUnreversedMessagePartsBinary.substr(0, this.messageSizeBinary);
		var actualMessageLengthBinary = decryptedUnreversedMessagePartsBinary.substr(this.messageSizeBinary, this.messageLengthSizeBinary);
		var messageTimestampBinary = decryptedUnreversedMessagePartsBinary.substr(this.messageSizeBinary + this.messageLengthSizeBinary, this.messageTimestampSizeBinary);
		
		// Convert the length and timestamp back to integers
		var actualMessageLength = parseInt(actualMessageLengthBinary, 2);
		var messageTimestamp = parseInt(messageTimestampBinary, 2);
		
		return {
			'messagePlaintextWithPaddingBinary': messagePlaintextWithPaddingBinary,
			'messageLength': actualMessageLength,
			'messageTimestamp': messageTimestamp
		};
	},
	
	/**
	 * Removes padding from the message portion. This checks to make sure the message length is 
	 * in the correct range for a message to avoid DOS and/or buffer overflow attacks.
	 * @param {String} messagePlaintextWithPaddingBinary The plaintext message with padding on it
	 * @param {Number} actualMessageLength The actual message length in number of bytes
	 * @return {String} Returns the original plaintext message in binary
	 */
	removePaddingFromMessage: function(messagePlaintextWithPaddingBinary, actualMessageLength)
	{
		// Check that the length only contains positive integers only
		if (/^\d+$/.test(actualMessageLength))
		{
			// Check the message length is in the correct range for a message
			if ((actualMessageLength >= 1) && (actualMessageLength <= common.messageSize))
			{
				// Find the actual length in binary digits
				var actualMessageLengthInBinary = actualMessageLength * 8;
				
				// Get the actual message length
				return messagePlaintextWithPaddingBinary.substr(0, actualMessageLengthInBinary);
			}
		}
		
		// On failure, the fallback is to return the full message including any padding
		return messagePlaintextWithPaddingBinary.substr(0, common.messageSizeBinary);
	},
	
	/**
	 * Takes a string of binary code and converts it to ASCII text
	 * @param {String} binaryText The binary numbers to be converted
	 * @returns {String} A string of ASCII characters
	 */
	convertBinaryToText: function(binaryText)
	{
		var output = '';
		var j = 0;

		// For each 8 binary characters convert to ASCII
		for (var i = 0; i < binaryText.length; i = j)
		{
			// Get 8 characters from string
			j += 8;
			var binaryCharacters = binaryText.slice(i, j);

			// Convert binary to decimal
			var decimalCode = parseInt(binaryCharacters, 2);

			// Convert to ASCII and append to output
			output += String.fromCharCode(decimalCode);
		}

		return output;
	},
	
	/**
	 * Converts a binary representation of a number into an integer
	 * @param {String} binaryString The binary representation of the number
	 * @returns {Number}
	 */
	convertBinaryToInteger: function(binaryString)
	{
		return parseInt(binaryString, 2);
	},

	/**
	 * Converts text to binary string (one character at a time)
	 * @param {String} inputText The text to be converted
	 * @returns {String} A string of binary numbers
	 */
	convertTextToBinary: function(inputText)
	{
		var output = '';

		// For every character in the input text
		for (var i = 0; i < inputText.length; i++)
		{
			// Convert character to get the ASCII code in decimal, then convert it to a binary value
			var binary = inputText[i].charCodeAt(0).toString(2);

			// The line above sometimes produces only 7 binary chars, so need to left pad it with 0 to give us full 8 bits
			binary = this.leftPadding(binary, '0', 8);

			// Append new binary code to output
			output += binary;
		}

		return output;
	},
	
	/**
	 * Converts an integer to binary and pads it up to the required length
	 * @param {Number} number The number to be converted to binary
	 * @param {Number} length The fixed length required in number of bits
	 * @returns {String} Returns the binary representation of the number
	 */
	convertIntegerToBinary: function(number, length)
	{
		// Convert to binary and left pad it with 0s up to the length
		var numberBinary = number.toString(2);
		var numberWithPaddingBinary = common.leftPadding(numberBinary, '0', length);
	
		return numberWithPaddingBinary;
	},
	
	/**
	 * Converts a small number (0-255) to its hexadecimal representation
	 * @param {Number} number The number to be converted
	 * @returns {String} Returns the hexadecimal representation of the number
	 */
	convertSingleByteIntegerToHex: function(number)
	{
		// Convert to hexadecimal and left pad it with 0s if it is not a full byte (numbers 0-9)
		var numberHex = number.toString(16);
		var numberWithPaddingBinary = common.leftPadding(numberHex, '0', 2);
		
		return numberWithPaddingBinary;
	},
	
	/**
	 * Converts a number from an integer to hexadecimal string of even length. The maximum number of the integer 
	 * should be 2^53 - 1. If a string is passed it will convert it to an integer (e.g. from form field).
	 * @param {integer|string} number The number as an integer or string
	 * @returns {String} Returns the hexadecimal string
	 */
	convertIntegerToHex: function(number)
	{
		// Make sure it is an integer then convert it to hex
		var numberInt = parseInt(number);
		var numberHex = numberInt.toString(16);
		var length = numberHex.length;
		
		// If the number length is not even, add a 0 onto the left side
		if (length % 2 !== 0) {
			numberHex = common.leftPadding(numberHex, '0', length + 1);
		}
		
		return numberHex;
	},

	/**
	 * Converts binary code to hexadecimal string. All hexadecimal is lowercase for consistency with the hash functions
	 * These are used as the export format and compatibility before sending via JSON or storing in the database
	 * @param {String} binaryString A string containing binary numbers e.g. '01001101'
	 * @return {String} A string containing the hexadecimal numbers
	 */
	convertBinaryToHexadecimal: function(binaryString)
	{
		var output = '';
		
		// For every 4 bits in the binary string
		for (var i = 0; i < binaryString.length; i += 4)
		{
			// Grab a chunk of 4 bits
			var bytes = binaryString.substr(i, 4);
			
			// Convert to decimal then hexadecimal
			var decimal = parseInt(bytes, 2);
			var hex = decimal.toString(16);
			
			// Append to output
			output += hex;
		}

		return output;		
	},
	
	/**
	 * Converts hexadecimal code to binary code
	 * @param {String} hexString A string containing single digit hexadecimal numbers
	 * @return {String} A string containing binary numbers
	 */
	convertHexadecimalToBinary: function(hexString)
	{
		var output = '';
		
		// For each hexadecimal character
		for (var i = 0; i < hexString.length; i++)
		{
			// Convert to decimal
			var decimal = parseInt(hexString.charAt(i), 16);
			
			// Convert to binary and add 0s onto the left as necessary to make up to 4 bits
			var binary = this.leftPadding(decimal.toString(2), '0', 4);
			
			// Append to string			
			output += binary;
		}
		
		return output;
	},

	/**
	 * Left pad a string with a certain character to a total number of characters
	 * @param {String} inputString The string to be padded
	 * @param {String} padCharacter The character/s that the string should be padded with
	 * @param {Number} totalCharacters The length of string that's required
	 * @returns {String} A string with characters appended to the front of it
	 */
	leftPadding: function(inputString, padCharacter, totalCharacters)
	{
		// Convert to string first, or it starts adding numbers instead of concatenating
		inputString = inputString.toString();
		
		// If the string is already the right length, just return it
		if (!padCharacter || (inputString.length >= totalCharacters))
		{
			return inputString;
		}

		// Work out how many extra characters we need to add to the string
		var charsToAdd = (totalCharacters - inputString.length) / padCharacter.length;

		// Add padding onto the string
		for (var i = 0; i < charsToAdd; i++)
		{
			inputString = padCharacter + inputString;
		}
		
		return inputString;
	},
	
	/**
	 * Round a number to specified decimal places, 0-4 round down, 5-9 round up
	 * @param {Number} num The number to be rounded e.g. 123.456
	 * @param {Number} decimals The number of decimal places to round to (use 0 for none) e.g. 1
	 * @returns {Number} The number round to the specified decimal places e.g. 123.5
	 */
	roundNumber: function(num, decimals)
	{
		var newNum = new Number(num + '').toFixed(parseInt(decimals));
		
		return parseFloat(newNum);
	},
			
	/**
	 * Wrapper function to do all the work necessary to encrypt the message for sending. Also returns the encrypted 
	 * MAC as well. This will use random padding, get the current timestamp for the message and random MAC algorithm as well.
	 * @param {String} plaintextMessage The actual plaintext written by the user
	 * @param {String} pad The one-time pad as a hexadecimal string
	 * @return {Array} Returns the ciphertext and MAC concatenated together ready to be sent
	 */
	encryptAndAuthenticateMessage: function(plaintextMessage, pad)
	{
		// Convert the text to binary
		var plaintextMessageBinary = common.convertTextToBinary(plaintextMessage);
		
		// Get the message with random variable length padding
		var paddingInfo = common.padMessage(plaintextMessageBinary);
		var plaintextBinaryWithPadding = paddingInfo.plaintextWithPaddingBinary;
		var originalPlaintextLength = paddingInfo.actualMessageLength;
				
		// Get the current timestamp and get a random MAC algorithm to use based on last byte of the pad
		var timestamp = common.getCurrentUtcTimestamp();
		var randomMacAlgorithmIndex = common.getRandomMacAlgorithmIndex(pad);
				
		// Format message parts into binary for encryption
		var messagePartsBinary = common.prepareMessageForEncryption(plaintextBinaryWithPadding, originalPlaintextLength, timestamp);
		
		// Reverse message parts or not depending on second last byte of pad
		var messagePartsReversedBinary = common.reverseMessageParts(pad, messagePartsBinary);
		
		// Format pad for encryption
		var padBinary = common.convertHexadecimalToBinary(pad);
		var padIdentifier = common.getPadIdentifier(padBinary);
		var padMessagePartsBinary = common.getPadMessageParts(padBinary);
		
		// Encrypt the message, combine the pad and ciphertext, then convert to hex for transport
		var encryptedMessagePartsBinary = common.xorBits(padMessagePartsBinary, messagePartsReversedBinary);
		var completeCiphertextBinary = common.combinePadIdentifierAndCiphertext(padIdentifier, encryptedMessagePartsBinary);
		var ciphertextHex = common.convertBinaryToHexadecimal(completeCiphertextBinary);
		
		// Create MAC for message
		var mac = common.createMessageMac(randomMacAlgorithmIndex, pad, ciphertextHex);
		var padForMac = common.getPadPartForMac(pad);
		var ciphertextMac = common.encryptOrDecryptMac(padForMac, mac);
		
		// Return ciphertext and encrypted MAC concatenated together
		return ciphertextHex + ciphertextMac;
	},
		
	/**
	 * Get the pad identifier from the ciphertext
	 * We can use this to quickly look up the database and retrieve the pad (key) used to encipher this message
	 * @param {String} ciphertextHex The ciphertext as sent in hexadecimal string
	 * @return {String} Returns the portion of the ciphertext that is the pad identifier
	 */
	getPadIdentifierFromCiphertext: function(ciphertextHex)
	{
		return ciphertextHex.substr(0, this.padIdentifierSizeHex);
	},
	
	/**
	 * Get the encrypted MAC from the end of the ciphertext 
	 * @param {String} ciphertextHex
	 * @returns {String}
	 */
	getMacFromCiphertext: function(ciphertextHex)
	{
		return ciphertextHex.substr(this.padIdentifierSizeHex + this.totalMessagePartsSizeHex, this.totalPadSizeHex);
	},
	
	/**
	 * Gets the Pad identifier and ciphertext message parts from the full ciphertext which includes the MAC
	 * @param {String} ciphertextHex The full ciphertext that would be sent over the wire
	 * @returns {String} Returns the ciphertext without the MAC
	 */
	getCiphertextWithoutMac: function(ciphertextHex)
	{
		return ciphertextHex.substr(0, this.padIdentifierSizeHex + this.totalMessagePartsSizeHex);
	},
	
	/**
	 * Wrapper function to decrypt a received message and compare the MAC to see if it is valid or not. It will return 
	 * the plaintext, the timestamp of when the message was sent, and whether the message was validated or not.
	 * @param {String} ciphertext The ciphertext and ciphertext MAC concatenated together in hexadecimal string format
	 * @param {String} pad The pad to be used to decrypt the message. The pad to use can be found from the message identifier (first x symbols in the ciphertext)
	 * @return {Array} Returns an array with the following keys 'plaintext', 'timestamp', 'valid'
	 */
	decryptAndVerifyMessage: function(ciphertext, pad)
	{
		// Separate the parts into the main ciphertext and the ciphertext MAC
		var ciphertextWithoutMac = common.getCiphertextWithoutMac(ciphertext);
		var ciphertextMac = common.getMacFromCiphertext(ciphertext);
		
		// Validate the message
		var padForMac = common.getPadPartForMac(pad);
		var mac = common.encryptOrDecryptMac(padForMac, ciphertextMac);
		var macAlgorithmIndex = common.getRandomMacAlgorithmIndex(pad);	
		var macValidation = common.validateMac(macAlgorithmIndex, pad, ciphertextWithoutMac, mac);
		
		// If the MAC failed, return early and display message to user
		if (macValidation === false)
		{
			// Return an error message to appear in the chat
			return {
				'plaintext': 'Warning: message tampering detected. Ask the user to resend the contents of this message again.',
				'timestamp': common.getCurrentUtcTimestamp(),
				'valid': false
			};
		}
		
		// Get the ciphertext message parts (no message identifier)
		var ciphertextBinaryConvertedFromHex = common.convertHexadecimalToBinary(ciphertextWithoutMac);
		var ciphertextMessageParts = common.getPadMessageParts(ciphertextBinaryConvertedFromHex);
		
		// Get the pad message parts (no message identifier)
		var padBinary = common.convertHexadecimalToBinary(pad);
		var padMessagePartsBinary = common.getPadMessageParts(padBinary);
		
		// Decrypt the message parts, and reverse the message parts depending on the second last byte of the pad
		var decryptedMessagePartsBinary = common.xorBits(padMessagePartsBinary, ciphertextMessageParts);
		var decryptedReversedMessagePartsBinary = common.reverseMessageParts(pad, decryptedMessagePartsBinary);
		
		// Find out the actual plaintext and time the message was sent
		var messageParts = common.getSeparateMessageParts(decryptedReversedMessagePartsBinary);
		var messagePlaintextWithPaddingBinary = messageParts.messagePlaintextWithPaddingBinary;
		var messageLength = messageParts.messageLength;
		var messageTimestamp = messageParts.messageTimestamp;
		
		// Remove padding from plaintext and convert back to readable text
		var plaintextMessageBinary = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, messageLength);
		var plaintextMessage = common.convertBinaryToText(plaintextMessageBinary);
		
		// Return all important parts back
		return {
			'plaintext': plaintextMessage,		// The decrypted message
			'timestamp': messageTimestamp,		// Time the message was sent
			'valid': macValidation				// Whether the message is valid (MAC matched or not)
		};
	},
		
	/**
	 * This lets a user move the pads from one computer/device to another. Because pads are deleted once
	 * they are sent/received then it's not a good idea to just import the original text file of pads 
	 * because that could easily lead to pad re-use. This will copy the current remaining pads from the 
	 * local database to the clipboard or text file.
	 * @param {String} exportMethod How the pads will be exported. Pass in 'clipboard', 'textFile'
	 */
	preparePadsForBackup: function(exportMethod)
	{
		// If the currently loaded database is the same as the blank default schema then there is nothing to backup
		if ((JSON.stringify(db.padData) === JSON.stringify(db.padDataSchema)))
		{
			common.showStatus('error', 'No pad database currently loaded.');
			return false;
		}
		
		// Convert to JSON for export to clipboard or text file
		var padDataJson = JSON.stringify(db.padData);	

		// Export to a dialog which lets the user copy from there to a text file
		if (exportMethod === 'clipboard')
		{							
			window.prompt('Copy to clipboard (Ctrl + C) then paste into text file', padDataJson);
		}
		else if (exportMethod === 'textFile')
		{
			// Check for the various File API support
			if ((window.File && window.FileReader && window.FileList && window.Blob) === false)
			{
				common.showStatus('error', 'The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new text file.');
				return false;
			}
			
			// Set text file download parameters
			var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
			var userCallsign = db.padData.info.user;
			var nickname = db.padData.info.userNicknames[userCallsign].toLowerCase();
			var filename = 'one-time-pads-backup-user-' + nickname + '.txt';

			// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
			saveAs(blob, filename);
		}
	},
	
	/**
	 * Remove non ASCII characters from the plaintext message and cut the 
	 * message short if they have exceeded the maximum size allowed
	 * @param {String} plaintext The plaintext to remove invalid characters from
	 * @return {String} A clean ASCII string
	 */
	removeInvalidChars: function(plaintext)
	{
		// Remove non ASCII characters from the plaintext message
		var plaintextFiltered = plaintext.replace(/[^A-Za-z 0-9 \.,\?"'!@#\$%\^&\*\(\)-_=\+;:<>\/\\\|\}\{\[\]`~]*/g, '');
		
		// If the plaintext is somehow too long, cut it short to the maximum size allowed
		return plaintextFiltered.substr(0, common.messageSize);
	},
	
	/**
	 * Get the pad to be used in encrypting the message
	 * @return {String|false} Returns the pad to be used, or false if none available
	 */
	getPadToEncryptMessage: function()
	{
		// Initialisations
		var user = db.padData.info.user;
		
		// If the user doesn't exist, then the database hasn't been loaded
		if (user === null)
		{
			return false;
		}
		
		// Get the number of pads remaining for the user
		var numOfPads = db.padData.pads[user].length;
		
		// If there are no pads to use (sent all messages) return false, and calling function can show error
		if (numOfPads === 0)
		{
			return false;
		}
		
		// Get the first pad which will be returned
		var padIndex = 0;
		var pad = db.padData.pads[user][padIndex].pad;
		
		// Remove from in memory pad array and update the database so that pad can't be used again
		db.padData.pads[user].splice(padIndex, 1);
		db.savePadDataToDatabase();
				
		// Return the pad
		return pad;
	},
	
	/**
	 * Gets the pad to decrypt the message. It finds the right pad based on the first x letters in the ciphertext
	 * which is the pad identifer. The database is then searched for the pad with the same pad identifier. After the 
	 * pad is found, it is returned to the calling function and the pad is removed from the local database.
	 * @param {String} ciphertextHex The ciphertext and MAC in hexadecimal format
	 * @param {String} fromUser Which user the message is from
	 * @return {Object} Returns an object with properties 'padIndex', 'padIdentifier' and 'pad'
	 */
	getPadToDecryptMessage: function(ciphertextHex, fromUser)
	{
		// Initialisations
		var numOfPads = db.padData.pads[fromUser].length;
		var padIdentifier = this.getPadIdentifierFromCiphertext(ciphertextHex);
		var padIndex = null;
		var pad = null;
		
		// For each pad in memory for the user find the first one that we can send
		for (var i = 0; i < numOfPads; i++)
		{
			// If the pad id matches the one in the local database
			if (padIdentifier === db.padData.pads[fromUser][i].padIdentifier)
			{
				// Get the index in the array and the one-time pad to be returned
				padIndex = i;
				pad = db.padData.pads[fromUser][i].pad;
				break;
			}
		}
						
		// Return the pad and index in the array where it is. If it couldn't find a pad to use (maybe a fake message), 
		// the calling function can check for a null padIndex or null pad and show an error to the user
		return {
			'padIndex': padIndex,
			'padIdentifier': padIdentifier,
			'pad': pad	
		};
	},
	
	/**
	 * Fixes the URL depending on if the user entered a URL with a slash on the end or not
	 * @param {String} serverAddress The url of the server where the files are e.g. http://mydomain.com or http://mydomain.com/otpchat/
	 * @param {String} page The page to be accessed e.g. index.php
	 * @return {String} The correct url e.g. http://mydomain/otpchat/index.php
	 */
	normaliseUrl: function(serverAddress, page)
	{		
		// If the user has entered a server address with a slash on the end then just append the page name
		if (serverAddress.charAt(serverAddress.length - 1) === '/')
		{
			return serverAddress += page;
		}
		else {
			// Otherwise append the slash
			return serverAddress += '/' + page;
		}
	},
	
	/**
	 * HTML encodes entities to prevent XSS
	 * @param {String} string The string to replace characters in
	 * @return {String} The escaped string
	 */
	htmlEncodeEntities: function(string)
	{
		// List of HTML entities for escaping
		var htmlEscapes = {
			'&': '&amp;',
			'<': '&lt;',
			'>': '&gt;',
			'"': '&quot;',
			"'": '&#x27;',
			'/': '&#x2F;'
		};

		// Regex containing the keys listed immediately above
		var htmlEscaper = /[&<>"'\/]/g;

		// Escape a string for HTML interpolation
		return ('' + string).replace(htmlEscaper, function(match)
		{
			return htmlEscapes[match];
		});
	},
		
	/**
	 * Shows a success, error or processing message. The processing message also has an animated gif.
	 * @param {String} type The type of the error which will match the CSS class 'success', 'error' or 'processing'
	 * @param {String} message The error or success message
	 * @param {Boolean} keepDisplayed Optional flag to keep the message on screen until manually cleared
	 */
	showStatus: function(type, message, keepDisplayed)
	{
		// Cache selector
		var $statusMessage = $('.statusMessage');
		
		// Remove existing CSS classes, add the class depending on the type of message and set the message
		$statusMessage.removeClass('success warning error processing').addClass(type);
		$statusMessage.find('.message').text(message);
		
		// Clear previous timeout so that new status messages being shown don't get prematurely 
		// hidden by an old timer that is still running but just completes and hides the new message
		window.clearTimeout(common.statusTimeoutId);
		
		// If the message should be kept displayed just show it
		if (keepDisplayed)
		{
			$statusMessage.show();
		}
		else {
			// Otherwise show the error or success message for 14 seconds then fade it out
			$statusMessage.show();
			
			// Set a timer to hide the status message after 14 seconds
			common.statusTimeoutId = setTimeout(function()
			{
				$statusMessage.fadeOut(300);
			
			}, 14000);
		}
	},
	
	/**
	 * Clears the previous status message
	 */
	hideStatus: function()
	{
		// Cache selector
		var $statusMessage = $('.statusMessage');
		
		// Remove past classes, clear the message and hide it
		$statusMessage.removeClass('success error processing');
		$statusMessage.find('.message').text('');
		$statusMessage.hide();
		
		// Clear previous timeout so that new status messages being 
		// shown don't get prematurely hidden by an old timer still running
		window.clearTimeout(common.statusTimeoutId);
	},
	
	/**
	 * Shows how long it took to process the data up to this point
	 * @param {String} message The status message to be displayed
	 * @param {Boolean} showTimeElapsed Whether to show how long it has taken so far, turn this off if just starting the process
	 */
	showProcessingMessage: function(message, showTimeElapsed)
	{
		// Current time
		var currentTime = new Date();
		
		// Calculate time taken in milliseconds and seconds
		var milliseconds = currentTime.getTime() - common.startTime.getTime();
		var seconds = (milliseconds / 1000).toFixed(1);
		
		// Show the time the process started if applicable
		var timeElapsedMessage = (showTimeElapsed) ? ' Total time elapsed: ' + milliseconds + ' ms (' + seconds + ' s)' : '';
		
		// Show status on page
		common.showStatus('processing', message + timeElapsedMessage, true);
	},
	
	/**
	 * Wrapper around the various hash functions from different libraries and options to keep the output format consistent
	 * @param {String} algorithm The name of the algorithm to run ('keccak-512' or 'skein-512')
	 * @param {String} messageHex The string to be hashed in hexadecimal
	 * @return {String} The hashed message as hexadecimal
	 */
	secureHash: function(algorithm, messageHex)
	{
		switch (algorithm)
		{
			// Keccak (512 bits) - Winner of the NIST hash function competition and selected to be next SHA-3.
			// This uses the original Keccak algorithm, Keccak[c=2d], not the SHA3 version with NSA/NIST modifications. 
			// The hexadecimal is converted to CryptoJS wordArray objects so it can accept the hexadecimal input.
			case 'keccak-512':
				var messageWordArray = CryptoJS.enc.Hex.parse(messageHex);
				return CryptoJS.SHA3(messageWordArray, { outputLength: 512 }).toString();
			
			// Skein (512 bits) - A finalist in the NIST hash function competition
			case 'skein-512':
				return skein.hash(messageHex);	
		}
	},
		
	/**
	 * A wrapper function to get the required number of random bits.
	 * @param {Number} numOfBits The desired number of random bits as an integer.
	 * @param {String} returnFormat Pass in 'binary' or 'hexadecimal' to return the random bits in that format.
	 * @returns {String} Returns the random bits as a string of 1s and 0s. If the returnFormat is 'hexadecimal', then the 
	 *                   requiredNumOfBits should be a multiple of 4 bits, otherwise it can't convert the remaining few 
	 *                   bits to a hexadecimal symbol and will truncate the output to the nearest multiple of 4 bits.
	 */
	getRandomBits: function(numOfBits, returnFormat)
	{
		// Get random bits
		var failsafeRngKey = db.padData.info.failsafeRngKey;
		var failsafeRngNonce = db.padData.info.failsafeRngNonce;
		var randomBits = common.getEncryptedRandomBits(numOfBits, failsafeRngKey, failsafeRngNonce, returnFormat);
		
		// Update the nonce after use so it is ready for use next time, then persist the change in localStorage
		db.padData.info.failsafeRngNonce += 1;
		db.savePadDataToDatabase();
		
		// Return the bits in binary or hexadecimal depending on what was requested
		return randomBits;
	},
	
	/**
	 * Private function to get the required number of bits from the HTML5 Web Crypto API which uses the operating 
	 * system's random source. If the browser's implementation of this CSPRNG is compromised then there is a failsafe. 
	 * The HTML5 Web Crypto API could be compromised by the user running a closed source OS (e.g. Windows or MacOS), or 
	 * there is a flaw in the browser or underlying OS such as it uses Intel's questionable on-chip RNG. The program 
	 * will use a 256 bit key, which will be unique to each user running the program, to create a keystream of random 
	 * bits using the failsafe CSPRNG Salsa20. This is XORed with the random bytes returned from the Web Crypto API. 
	 * The failsafe nonce for Salsa20 should be incremented after each request by the code calling this function to 
	 * prevent re-use.
	 * @param {Number} numOfBits The desired number of random bits as an integer.
	 * @param {String} failsafeRngKey A key for the Salsa20 CSPRNG which should be a hexadecimal string consisting of 256 bits.
	 * @param {Number} failsafeRngNonce An integer starting from 0 up to 2^53 - 1 to be used as the nonce for the Salsa20 CSPRNG.
	 * @param {String} returnFormat Pass in 'binary' or 'hexadecimal' to return the random bits in that format.
	 * @returns {String} Returns the random bits as a string of 1s and 0s. If the returnFormat is 'hexadecimal', then the 
	 *                   requiredNumOfBits should be a multiple of 4 bits, otherwise it can't convert the remaining few 
	 *                   bits to a hexadecimal symbol and will truncate the output to the nearest multiple of 4 bits.
	 */
	getEncryptedRandomBits: function(numOfBits, failsafeRngKey, failsafeRngNonce, returnFormat)
	{
		// If the failsafe Salsa20 RNG has not been initialised with a key then throw a hard error which will halt 
		// program execution. This should not happen during normal program operation. It is a protection against 
		// programming error and the code logic requesting random bits before the key has been loaded.
		if ((failsafeRngKey === null) || (failsafeRngNonce === null) || (typeof failsafeRngKey === 'undefined') || (typeof failsafeRngNonce === 'undefined'))
		{
			throw new Error('Failsafe Salsa20 RNG has not been initialised with a key or nonce.\n' + new Error().stack);
		}
		
		// Get at least one byte from the Web Crypto API if less than 8 bits is required
		var requiredNumOfBytes = 1;
		
		// If more than 8 bits is required
		if (numOfBits > 8)
		{
			// Find out how many bytes to get. If not cleanly divisible by 8 bits, get the next whole number of bytes
			// so at least that many bits is collected from the Web Crypto API e.g. 17 bits will get 24 bits (3 bytes)
			requiredNumOfBytes = Math.ceil(numOfBits / 8);
		}
		
		// Initialise a typed array and fill it with 0 bytes
		var webCryptoRandomBytes = new Uint8Array(requiredNumOfBytes);
		
		try {
			// Fill array with required number of random bytes from the Web Crypto API
			window.crypto.getRandomValues(webCryptoRandomBytes);
		}
		catch (exception)
		{
			// If there is a failure getting random bytes from the Web Crypto API then halt program execution
			throw new Error('Failed to get ' + requiredNumOfBytes + ' random values from Web Crypto API.\n' + exception + '\n' + new Error().stack);
		}
		
		// Encrypt the bytes from the Web Crypto API with a key only the user knows. This prevents flaws in the 
		// Web Crypto API or underlying operating system's RNG from compromising the security of the program.
		var encryptedRandomBytesHex = Salsa20.encrypt(failsafeRngKey, webCryptoRandomBytes, failsafeRngNonce, 0, { returnType: 'hex' });
		
		// If hexadecimal format is needed
		if (returnFormat === 'hexadecimal')
		{	
			// Determine how many hexadecimal symbols to return and truncate the output to desired length
			var numOfHexSymbols = Math.floor(numOfBits / 4);
			var randomBitsHexadecimal = encryptedRandomBytesHex.substr(0, numOfHexSymbols);
			
			return randomBitsHexadecimal;
		}
		else {
			// Convert to binary string e.g. '101001010...' then truncate the output to exact length required
			var randomBitsBinary = common.convertHexadecimalToBinary(encryptedRandomBytesHex);
			randomBitsBinary = randomBitsBinary.substr(0, numOfBits);
			
			return randomBitsBinary;
		}
	},
		
	/**
	 * Gets a cryptographically secure random integer inbetween the minimum and maxium passed in. See:  
	 * http://stackoverflow.com/a/18230432. It gets a random number (assisted by the Web Crypto API and failsafe Salsa20 
	 * RNG) and then uses rejection sampling (see: http://en.wikipedia.org/wiki/Rejection_sampling). Depending on the 
	 * maximum value wanted it will get a 8 bit, 16 bit or 32 bit unsigned integer from the API. For example if a small 
	 * number between 0 and 10 is wanted it will just get an 8 bit number from the API rather than a 32 bit number which 
	 * is unnecessary.
	 * @param {Number} min The minimum number allowed. The minimum this function will allow is 0.
	 * @param {Number} max The maximum number allowed. The maximum this function will allow is 4294967295.
	 * @returns {Number} A random number between the minimum and maximum
	 */
	getRandomIntInRange: function(min, max)
	{
		// Find the range
		var range = max - min + 1;
				
		// Get at least 8 bits
		var numOfBits = 8;
		var maxRange = 256;
		
		// If the maximum required exceeds an unsigned 8 bit int, get 16 bits
		if (max > 255) 
		{			
			numOfBits = 16;
			maxRange = 65536;
		}
		
		// If the maximum required exceeds an unsigned 16 bit int, get 32 bits
		if (max > 65535)
		{			
			numOfBits = 32;
			maxRange = 4294967296;
		}
		
		// If the maximum required exceeds an unsigned 32 bit int, throw error
		if (max > 4294967295)
		{
			throw new Error('Maximum exceeded for getting a random int in range. The maximum is 4,294,967,295 (32 bit unsigned int).\n' + new Error().stack)
		}
		
		// Get a random number
		var randomBitsBinary = common.getRandomBits(numOfBits, 'binary');
		var randomNumber = common.convertBinaryToInteger(randomBitsBinary);
		
		// If the random number is outside of the range, get another. In testing 
		// it rarely needs to call the function recursively more than once.
		if (randomNumber >= Math.floor(maxRange / range) * range)
		{
			return common.getRandomIntInRange(min, max);
		}

		return min + (randomNumber % range);
	},
	
	/**
	 * Test that the server and database connection is working from the client
	 * @param {String} serverAddressAndPort The server address and port e.g. http://myserver.net:8080/jericho/
	 * @param {String} serverKey The 512 bit server key in hexadecimal
	 * @param {String} callbackFunction Optional callback function to execute after server response is complete
	 */
	testServerConnection: function(serverAddressAndPort, serverKey, callbackFunction)
	{
		// If there's no failsafe CSPRNG key set, e.g. user is using the program for the first time and wants to test 
		// the connection. This will get overwritten with a key from the TRNG if a user loads a database of one-time pads.
		if ((db.padData.info.failsafeRngKey === null) || (db.padData.info.failsafeRngNonce === null))
		{
			// Get 256 bits (32 bytes) from the Web Crypto API
			var randomBytes = new Uint8Array(32);
			window.crypto.getRandomValues(randomBytes);
			
			// Convert the random bytes to hexadecimal
			var randomDataHex = Salsa20.core.util.bytesToHex(randomBytes);
			
			// Update the failsafe CSPRNG key and nonce and persist the change in localStorage
			db.padData.info.failsafeRngKey = randomDataHex;
			db.padData.info.failsafeRngNonce = 0;
			db.savePadDataToDatabase();
			
			console.info('Generated a temporary failsafe CSPRNG key using the Web Crypto API.');
		}
		
		// If they didn't enter the server address show error
		if (serverAddressAndPort === '')
		{
			common.showStatus('error', 'Enter the server address and port.');
		}
		else if (serverKey === '')
		{
			common.showStatus('error', 'You need to have a user and key or anyone can access the server messaging API.');
		}
		else {
			// Package the data to be sent to the server
			var data = {
				'user': 'alpha',
				'apiAction': 'testConnection'
			};
			
			// Send a request off to the server to check the connection
			common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseData)
			{
				// If the server response is authentic
				if (validResponse)
				{
					// If it connected successfully show success message or error on failure
					var status = (responseData.success) ? 'success' : 'error';
					common.showStatus(status, responseData.statusMessage);
				}
				
				// If response check failed it means there was probably interference from attacker altering data or MAC
				else if (validResponse === false)
				{
					common.showStatus('error', 'Unauthentic response from server detected.');
				}

				else {
					// Most likely cause is user has incorrect server url or key entered.
					// Another alternative is the attacker modified their request while en route to the server
					common.showStatus('error', 'Error contacting server. Check: 1) you are connected to the network, 2) the client/server configurations are correct, and 3) client/server system clocks are up to date. If everything is correct, the data may have been tampered with by an attacker.');
				}
				
				// Execute the callback function (used to reposition Export Pads dialog if long error message)
				if (typeof callbackFunction === 'function')
				{
					callbackFunction();
				}
			});
		}
	},
		
	/**
	 * Sends a request to the server and performs a specific API action on the server
	 * @param {Object} requestData The data to be sent to the server
	 * @param {String} serverAddressAndPort The server address and port
	 * @param {String} serverKey The 512 bit hexadecimal server key
	 * @param {Function} callbackFunction The anonymous callback function to run when complete. The first parameter to 
	 *                                    the function will say whether the request succeeded and the MAC was valid 
	 *                                    (true), or if it failed because of an invalid MAC (false) or if it failed 
	 *                                    because of other problem e.g. server connection issue (null). The second 
	 *                                    parameter to the function will include the data response from the server if 
	 *                                    applicable e.g. messages received.
	 */
	sendRequestToServer: function(requestData, serverAddressAndPort, serverKey, callbackFunction)
	{
		// Fix the URL for any excess slashes
		var fullServerAddress = common.normaliseUrl(serverAddressAndPort, 'index.php');
		
		// Add a random nonce and the current timestamp to the data to be sent
		requestData.nonce = common.getRandomBits(512, 'hexadecimal');
		requestData.timestamp = common.getCurrentUtcTimestamp();
		
		// Convert to JSON and MAC the request data
		var requestDataJson = JSON.stringify(requestData);			
		var requestMac = common.authenticateRequest(requestDataJson, serverKey);
		
		// Base64 encode to obfuscate the meta data somewhat (future versions will encrypt the request data)
		var requestDataAndMacBase64 = btoa(requestDataJson + requestMac);
		
		// Create AJAX request to chat server
		$.ajax(
		{
			data: { data: requestDataAndMacBase64 },	// Use 'data' as the POST key which is as generic as possible to hinder traffic fingerprinting
			dataType: 'text',							// Expect plain text response as Base64 encoded string
			jsonp: false,								// Prevent insecure JSONP from being used and use CORS instead
			timeout: 14000,								// Timeout at 14 seconds
			type: 'POST',								// API accepts POST requests only
			url: fullServerAddress						// The API URL
		})
		.done(function(responseData)
		{
			// Check if the response was really from the server
			var validation = common.decodeAndValidateServerResponse(serverKey, responseData, requestMac);

			// Return back to the calling function so it can process the response
			callbackFunction(validation.valid, validation.responseData);
		})
		.fail(function()
		{			
			// Return back to the calling function so it can process the error
			callbackFunction(null, null);
		});		
	},
		
	/**
	 * Function will use Skein-512 as a MAC to authenticate data being sent to the server. 
	 * On the server side the key and data is input into the hash as binary so this means 
	 * the MAC from JavaScript and MAC from PHP will match.
	 * @param {String} dataJson The JSON data to be sent to the server
	 * @param {String} serverKey The server key as a hexadecimal string
	 * @returns {String} Returns the MAC as a hexadecimal string
	 */
	authenticateRequest: function(dataJson, serverKey)
	{
		// Convert the data to hexadecimal so it's in the same format as the key
		var dataJsonBinary = common.convertTextToBinary(dataJson);
		var dataJsonHex = common.convertBinaryToHexadecimal(dataJsonBinary);	

		// MAC the response by doing Hash(K | data)
		var dataToMac = serverKey + dataJsonHex;
		var mac = common.secureHash('skein-512', dataToMac);
		
		return mac;
	},
	
	/**
	 * Validates the server response to make sure it came back from the real server. It also checks 
	 * that the response it sent was a direct response to the request it was sent. It does this by 
	 * performing a MAC using the Skein-512 hash algorithm on the request data and the response data 
	 * with the server key then comparing that with the MAC sent back from the server.
	 * @param {String} serverKey The hexadecimal server key
	 * @param {Object} response The data from the response which should be the Base64 encoded JSON data and the MAC
	 * @param {String} requestMac The MAC of the data sent to the server
	 * @returns {Boolean} Whether the response was valid or not
	 */
	decodeAndValidateServerResponse: function(serverKey, response, requestMac)
	{
		// Default is invalid result
		var result = {
			valid: false,
			responseData: {}
		};
				
		// Check the data actually came back from the request
		if (typeof response !== 'undefined')
		{
			try {
				// Filter invalid Base64 characters
				var filteredResponseData = response.replace(/[^A-Za-z0-9+\/=]/g, '');
				
				// Decode from Base64
				var responseString = atob(filteredResponseData);
			
				// Take off the last 128 hex chars of the response which is the MAC
				var macStartPos = responseString.length - 128;
				var responseMac = responseString.substring(macStartPos);

				// Get the string up to the start of the MAC, which is the data then parse the JSON
				var responseDataJson = responseString.substring(0, macStartPos);
				
				// Validate the response from the server			
				var validResponse = common.validateResponseMac(serverKey, responseDataJson, requestMac, responseMac);
			
				// Check if it is an authentic response from the server first before decoding the JSON in case an 
				// attacker has modified the response and it executes some 0-day exploit in the browser's JSON parser
				if (validResponse)
				{
					// Decode the JSON to a regular JavaScript object, invalid JSON will throw an exception
					var responseData = JSON.parse(responseDataJson);

					// Successful result
					result.valid = true;
					result.responseData = responseData;
				}
			}
			catch (exception)
			{
				// If Base64 decoding or JSON parsing fails, e.g. malformed data was sent back, then return failure
				return result;
			}
		}
		
		// Return result
		return result;
	},
		
	/**
	 * Function to validate the response from the server
	 * @param {String} serverKey The server key
	 * @param {String} responseDataJson The server response JSON data
	 * @param {String} requestMac The MAC that was sent to the server	 
	 * @param {String} responseMac The server response MAC	 
	 * @returns {Boolean} Returns whether the server response is valid or not
	 */
	validateResponseMac: function(serverKey, responseDataJson, requestMac, responseMac)
	{
		// Convert the response data to hexadecimal
		var responseDataJsonBinary = common.convertTextToBinary(responseDataJson);
		var responseDataJsonHex = common.convertBinaryToHexadecimal(responseDataJsonBinary);
		
		// Perform the MAC - the order should match the PHP code
		var dataToMac = serverKey + responseDataJsonHex + requestMac;
		var macToCheck = common.secureHash('skein-512', dataToMac);
		
		// Check the calculated MAC matches the one from the server
		return (macToCheck === responseMac) ? true : false;
	},
	
	/**
	 * Saves just the server connection details to local storage
	 * @param {String} serverAddressAndPort
	 * @param {String} serverKey
	 */
	saveServerConnectionDetails: function(serverAddressAndPort, serverKey)
	{
		// Set the values to null if not set
		db.padData.info.serverAddressAndPort = (serverAddressAndPort !== '') ? serverAddressAndPort : null;
		db.padData.info.serverKey = (serverKey !== '') ? serverKey : null;
		
		// Save to local storage
		db.savePadDataToDatabase();
	},
	
	/**
	 * Checks if HTML5 Local Storage is supported
	 * @return {Boolean}
	 */
	checkLocalStorageSupported: function()
	{
		try	{
			return 'localStorage' in window && window['localStorage'] !== null;
		}
		catch (exception)
		{
			return false;
		}
	},
	
	/**
	 * Checks if the HTML5 Web Workers are supported
	 * @returns {Boolean}
	 */
	checkWebWorkerSupported: function()
	{
		return !!window.Worker;
	},
	
	/**
	 * Checks if the HTML5 Web Crypto API getRandomValues functon is supported
	 * @returns {Boolean}
	 */
	checkWebCryptoApiSupported: function()
	{
		try {					
			// Collect a small random number
			var smallNumByteArray = new Uint8Array(1);
			window.crypto.getRandomValues(smallNumByteArray);
			
			// Collect a medium random number
			var mediumNumByteArray = new Uint16Array(1);
			window.crypto.getRandomValues(mediumNumByteArray);
			
			// Collect a large random number
			var largeNumByteArray = new Uint32Array(1);
			window.crypto.getRandomValues(largeNumByteArray);
			
			// Check a random number got returned for each
			if ((smallNumByteArray[0].length !== 0) && (mediumNumByteArray[0].length) !== 0 && (largeNumByteArray[0].length !== 0))
			{
				return true;
			}
			
			// If no random numbers found
			return false;
		}
		catch (exception)
		{
			return false;
		}
	},
	
	/**
	 * Checks if HTML5 Offline Web Application Cache is supported
	 * @returns {Boolean}
	 */
	checkOfflineWebApplicationSupported: function()
	{
		return !!window.applicationCache;
	},
		
	/**
	 * Formats the number with thousands separator
	 * @param {Number} num Pass in number e.g. 2000000
	 * @returns {String} Returns in format 2,000,000
	 */
	formatNumberWithCommas: function(num)
	{
		return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
	},
	
	/**
	 * Capitalises the first letter of a string
	 * @param {String} text
	 * @returns {String}
	 */
	capitaliseFirstLetter: function(text)
	{
		return text.charAt(0).toUpperCase() + text.slice(1);
	},
	
	/**
	 * Some boilerplate code to start an inline HTML5 Web Worker. This can be used to do CPU intensive tasks and 
	 * prevent the main UI thread from being blocked. Using the ID of the worker it will find the code within the 
	 * <script id="worker-id" type="javascript/worker"><script> tag of the HTML page and initialise the web worker 
	 * with that code. This inline web worker avoids the same origin policy restrictions when loading a web worker 
	 * from a different file path in Chromium.
	 * See: http://stackoverflow.com/a/18490502
	 * and: http://www.html5rocks.com/en/tutorials/workers/basics/#toc-inlineworkers
	 * @param {String} workerId The CSS ID of the worker to be loaded e.g. 'export-pads-worker'
	 * @returns {Worker} Returns the web worker object
	 */
	startWebWorker: function(workerId)
	{
		// Convert the base URL so the web worker can import the common.js script
		// Also load the JavaScript code on the HTML page which is what the worker will run
		var baseUrl = window.location.href.replace(/\\/g, '/').replace(/\/[^\/]*$/, '');
		var workerJavaScript = $('#' + workerId).html();
        var array = ['var baseUrl = "' + baseUrl + '";' + workerJavaScript];
		
		// Create a Blob to hold the JavaScript code and send it to the inline worker
        var blob = new Blob(array, { type: 'text/javascript' });
		var blobUrl = window.URL.createObjectURL(blob);
		var worker = new Worker(blobUrl);
		
		// Worker error handler
		worker.addEventListener('error', function(event)
		{
			console.error('ERROR: Worker ID ' + workerId + ' line ' + event.lineno + ' in ' + event.filename + ': ' + event.message);
			
		}, false);
		
		// Free up memory
		window.URL.revokeObjectURL(blobUrl);
		
		// Return the worker object so custom listeners can be added
		return worker;
	},
		
	/**
	 * Parses JSON with detection for invalid JSON
	 * @param {String} jsonString The JSON string to parse
	 * @returns {Object|false} Returns the JavaScript object if valid JSON or false if not
	 */
	parseJson: function(jsonString)
	{
		try {
			// Try parsing the string
			var json = JSON.parse(jsonString);
			
			// Handle non-exception throwing cases
			if (json && (typeof json === 'object'))
			{
				// Return valid JSON
				return json;
			}
			
			return false;
		}		
		catch (exception)
		{
			return false;
		}
	},	
	
	/**
	 * Helper function to get a clone of the outer HTML of an element
	 * @param {Object} $html The jQuery element or object e.g. $html = $('<div class="abc"></div>')
	 * @returns {String} Returns the outer HTML as a string e.g. '<div class="abc"></div>'
	 */
	getOuterHtml: function($html)
	{
		return $html.clone().wrap('<p>').parent().html();
	}
};