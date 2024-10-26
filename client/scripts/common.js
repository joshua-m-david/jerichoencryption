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
 * Various common functions used by multiple pages
 */
var common = {

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

	/** Hash and MAC algorithms to be used */
	macAlgorithms: ['skein-512', 'keccak-512'],

	/** List of possible users */
	userList: ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf'],

	/** Listed of possible users with the shorthand single letter callsign as key */
	userListKeyedShort: {
		a: 'alpha',
		b: 'bravo',
		c: 'charlie',
		d: 'delta',
		e: 'echo',
		f: 'foxtrot',
		g: 'golf'
	},

	/** Listed of possible users with the full callsign as key */
	userListKeyedLong: {
		alpha: 'alpha',
		bravo: 'bravo',
		charlie: 'charlie',
		delta: 'delta',
		echo: 'echo',
		foxtrot: 'foxtrot',
		golf: 'golf'
	},

	/** The keyboard key codes that can be used */
	keyCodes: {
		enter: 13,
		esc: 27
	},

	/**
	 * Pad a message with random numbers up to the length of the message. Random bits will be added to the
	 * right of the message. This is so that all messages will be the same length to make cryptanalysis difficult.
	 * @param {String} plaintextMessageBinary The plaintext message in binary to be padded
	 * @returns {Object} Returns the 'actualMessageLength' as an integer representing the length of message in bytes and
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
	 * @returns {Number} The current timestamp in seconds as an integer
	 */
	getCurrentUtcTimestamp: function()
	{
		// Get current timestamp and convert from milliseconds to seconds
		var currentTimestampMilliseconds = Date.now();
		var currentTimestampSeconds = currentTimestampMilliseconds / 1000;

		// Remove any numbers after the decimal point
		return Math.round(currentTimestampSeconds);
	},

	/**
	 * Gets the current local date and time
	 * @returns {String} Returns the formatted string
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
	 * @returns {String} Returns the string in format: 19:37:21
	 */
	getCurrentLocalTime: function()
	{
		return this.formatTimeFromDateObject(new Date());
	},

	/**
	 * Gets the current date from a UTC timestamp
	 * @param {Number} timestamp A UNIX timestamp
	 * @returns {String} Returns the string in format: Mon 14 Jul 2014 19:37:21
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
	 * @returns {String} Returns the string in format: 21 JUL 14
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
	 * @returns {String} Returns the string in format: 19:07:01
	 */
	formatTimeFromDateObject: function(date)
	{
		return this.leftPadding(date.getHours(), '0', 2) + ':'
		     + this.leftPadding(date.getMinutes(), '0', 2) + ':'
		     + this.leftPadding(date.getSeconds(), '0', 2);
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
	 * @returns {Number} Returns a number (the array index) referencing the algorithm in the macAlgorithms array
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
	 * @returns {String} The MAC of the message and pad as hexadecimal
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
	 * @returns {Boolean} Returns true if valid, false if not
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
	 * @returns {String} Returns binary string of all message parts
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
	 * @returns {String} Returns just the message parts without the pad identifier
	 */
	getPadIdentifier: function(binary)
	{
		return binary.substr(0, this.padIdentifierSizeBinary);
	},

	/**
	 * Get the pad message parts from the pad. After that it can be XORed (pad message parts XOR plaintext message parts)
	 * @param {String} binaryPad Pass in a pad in binary
	 * @returns {String} Returns just the message parts without the pad identifier
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
		// message does not get encrypted properly. This is added as a basic defense against possible coding error.
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
	 * @returns {String} Returns the complete encrypted message including pad identifier and encrypted message parts
	 */
	combinePadIdentifierAndCiphertext: function(binaryPadIdentifier, binaryEncryptedMessageParts)
	{
		return binaryPadIdentifier + binaryEncryptedMessageParts;
	},

	/**
	 * Get the separate message parts (plaintext with padding, the actual message length and the message timestamp)
	 * @param {String} decryptedUnreversedMessagePartsBinary The plaintext message parts joined together
	 * @returns {Array} Returns the message parts separated out into an array with keys 'messagePlaintextWithPaddingBinary', 'messageLength', 'messageTimestamp'
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
	 * @returns {String} Returns the original plaintext message in binary
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
	 * Converts the number of bits to the number of hexadecimal symbols those bits represent.
	 * E.g. the number of bits in the string '0101111100001010' is 16 and the number in hex symbols this represents is 4.
	 * NB: The number of bits must be cleanly divisible into full hexadecimal symbols.
	 * @param {Number} numOfBits The number of bits e.g. 16
	 * @returns {Number} Returns the number of hex symbols if it was converted e.g. 4
	 */
	convertNumOfBitsToNumOfHexSymbols: function(numOfBits)
	{
		return numOfBits / 4;
	},

	/**
	 * Converts the number of bits to the number of bytes those bits represent.
	 * E.g. the number of bits in the string '0101111100001010' is 16 and the number in bytes this represents is 2.
	 * NB: The number of bits must be cleanly divisible into full bytes.
	 * @param {Number} numOfBits The length of the bit string e.g. 16
	 * @returns {Number} Returns the length of the string if it was converted to bytes e.g. 2
	 */
	convertNumOfBitsToNumOfBytes: function(numOfBits)
	{
		return numOfBits / 8;
	},

	/**
	 * Converts the number of hex symbols to the number of bits those symbols represent.
	 * E.g. the number of hex symbols in the string '5f0a' is 4 and the number in bits this represents is 16.
	 * @param {Number} numOfHexSymbols The number of hexadecimal symbols e.g. 4
	 * @returns {Number} Returns the number of bits those symbols represent e.g. 16
	 */
	convertNumOfHexSymbolsToNumOfBits: function(numOfHexSymbols)
	{
		return numOfHexSymbols * 4;
	},

	/**
	 * Converts the number of hexadecimal symbols to the number of bytes those hex symbols represent.
	 * E.g. the number of hex symbols in the string '5f0a' is 4 and the number in bytes this represents is 2.
	 * NB: The number of hex symbols must be cleanly divisible into full bytes.
	 * @param {Number} numOfHexSymbols The length of the string in hexadecimal symbols e.g. 4
	 * @returns {Number} Returns the number of bytes if it was converted e.g. 2
	 */
	convertNumOfHexSymbolsToNumOfBytes: function(numOfHexSymbols)
	{
		return numOfHexSymbols / 2;
	},

	/**
	 * Converts the number of bytes e.g. 2 to the number in bits e.g. 16.
	 * @param {Number} numOfBytes The number of bytes e.g. 2
	 * @returns {Number} Returns the number of bits in those bytes e.g. 16
	 */
	convertNumOfBytesToNumOfBits: function(numOfBytes)
	{
		return numOfBytes * 8;
	},

	/**
	 * Converts the number of bytes to the number of hex symbols those bytes represent.
	 * @param {Number} numOfBytes The number of bytes e.g. 2
	 * @returns {Number} Returns the number of hex symbols those bytes represent e.g. 4
	 */
	convertNumOfBytesToNumOfHexSymbols: function(numOfBytes)
	{
		return numOfBytes * 2;
	},

	/**
	 * Takes a string of binary code and converts it to UTF-8 text
	 * @param {String} binaryText The binary numbers to be converted e.g. 10010001
	 * @returns {String} A string of ASCII or UTF-8 characters
	 */
	convertBinaryToText: function(binaryText)
	{
		var convertedBytes = [];

		// For each 8 binary characters convert to an array of bytes
		for (var i = 0, j = 0; i < binaryText.length; i = j)
		{
			// Get the end point of the byte
			j += 8;

			// Get 8 chars from the string
			var binaryCharacters = binaryText.slice(i, j);

			// Convert binary to decimal
			var byteInteger = parseInt(binaryCharacters, 2);

			// Append to array
			convertedBytes.push(byteInteger);
		}

		// Convert the regular array to a Uint8Array for the TextDecoder
		var convertedByteArray = Uint8Array.from(convertedBytes);

		// Convert to regular text
		var utf8decoder = new TextDecoder();
		var output = utf8decoder.decode(convertedByteArray);

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
	 * Converts ASCII or UTF-8 text to binary string (one character at a time)
	 * @param {String} inputText The text to be converted
	 * @returns {String} A string of binary numbers e.g. 10010010...
	 */
	convertTextToBinary: function(inputText)
	{
		// Convert the text to a stream of UTF-8 bytes
		var encoder = new TextEncoder();
		var byteArray = encoder.encode(inputText);
		var output = '';

		// For each byte (represented as an integer in range of 0 - 255)
		for (var i = 0; i < byteArray.length; i++)
		{
			// Convert each byte integer to a byte represented as a binary string e.g. 10110000
			var byteInteger = byteArray[i];
			var byteBinary = byteInteger.toString(2);
			var byteBinaryPadded = common.leftPadding(byteBinary, '0', 8);

			// Append to output
			output += byteBinaryPadded;
		}

		return output;
	},

	/**
	 * Converts ASCII or UTF-8 text to a hexadecimal string (one character at a time)
	 * @param {String} inputText The text to be converted
	 * @returns {String} A string containing the hexadecimal numbers e.g. ab0d3f...
	 */
	convertTextToHexadecimal: function(inputText)
	{
		// Convert the text to a stream of UTF-8 bytes
		var encoder = new TextEncoder();
		var byteArray = encoder.encode(inputText);
		var output = '';

		// For each byte (represented as an integer in range of 0 - 255)
		for (var i = 0; i < byteArray.length; i++)
		{
			// Convert each byte integer to a byte represented as a hexadecimal string e.g. a0
			var byteInteger = byteArray[i];
			var byteHex = byteInteger.toString(16);
			var byteHexPadded = common.leftPadding(byteHex, '0', 2);

			// Append to output
			output += byteHexPadded;
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
		if (length % 2 !== 0)
		{
			numberHex = common.leftPadding(numberHex, '0', length + 1);
		}

		return numberHex;
	},

	/**
	 * Converts a Base64 string (including padding etc) to a hexadecimal string
	 * @param {String} base64String The Base64 string to be converted
	 * @returns {String} The converted string as hexadecimal
	 */
	convertBase64ToHexadecimal: function(base64String)
	{
		// Decode from Base64 to hex
		const words = CryptoJS.enc.Base64.parse(base64String);
		const hexString = CryptoJS.enc.Hex.stringify(words);

		return hexString;
	},

	/**
	 * Converts binary code to hexadecimal string. All hexadecimal is lowercase for consistency with the hash functions
	 * These are used as the export format and compatibility before sending via JSON or storing in the database
	 * @param {String} binaryString A string containing binary numbers e.g. '01001101'
	 * @returns {String} A string containing the hexadecimal numbers
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
	 * @returns {String} A string containing binary numbers
	 */
	convertHexadecimalToBinary: function(hexString)
	{
		var outputBinary = '';

		// For each hexadecimal character
		for (var i = 0; i < hexString.length; i++)
		{
			// Convert to decimal
			var decimal = parseInt(hexString.charAt(i), 16);

			// Convert to binary and add 0s onto the left as necessary to make up to 4 bits
			var binary = this.leftPadding(decimal.toString(2), '0', 4);

			// Append to string
			outputBinary += binary;
		}

		return outputBinary;
	},

	/**
	 * Converts hexadecimal code to Base64 string
	 * @param {String} hexString A string containing single digit hexadecimal numbers
	 * @returns {String} The string represented as Base64 (can include padding chars i.e. =)
	 */
	convertHexadecimalToBase64: function(hexString)
	{
		// Convert to hexadecimal to WordArray objects for CryptoJS to use then to Base64
		const words = CryptoJS.enc.Hex.parse(hexString);
		const outputBase64 = CryptoJS.enc.Base64.stringify(words);

		return outputBase64;
	},

	/**
	 * Converts hexadecimal code to UTF-8 string
	 * @param {String} hexString A string containing single digit hexadecimal numbers e.g. ab0d3f...
	 * @returns {String} Returns ASCII or UTF-8 text
	 */
	convertHexadecimalToText: function(hexString)
	{
		const convertedBytes = [];

		// For each 2 hex characters, convert to an array of bytes
		for (let i = 0; i < hexString.length; i += 2)
		{
			// Get 2 chars from the string
			const hexSymbols = hexString.slice(i, i + 2);

			// Convert 2 hex symbols to decimal
			const byteInteger = parseInt(hexSymbols, 16);

			// Append to array
			convertedBytes.push(byteInteger);
		}

		// Convert the regular array to a Uint8Array for the TextDecoder
		const convertedByteArray = Uint8Array.from(convertedBytes);

		// Convert to regular text
		const utf8decoder = new TextDecoder();
		const outputText = utf8decoder.decode(convertedByteArray);

		return outputText;
	},

	/**
	 * Left pad a string with a certain character to a total number of characters
	 * @param {String|Number} inputString The string or number to be padded
	 * @param {String} padCharacter The character/s that the string should be padded with
	 * @param {Number} totalCharacters The length of string that's required
	 * @returns {String} A string with characters appended to the front of it
	 */
	leftPadding: function(inputString, padCharacter, totalCharacters)
	{
		return inputString.toString().padStart(totalCharacters, padCharacter);
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
	 * @returns {Array} Returns the ciphertext and MAC concatenated together ready to be sent
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
	 * @returns {String} Returns the portion of the ciphertext that is the pad identifier
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
	 * @returns {Array} Returns an array with the following keys 'plaintext', 'timestamp', 'valid'
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
	 * @returns {Boolean} Returns true if the backup succeeded or false if there was a problem
	 */
	preparePadsForBackup: function(exportMethod)
	{
		// If the currently loaded database is the same as the blank default schema then there is nothing to backup
		if ((JSON.stringify(db.padData) === JSON.stringify(db.padDataSchema)))
		{
			app.showStatus('error', 'No pad database currently loaded.');
			return false;
		}

		// Convert to JSON for export to clipboard or text file
		var padDataJson = JSON.stringify(db.padData);

		// Export to a dialog which lets the user copy from there to a text file
		if (exportMethod === 'clipboard')
		{
			window.prompt('Copy to clipboard (Ctrl + C) then paste into text file', padDataJson);
			return true;
		}
		else if (exportMethod === 'textFile')
		{
			// Check for the various File API support
			if ((window.File && window.FileReader && window.FileList && window.Blob) === false)
			{
				app.showStatus('error', 'The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new text file.');
				return false;
			}

			// Set text file download parameters
			var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
			var userCallsign = db.padData.info.user;
			var nickname = db.padData.info.userNicknames[userCallsign].toLowerCase();
			var filename = 'one-time-pads-backup-user-' + nickname + '.txt';

			// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
			saveAs(blob, filename);
			return true;
		}
	},

	/**
	 * Get the length of any UTF-8 text in bytes
	 * @param {String} plaintext The plaintext as a string
	 * @returns {Number} Returns the length of the string in bytes
	 */
	getUtf8TextLengthInBytes: function(plaintext)
	{
		// Convert the text which possibly contains UTF-8 characters to bytes, then get the length
		var encoder = new TextEncoder();
		var byteArray = encoder.encode(plaintext);
		var length = byteArray.length;

		return length;
	},

	/**
	 * Get the pad to be used in encrypting the message
	 * @returns {String|false} Returns the pad to be used, or false if none available
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
	 * @returns {Object} Returns an object with properties 'padIndex', 'padIdentifier' and 'pad'
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
	 * @param {String} serverAddress The url of the server where the files are e.g. http://localhost or http://localhost/
	 * @returns {String} The correct url e.g. http://localhost/
	 */
	normaliseUrl: function(serverAddress)
	{
		// If the user has entered a server address with a slash on the end then just use that
		if (serverAddress.charAt(serverAddress.length - 1) === '/')
		{
			return serverAddress;
		}
		else {
			// Otherwise append the slash
			return serverAddress += '/';
		}
	},

	/**
	 * HTML encodes entities to prevent XSS
	 * @param {String} string The string to replace characters in
	 * @returns {String} The escaped string
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
	 * Wrapper around the various hash functions from different libraries and options to keep the output format consistent
	 * @param {String} algorithm The name of the algorithm to run ('keccak-512' or 'skein-512')
	 * @param {String} messageHex The string to be hashed in hexadecimal
	 * @returns {String} The hashed message as hexadecimal
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
			throw new Error('Maximum exceeded for getting a random int in range. The maximum is 4,294,967,295 (32 bit unsigned int).\n' + new Error().stack);
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
	 * @param {String} serverGroupIdentifier The 64 bit server group identifier in hexadecimal
	 * @param {String} serverGroupKey The 512 bit server group key in hexadecimal
	 * @param {String} callbackFunction Optional callback function to execute after server response is complete
	 */
	testServerConnection: function(serverAddressAndPort, serverGroupIdentifier, serverGroupKey, callbackFunction)
	{
		// If there's no failsafe CSPRNG key set, e.g. user is using the program for the first time and wants to test
		// the connection. This will get overwritten with a key from the TRNG if a user loads a database of one-time pads.
		if ((db.padData.info.failsafeRngKey === null) || (db.padData.info.failsafeRngNonce === null))
		{
			// Get 256 bits (32 bytes) from the Web Crypto API
			const randomBytes = new Uint8Array(32);
			window.crypto.getRandomValues(randomBytes);

			// Convert the random bytes to hexadecimal
			const randomDataHex = Salsa20.core.util.bytesToHex(randomBytes);

			// Update the failsafe CSPRNG key and nonce and persist the change in localStorage
			db.padData.info.failsafeRngKey = randomDataHex;
			db.padData.info.failsafeRngNonce = 0;
			db.savePadDataToDatabase();

			// Add an information log
			console.info('Generated a temporary failsafe CSPRNG key using the Web Crypto API.');
		}

		// If they didn't enter a valid server address/port, group identifier, or key show an error
		if (serverAddressAndPort === '')
		{
			app.showStatus('error', 'Enter the server address and port.');
			return false;
		}

		// Validate the server group identifier is hex and the correct length (in case they entered it themselves)
		if ((/^[0-9A-F]{16}$/i.test(serverGroupIdentifier) === false))
		{
			app.showStatus('error', 'The server group identifier  must be a hex string of 64 bits (16 hex symbols).', true);
			return false;
		}

		// Validate the server key is hex and the correct length (in case they entered it themselves)
		if ((/^[0-9A-F]{128}$/i.test(serverGroupKey) === false))
		{
			app.showStatus('error', 'The server group key must be a hex string of 512 bits (128 hex symbols).', true);
			return false;
		}

		// Package the data to be sent to the server. The From User is hard coded as alpha because we are just
		// testing the network connection. Any valid group user would work here and pass the request validation,
		// but alpha and bravo are guaranteed to be in every group (because you need at least 2 in a group). The
		// From User is required for sending actual (or decoy) messages, because messages from a user are stored
		// under that user in the DB, so when that user goes to retrieve messages from the server they don't refetch
		// the messages they sent.
		const requestData = {
			fromUser: common.userListKeyedLong.alpha,
			apiAction: networkCrypto.apiActionTest,
			serverAddressAndPort: serverAddressAndPort,
			serverGroupIdentifier: serverGroupIdentifier,
			serverGroupKey: serverGroupKey
		};

		// Send a request off to the server to check the connection
		common.sendRequestToServer(requestData, function(validResponse, responseCode)
		{
			// Get a status message
			let statusMessage = networkCrypto.getStatusMessage(responseCode);

			// Default to error style status message
			let status = 'error';

			// If the server response is authentic and it connected successfully, show success style message
			if (validResponse && responseCode === networkCrypto.RESPONSE_SUCCESS)
			{
				status = 'success';
			}
			else {
				// If not a valid response, add additional information for the user.
				// Most likely cause is user has incorrect server url/key entered. Another alternative is the
				// attacker modified their request while en route to the server.
				statusMessage += ' ' + networkCrypto.getNetworkTroubleshootingText();
			}

			// Show the status message
			app.showStatus(status, statusMessage);

			// Execute the outer test server connection callback function if it was passed.
			// This is used to reposition Export Pads dialog if it has a long error message.
			if (typeof callbackFunction === 'function')
			{
				callbackFunction();
			}
		});
	},

	/**
	 * Sends a request to the server and performs a specific API action on the server
	 * @param {Object} requestData The data to be sent to the server, with keys:
	 *     'fromUser'
	 *     'apiAction'
	 *     'serverAddressAndPort'
	 *     'serverGroupIdentifier'
	 *     'serverGroupKey'
	 *     'messagePackets' (optional - not required for test & receive requests)
	 * @param {Function} callbackFunction The anonymous callback function to run when complete. The first parameter to
	 *                                    the function will say whether the request succeeded and the MAC was valid
	 *                                    (true), or if it failed because of an invalid MAC or other problem (false).
	 *                                    The second parameter to the function will be the response/error code
	 *                                    (referencing numeric codes/constants in the network crypto class). The third
	 *                                    parameter will be an array of User Message Packets from the server (if the
	 *                                    response code says there were messages).
	 */
	sendRequestToServer: function(requestData, callbackFunction)
	{
		// Get the From User, API Action and message packets (for send request) or default to empty array
		const fromUser = requestData.fromUser;
		const apiAction = requestData.apiAction;
		const serverAddressAndPort = requestData.serverAddressAndPort;
		const groupIdentifierHex = requestData.serverGroupIdentifier;
		const serverGroupKeyHex = requestData.serverGroupKey;
		const messagePackets = requestData.messagePackets || [];

		// Prepare request data
		const nonceHex = common.getRandomBits(512, 'hexadecimal');
		const paddingHex = networkCrypto.getPaddingBytes();
		const currentTimestamp = common.getCurrentUtcTimestamp();

		// Derive encryption and MAC keys
		const derivedKeys = networkCrypto.deriveEncryptionAndMacKeys(serverGroupKeyHex);
		const encryptionKeyHex = derivedKeys.encryptionKey;
		const macKeyHex = derivedKeys.macKey;

		// Serialise, encrypt, authenticate and encode the data for the network request
		const requestDataBase64 = networkCrypto.encryptAndAuthenticateRequest(
			encryptionKeyHex, macKeyHex, groupIdentifierHex, nonceHex, paddingHex,
			fromUser, apiAction, currentTimestamp, messagePackets
		);

		// Fix the URL for any excess slashes
		const fullServerAddress = common.normaliseUrl(serverAddressAndPort);

		// Send request using the Fetch API
		fetch(fullServerAddress, {
			method: 'POST',
			mode: 'cors',
			cache: 'no-cache',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			redirect: 'follow',
			referrer: 'no-referrer',
			body: requestDataBase64
		})
		.then(response =>
		{
			// Check if the response code not 200
			if (response.status !== 200)
			{
				// Log error to console
				console.error('Network Fetch API response was not 200.', response);

				// Throw exception (caught in catch block below)
				throw new Error(`Network Fetch API response was not 200 (code ${response.status}).`);
			}

			return response.text();
		})
		.then(responseDataBase64 =>
		{
			// Get the Request MAC from the Base64 Request Data which is used in the Response MAC calculation
			const requestDataHex = common.convertBase64ToHexadecimal(requestDataBase64);
			const requestMacHex = networkCrypto.parseMacFromHex(requestDataHex);

			// Decode and verify the server response
			const verificationResult = networkCrypto.verifyResponse(macKeyHex, responseDataBase64, requestMacHex);

			// If there was an error in MAC validation
			if (!verificationResult.valid)
			{
				// Return the specific error
				callbackFunction(false, verificationResult.errorCode);
			}
			else {
				// Decrypt and deserialise the response
				const decryptedResponseHex = networkCrypto.decryptResponse(encryptionKeyHex, verificationResult.responseDataHex);
				const deserialisedResponse = networkCrypto.deserialiseDecryptedData(decryptedResponseHex);

				// If this is a receive messages API request
				if (apiAction === networkCrypto.apiActionReceive)
				{
					// If there were messages and the were successfully deserialised
					if (deserialisedResponse.responseCode === networkCrypto.RESPONSE_SUCCESS)
					{
						// Return the message packets
						callbackFunction(true, deserialisedResponse.responseCode, deserialisedResponse.messagePackets);
					}

					// Otherwise if the request/response was successful but there were no messages
					else if (deserialisedResponse.responseCode === networkCrypto.RESPONSE_SUCCESS_NO_MESSAGES)
					{
						// Return the success code and an empty array
						callbackFunction(true, deserialisedResponse.responseCode, []);
					}
				}
				else {
					// Otherwise return the success or error in the response code
					callbackFunction(true, deserialisedResponse.responseCode);
				}

				// ToDo 2022-05-07:  Fetch abort controller to timeout after 21secs https://dmitripavlutin.com/timeout-fetch-request/
			}
		})
		.catch(error =>
		{
			// Log exception to console
			console.error('Network Fetch API caught exception.', error);

			// Return back to the calling function so it can process the error
			callbackFunction(false, networkCrypto.RESPONSE_ERROR_NETWORK_FETCH_EXCEPTION);
		});
	},

	/**
	 * Saves just the server connection details to the local storage database
	 * @param {String} serverAddressAndPort
	 * @param {String} serverGroupIdentifier
	 * @param {String} serverGroupKey
	 */
	saveServerConnectionDetails: function(serverAddressAndPort, serverGroupIdentifier, serverGroupKey)
	{
		// Set the values to null if not set
		db.padData.info.serverAddressAndPort = (serverAddressAndPort !== '') ? serverAddressAndPort : null;
		db.padData.info.serverGroupIdentifier = (serverGroupIdentifier !== '') ? serverGroupIdentifier : null;
		db.padData.info.serverGroupKey = (serverGroupKey !== '') ? serverGroupKey : null;

		// Save to local storage
		db.savePadDataToDatabase();
	},

	/**
	 * Checks if HTML5 Local Storage is supported
	 * @returns {Boolean}
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
	 * @param {String} workerId The script tag ID of the worker to be loaded e.g. 'export-pads-worker'
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
	}
};