/*!
 * Jericho Chat - Information-theoretically secure communications
 * Copyright (C) 2013-2014  Joshua M. David
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
 * Various and common functions used by multiple pages
 */
var common = {
	
	// Current program version to help with importing from old versions later
	programVersion: '1.4',
	
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
			
	// Random data collected or loaded from TRNG
	randomDataBinary: '',
	randomDataHexadecimal: '',
		
	/**
	 * Calculates the length of the plaintext message without any padding
	 * @param {string} plaintextMessage The plaintext message
	 * @return {integer} Returns the original length of the message in bytes before padding e.g. 70, 5, 115
	 */
	getOriginalPlaintextLength: function(plaintextMessage)
	{
		var messageLength = plaintextMessage.length;
		
		// If the message is somehow bigger than the allowed message size (maybe they bypassed the text field maxlength)
		if (messageLength > this.messageSize)
		{
			// Return the max length allowed, the message will be truncated by the padMessage function
			return this.messageSize;
		}
		else {
			// Return the actual size
			return messageLength;
		}
	},
	
	/**
	 * Pad a message with random numbers up to the length of the message. Random numbers will be added to the 
	 * right of the message. This is so that all messages will be the same length to frustrate cryptanalysis.
	 * @param {string} plaintextMessageBinary The plaintext message in binary to be padded
	 * @return {string} Returns a binary string with length the sames as the maximum message length
	 */
	padMessage: function(plaintextMessageBinary)
	{
		// Get the current message length
		var currentMessageLength = plaintextMessageBinary.length;
		
		// If the message is somehow bigger than the allowed message size (maybe they bypassed the 
		// text field maxlength), then truncate it up to the maximum message size
		if (currentMessageLength > this.messageSizeBinary)
		{
			return plaintextMessageBinary.substr(0, this.messageSizeBinary);
		}
		else if (currentMessageLength === this.messageSizeBinary)
		{
			// If it's already the max length just return it
			return plaintextMessageBinary;
		}
		else {
			// Otherwise add random numbers up to message size
			while (currentMessageLength < this.messageSizeBinary)
			{
				// Collect a random number from the HTML5 CSPRNG
				var byteArray = new Uint32Array(1);
				window.crypto.getRandomValues(byteArray);
				
				// Convert to string
				var randomNumbers = byteArray[0].toString();
								
				// Loop through the integers returned
				for (var i=0, length = randomNumbers.length; i < length; i++)
				{
					// The crypto.getRandomValues API returns whole integers however random bits for the padding is better to prevent a crib 
					// for an attacker (the first 4 bits of every ASCII encoded number is 0011). This method will get a single bit for every 
					// integer received from the API. To get a uniform distribution, half the integers (0, 1, 2, 3, 4) will be assigned to a 
					// 0 bit and the other half (5, 6, 7, 8, 9) to a 1 bit.
					var integer = parseInt(randomNumbers.charAt(i));
					plaintextMessageBinary += (integer < 5) ? '0' : '1';
				}
				
				// Add to the plaintext and update the current length
				currentMessageLength = plaintextMessageBinary.length;
			}
			
			// Sometimes the getRandomValues returns variable sized numbers and it would put it oversize so truncate it
			return plaintextMessageBinary.substr(0, this.messageSizeBinary);
		}
	},
	
	/**
	 * Get the current UNIX timestamp in UTC
	 * @return {string} The current timestamp
	 */
	getCurrentUtcTimestamp: function()
	{
		// Convert from milliseconds to seconds
		return Math.floor(Date.now() / 1000);
	},
	
	/**
	 * Gets the current local date and time
	 * @return {string} Returns the formatted string
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
	 * @return {string} Returns the string in format: 19:37:21
	 */
	getCurrentLocalTime: function()
	{
		return this.formatTimeFromDateObject(new Date());
	},
	
	/**
	 * Gets the current date from a UTC timestamp
	 * @param {number} timestamp A UNIX timestamp
	 * @return {string} Returns the string in format: Mon 14 Jul 2014 19:37:21
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
			'date': common.formatDateFromDateObject(date),
			'time': common.formatTimeFromDateObject(date)
		};
	},
		
	/**
	 * Formats the current local date from a date object
	 * @param {date} date A JavaScript date object
	 *  @return {string} Returns the string in format: 21 JUL 14
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
	 * @return {string} Returns the string in format: 19:37:21
	 */
	formatTimeFromDateObject: function(date)
	{	
		return this.leftPadding(date.getHours(), '0', 2) + ':' + this.leftPadding(date.getMinutes(), '0', 2) + ':' + this.leftPadding(date.getSeconds(), '0', 2);
	},
			
	/**
	 * Gets the index of a random MAC algorithm to use to create and verify the MAC for each message. It uses the 
	 * last byte of the one-time pad, converts it to an integer value, then uses that number mod the number of 
	 * MAC algorithms available. That will return an integer from 0, 1 which references the index of the algorithm 
	 * in an array.
	 * @param {string} pad The one-time pad for this message in hexadecimal
	 * @return {number} Returns a number (the array index) referencing the algorithm in the macAlgorithms array
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
	 * @param {string} pad The full pad in hexadecimal
	 * @returns {string} The pad to use to encrypt the MAC
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
	 * @param {integer} macAlgorithmIndex The MAC algorithm to use
	 * @param {string} pad The pad (key) as hexadecimal
	 * @param {string} ciphertextMessage The ciphertext (message) as hexadecimal
	 * @return {string} The MAC of the message and pad as hexadecimal
	 */
	createMessageMac: function(macAlgorithmIndex, pad, ciphertextMessage)
	{
		// Get which algorithm to use and generate the MAC
		var macAlgorithm = this.macAlgorithms[macAlgorithmIndex];
		
		// The new SHA3 competition algorithms Skein and Keccak are secure in the simple format of Hash(K, M) for a MAC. 
		// They have length extension attack prevention built in and do not need more complicated constructions like HMAC.
		var inputMessageHex = pad + ciphertextMessage;
				
		// Run the MAC algorithm
		return common.secureHash(macAlgorithm, inputMessageHex);		
	},
	
	/**
	 * Encrypt or decrypt the MAC with part of the one-time pad
	 * @param {string} padForMac Part of the pad to use for encrypting/decrypting the MAC in hexadecimal
	 * @param {string} mac The MAC or ciphertext MAC as hexadecimal
	 * @returns {string} Returns the encrypted or decrypted MAC in hexadecimal
	 */		
	encryptOrDecryptMac: function(padForMac, mac)
	{
		// Convert the pad and MAC to binary
		var padForMacBinary = common.convertHexadecimalToBinary(padForMac);
		var macBinary = common.convertHexadecimalToBinary(mac);	
		
		// Perform the encryption/decryption then convert the result back to hexadecimal
		var xoredMacBinary = common.encryptOrDecrypt(padForMacBinary, macBinary);
		var xoredMacHex = common.convertBinaryToHexadecimal(xoredMacBinary);
		
		return xoredMacHex;
	},
	
	/**
	 * Function for the receiver of a message to validate the message received by comparing the MAC. Then they can 
	 * check the integrity and authentication of the message by comparing the MAC to what was sent with the message. 
	 * The sender and receiver have a shared secret which is the one-time pad and the algorithm to be used to verify 
	 * the MAC is encoded with the message.
	 * @param {integer} macAlgorithmIndex The array index of MAC algorithm to use
	 * @param {string} pad The full pad as a hexadecimal string
	 * @param {string} ciphertextMessage The ciphertext of the message as a hexadecimal string	 
	 * @param {string} mac The plaintext MAC to be checked as a hexadecimal string
	 * @return {boolean} Returns true if valid, false if not 
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
	 * @param {string} plaintextMessageWithPaddingBinary The plaintext and any padding in binary
	 * @param {integer} messageLength The length of the actual message minus padding
	 * @param {integer} messageTimestamp The current UNIX timestamp in UTC
	 * @return {string} Returns binary string of all message parts
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
	 * @param {string} pad The one-time pad in hexadecimal
	 * @param {string} messagePartsBinary The message parts in binary
	 * @returns {string}
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
	 * @param {string} binary Pass in a pad in binary, or a full encrypted message in binary to retrieve the pad identifier
	 * @return {string} Returns just the message parts without the pad identifier
	 */
	getPadIdentifier: function(binary)
	{
		return binary.substr(0, this.padIdentifierSizeBinary);
	},
	
	/**
	 * Get the pad message parts from the pad. After that it can be XORed (pad message parts XOR plaintext message parts)
	 * @param {string} binaryPad Pass in a pad in binary
	 * @return {string} Returns just the message parts without the pad identifier
	 */
	getPadMessageParts: function(binaryPad)
	{
		return binaryPad.substr(this.padIdentifierSizeBinary, this.totalMessagePartsSizeBinary);
	},
	
	/**
	 * Function to encrypt or decrypt data by doing a bitwise exclusive or (XOR) on the one-time pad (key) and the plaintext.
	 * The pad and the plaintext/ciphertext being passed in should be the same length.
	 * To encrypt, pass in the one-time pad and the plaintext in binary
	 * To decrypt, pass in the one-time pad and the ciphertext in binary
	 * @param {string} binaryPad The pad/key (as a binary string) without the pad identifier
	 * @param {string} binaryText The plaintext or ciphertext as a binary string
	 * @returns {string} A binary string containing the XOR of the pad and text
	 */
	encryptOrDecrypt: function(binaryPad, binaryText)
	{
		var length = binaryText.length;
		var output = '';

		// For each binary character in the message
		for (var i=0; i < length; i++)
		{
			// Get binary number of the pad and plaintext
			var binaryPadChar = binaryPad.charAt(i);
			var binaryTextChar = binaryText.charAt(i);

			// XOR the binary character of the pad and binary text character together and append to output
			output += binaryPadChar ^ binaryTextChar;
		}

		return output;
	},
	
	/**
	 * Concatenates the pad identifier and ciphertext to make the full encrypted message
	 * After this the encrypted message can be converted to hexadecimal and is ready for sending
	 * @param {string} binaryPadIdentifier The pad identifier
	 * @param {string} binaryEncryptedMessageParts The encrypted message parts
	 * @return {string} Returns the complete encrypted message including pad identifier and encrypted message parts
	 */
	combinePadIdentifierAndCiphertext: function(binaryPadIdentifier, binaryEncryptedMessageParts)
	{
		return binaryPadIdentifier + binaryEncryptedMessageParts;
	},
	
	/**
	 * Get the separate message parts (plaintext with padding, the actual message length and the message timestamp)
	 * @param {string} decryptedUnreversedMessagePartsBinary The plaintext message parts joined together
	 * @return {array} Returns the message parts separated out into an array with keys 'messagePlaintextWithPaddingBinary', 'messageLength', 'messageTimestamp'
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
	 * @param {string} messagePlaintextWithPaddingBinary The plaintext message with padding on it
	 * @param {integer} actualMessageLength The actual message length in number of bytes
	 * @return {string} Returns the original plaintext message in binary
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
	 * @param {string} binaryText The binary numbers to be converted
	 * @returns {string} A string of ASCII characters
	 */
	convertBinaryToText: function(binaryText)
	{
		var output = '';
		var j = 0;

		// For each 8 binary characters convert to ASCII
		for (var i=0; i < binaryText.length; i = j)
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
	 * @param {string} binaryString The binary representation of the number
	 * @returns {integer}
	 */
	convertBinaryToInteger: function(binaryString)
	{
		return parseInt(binaryString, 2);
	},

	/**
	 * Converts text to binary string (one character at a time)
	 * @param {string} inputText The text to be converted
	 * @returns {string} A string of binary numbers
	 */
	convertTextToBinary: function(inputText)
	{
		var output = '';

		// For every character in the input text
		for (var i=0; i < inputText.length; i++)
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
	 * @param {integer} number The number to be converted to binary
	 * @param {integer} length The fixed length required in number of bits
	 * @returns {string} Returns the binary representation of the number
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
	 * @param {integer} number The number to be converted
	 * @returns {string} Returns the hexadecimal representation of the number
	 */
	convertIntegerToHexadecimal: function(number)
	{
		// Convert to hexadecimal and left pad it with 0s if it is not a full byte (numbers 0-9)
		var numberHex = number.toString(16);
		var numberWithPaddingBinary = common.leftPadding(numberHex, '0', 2);
		
		return numberWithPaddingBinary;
	},

	/**
	 * Converts binary code to hexadecimal string. All hexadecimal is lowercase for consistency with the hash functions
	 * These are used as the export format and compatibility before sending via JSON or storing in the database
	 * @param {string} binaryString A string containing binary numbers e.g. '01001101'
	 * @return {string} A string containing the hexadecimal numbers
	 */
	convertBinaryToHexadecimal: function(binaryString)
	{
		var output = '';
		
		// For every 4 bits in the binary string
		for (var i=0; i < binaryString.length; i+=4)
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
	 * @param {string} hexString A string containing single digit hexadecimal numbers
	 * @return {string} A string containing binary numbers
	 */
	convertHexadecimalToBinary: function(hexString)
	{
		var output = '';
		
		// For each hexadecimal character
		for (var i=0; i < hexString.length; i++)
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
	 * @param {string} inputString The string to be padded
	 * @param {string} padCharacter The character that the string should be padded with
	 * @param {number} totalCharacters The length of string that's required
	 * @returns {string} A string with characters appended to the front of it
	 */
	leftPadding: function(inputString, padCharacter, totalCharacters)
	{
		// Convert to string first, or it starts adding numbers instead of concatenating
		inputString = inputString.toString();
		
		// If the string is already the right length, just return it
		if (!inputString || !padCharacter || inputString.length >= totalCharacters)
		{
			return inputString;
		}

		// Work out how many extra characters we need to add to the string
		var charsToAdd = (totalCharacters - inputString.length)/padCharacter.length;

		// Add padding onto the string
		for (var i = 0; i < charsToAdd; i++)
		{
			inputString = padCharacter + inputString;
		}
		
		return inputString;
	},
	
	/**
	 * Round a number to specified decimal places
	 * @param {number} num The number to be rounded
	 * @param {number} decimals The number of decimal places to round to (use 0 for none)
	 * @returns {number} The number round to the specified decimal places
	 */
	roundNumber: function(num, decimals)
	{
		var newNum = new Number(num + '').toFixed(parseInt(decimals));
		return parseFloat(newNum);
	},
			
	/**
	 * Wrapper function to do all the work necessary to encrypt the message for sending. Also returns the encrypted 
	 * MAC as well. This will use random padding, get the current timestamp for the message and random MAC algorithm as well.
	 * @param {string} plaintextMessage The actual plaintext written by the user
	 * @param {string} pad The one-time pad as a hexadecimal string
	 * @return {array} Returns the ciphertext and MAC concatenated together ready to be sent
	 */
	encryptAndAuthenticateMessage: function(plaintextMessage, pad)
	{
		// Get the original length of the plaintext
		var originalPlaintextLength = common.getOriginalPlaintextLength(plaintextMessage);
		
		// Get the message with random variable length padding, but use the padding if it's passed in (for testing purposes)
		var plaintextMessageBinary = common.convertTextToBinary(plaintextMessage);
		var plaintextBinaryWithPadding = common.padMessage(plaintextMessageBinary);
				
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
		var encryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, messagePartsReversedBinary);
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
	 * @param {string} ciphertextHex The ciphertext as sent in hexadecimal string
	 * @return {string} Returns the portion of the ciphertext that is the pad identifier
	 */
	getPadIdentifierFromCiphertext: function(ciphertextHex)
	{
		return ciphertextHex.substr(0, this.padIdentifierSizeHex);
	},
	
	/**
	 * Get the encrypted MAC from the end of the ciphertext 
	 * @param {string} ciphertextHex
	 * @returns {string}
	 */
	getMacFromCiphertext: function(ciphertextHex)
	{
		return ciphertextHex.substr(this.padIdentifierSizeHex + this.totalMessagePartsSizeHex, this.totalPadSizeHex);
	},
	
	/**
	 * Gets the Pad identifier and ciphertext message parts from the full ciphertext which includes the MAC
	 * @param {string} ciphertextHex The full ciphertext that would be sent over the wire
	 * @returns {string} Returns the ciphertext without the MAC
	 */
	getCiphertextWithoutMac: function(ciphertextHex)
	{
		return ciphertextHex.substr(0, this.padIdentifierSizeHex + this.totalMessagePartsSizeHex);
	},
	
	/**
	 * Wrapper function to decrypt a received message and compare the MAC to see if it is valid or not. It will return 
	 * the plaintext, the timestamp of when the message was sent, and whether the message was validated or not.
	 * @param {string} ciphertext The ciphertext and ciphertext MAC concatenated together in hexadecimal string format
	 * @param {string} pad The pad to be used to decrypt the message. The pad to use can be found from the message identifier (first x symbols in the ciphertext)
	 * @return {array} Returns an array with the following keys 'plaintext', 'timestamp', 'valid'
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
		var decryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, ciphertextMessageParts);
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
	 * Create the one-time pads from the collected and extracted entropy
	 * @param {integer} numOfUsers The number of users in the group ie. 2, 3, 4, 5, 6, 7
	 * @param {string} randomDataHexadecimal A string of hexadecimal random data
	 * @return {array} Returns an array of pad objects. Each object contains keys 'padIdentifier' and 'pad'
	 */
	createPads: function(numOfUsers, randomDataHexadecimal)
	{
		var pads = {};
		
		// Initialise an array of pads for each user
		for (var i=0; i < numOfUsers; i++)
		{
			// Get the user e.g. 'alpha', 'bravo' etc and set that as the key to hold the pads
			var user = this.userList[i];
			pads[user] = [];
		}
		
		// Counters for loop
		var numOfPads = 0;
		var currentUserIndex = 0;
		var currentUser = 'alpha';
		
		// Loop through all the entropy hexadecimal chars
		for (var i=0, length = randomDataHexadecimal.length; i < length; i += this.totalPadSizeHex)
		{
			// Get the number of characters for the pad
			var pad = randomDataHexadecimal.substr(i, this.totalPadSizeHex);
			
			// If near the end of the string and we don't have enough for one more pad, don't use the remainder
			if (pad.length < this.totalPadSizeHex)
			{
				break;
			}
			
			// Store the pad in an object that can be easily retrieved later
			var padInfo = {
				'padIdentifier': pad.substr(0, this.padIdentifierSizeHex),	// A copy of the first x characters of the pad to identify which pad to use, separated for faster DB lookup
				'pad': pad													// The actual pad
			};
			
			// Add to array of pads for this user
			pads[currentUser].push(padInfo);
			
			// Update counters for next loop
			numOfPads++;
			currentUserIndex++;
			currentUser = this.userList[currentUserIndex];
						
			// Start back on first user
			if (currentUserIndex === numOfUsers)
			{
				currentUserIndex = 0;
				currentUser = this.userList[currentUserIndex];
			}
		}
		
		return pads;
	},
	
	/**
	 * Exports the random data to the clipboard in various formats or to a binary file
	 * @param {string} exportMethod How to export the data e.g. 'testExportBase64', 'testExportHexadecimal', 'testExportBinaryFile' or 'testExportBinaryString'
	 * @param {string} extractedRandomDataBinary The extracted entropy bits in binary
	 * @param {string} extractedRandomDataHexadecimal The extracted entropy bits in hexadecimal
	 */
	prepareRandomDataForExternalTesting: function(exportMethod, extractedRandomDataBinary, extractedRandomDataHexadecimal)
	{
		// Instructions for the popup prompt
		var instructions = 'Copy to clipboard (Ctrl + C) then paste into a plain text file';

		// Export to Base 64
		if (exportMethod.indexOf('Base64') !== -1)
		{
			// Convert to WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(extractedRandomDataHexadecimal);
			var output = CryptoJS.enc.Base64.stringify(words);
			
			// Export the Base64 to a dialog which lets the user copy from there to a text file
			window.prompt(instructions, output);
		}
		
		// Export to hexadecimal string
		else if (exportMethod.indexOf('Hexadecimal') !== -1)
		{			
			window.prompt(instructions, extractedRandomDataHexadecimal);
		}
		
		// Export to binary file
		else if (exportMethod.indexOf('BinaryFile') !== -1)
		{
			// Convert to hexadecimal then WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(extractedRandomDataHexadecimal);
			var output = CryptoJS.enc.Base64.stringify(words);
			
			// Output the binary file for the user to save
			location.href = 'data:application/octet-stream;base64,' + output;
		}
	},
	
	/**
	 * Export the pads to either clipboard, textfile or to the local machine database for each user.
	 * Each user gets allocated their own one-time pads for sending. This prevents each user from using 
	 * each other's pads which could cause them to use a pad more than once. If a one-time pad is used more 
	 * than once then cryptanalysis is possible.
	 * 
	 * @param {integer} numOfUsers The number of users in the group ie. 2, 3, 4, 5, 6, 7
	 * @param {string} exportForUser Who the pads are being exported for, e.g. alpha, bravo, charlie
	 * @param {array} userNicknames An array of objects containing the users and their nicknames, e.g. [{ user: 'alpha', nickname: 'Joshua' }, ...]
	 * @param {string} exportMethod How the pads will be exported. Pass in 'clipboard', 'textFile' or 'localDatabase'
	 * @param {string} serverAddressAndPort The server address to send/receive messages
	 * @param {string} serverKey The key to connect to the server and send/receive messages
	 * @param {string } extractedRandomDataHexadecimal The random data as a hexadecimal string
	 */
	preparePadsForExport: function(numOfUsers, userNicknames, exportForUser, exportMethod, serverAddressAndPort, serverKey, extractedRandomDataHexadecimal)
	{
		// Ssplit up the random data into separate pads
		var pads = common.createPads(numOfUsers, extractedRandomDataHexadecimal);
				
		// Clone the object storage schema
		var padData = db.clone(db.padDataSchema);
		
		// Set the values
		padData.info.programVersion = common.programVersion;
		padData.info.serverAddressAndPort = serverAddressAndPort;
		padData.info.serverKey = serverKey;
		padData.info.user = exportForUser;
		padData.info.userNicknames = userNicknames;
		padData.pads = pads;
				
		// Convert to JSON for export to clipboard or text file
		var padDataJson = JSON.stringify(padData);	
		
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
				alert('The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new plain text file.');
			}
			else {
				// Set parameters
				var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
				var nickname = padData.info.userNicknames[exportForUser].toLowerCase();
				var filename = 'one-time-pads-user-' + nickname + '.txt';
				
				// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
				saveAs(blob, filename);
			}
		}
		else {
			// Save to current machine local database
			db.saveNewPadDataToDatabase(padData);
			
			// Show success message
			common.showStatus('success', 'Pads saved successfully to local database.');
		}
	},
	
	/**
	 * This lets a user move the pads from one computer/device to another. Because pads are deleted once
	 * they are sent/received then it's not a good idea to just import the original text file of pads 
	 * because that could easily lead to pad re-use. This will copy the current remaining pads from the 
	 * local database to the clipboard or text file.
	 * @param {string} exportMethod How the pads will be exported. Pass in 'clipboard', 'textFile'
	 */
	preparePadsForBackup: function(exportMethod)
	{
		// Convert to JSON for export to clipboard or text file
		var padDataJson = JSON.stringify(db.padData);	

		// Export to a dialog which lets the user copy from there to a text file
		if (exportMethod == 'clipboard')
		{							
			window.prompt('Copy to clipboard (Ctrl + C) then paste into text file', padDataJson);
		}
		else if (exportMethod == 'textFile')
		{
			// Check for the various File API support
			if ((window.File && window.FileReader && window.FileList && window.Blob) === false)
			{
				alert('The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new text file.');
			}
			else {
				// Set text file download parameters
				var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
				var nickname = db.padData.info.userNicknames[db.padData.info.user].toLowerCase();
				var filename = 'one-time-pads-backup-user-' + nickname + '.txt';
				
				// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
				saveAs(blob, filename);
			}
		}
	},
	
	/**
	 * Gets the data back from JSON format and saves it to the two database tables
	 * @param {string} padDataJson The one-time pads and meta data in JSON format
	 */
	preparePadDataForImport: function(padDataJson)
	{
		// Parse the serialized data into a JavaScript object and save to the database
		db.padData = JSON.parse(padDataJson);
		db.savePadDataToDatabase();
	},
		
	/**
	 * Load the one-time pads from a text file
	 * @param {event} evt The event object
	 */
	loadPadsFromTextFile: function(evt)
	{
		// FileList object
		var files = evt.target.files;
		var file = files[0];
		
		// List some properties
		var fileInfo = 'Pads loaded: ' + file.name + ', ' + file.type + ', ' + file.size + ' bytes.';
		
		// Set up to read from text file
		var reader = new FileReader();
		reader.readAsText(file);

		// Closure to read the file information
		reader.onload = (function(theFile)
		{
			return function(e)
			{
				// Send the JSON to be loaded to the database
				common.preparePadDataForImport(e.target.result);
				
				// Log loaded file info to console
				common.showStatus('success', 'Pads loaded successfully. ' + fileInfo);
			};
		})(file);
	},
	
	/**
	 * Remove non ASCII characters from the plaintext message and cut the 
	 * message short if they have exceeded the maximum size allowed
	 * @param {string} plaintext The plaintext to remove invalid characters from
	 * @return {string} A clean ASCII string
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
	 * @return {string|false} Returns the pad to be used, or false if none available
	 */
	getPadToEncryptMessage: function()
	{
		// Initialisations
		var user = db.padData.info.user;
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
	 * @param {string} ciphertextHex The ciphertext and MAC in hexadecimal format
	 * @param {string} fromUser Which user the message is from
	 * @return {object} Returns an object with properties 'padIndex', 'padIdentifier' and 'pad'
	 */
	getPadToDecryptMessage: function(ciphertextHex, fromUser)
	{
		// Initialisations
		var numOfPads = db.padData.pads[fromUser].length;
		var padIdentifier = this.getPadIdentifierFromCiphertext(ciphertextHex);
		var padIndex = null;
		var pad = null;
		
		// For each pad in memory for the user find the first one that we can send
		for (var i=0; i < numOfPads; i++)
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
	 * @param {string} serverAddress The url of the server where the files are e.g. http://mydomain.com or http://mydomain.com/otpchat/
	 * @param {string} page The page to be accessed e.g. index.php
	 * @return {string} The correct url e.g. http://mydomain/otpchat/index.php
	 */
	standardiseUrl: function(serverAddress, page)
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
	 * @param {string} string The string to replace characters in
	 * @return {string} The escaped string
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
	 * Shows a success or error message
	 * @param {string} type The type of the error which will match the CSS class 'success' or 'error'
	 * @param {string} message The error or success message
	 */
	showStatus: function(type, message)
	{
		// Escape for XSS just in case a message is coming back from the server
		message = this.htmlEncodeEntities(message);
		
		// Remove existing CSS classes and add the class depending on the type of message
		$('.statusMessage').removeClass('success error').addClass(type);
		
		// Show the message for 14 seconds then fade it out
		$('.statusMessage').html(message).show().delay(14000).fadeOut(300);
	},
		
	/**
	 * Wrapper around the various hash functions from different libraries and options to keep the output format consistent
	 * @param {string} algorithm The name of the algorithm to run ('keccak-512' or 'skein-512')
	 * @param {string} messageHex The string to be hashed in hexadecimal
	 * @return {string} The hashed message as hexadecimal
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
	 * Gets a random 512 bit nonce from the Web Crypto API
	 * @returns {String} Returns a random hexadecimal string with length of 128 hexadecimal symbols (512 bits/64 bytes)
	 */
	getRandomNonce: function()
	{
		var nonceBitLength = 512;
		var randomBits = '';		
		
		// Gather until we have 512 random bits
		while (randomBits.length < nonceBitLength)
		{		
			// Collect a random number from the Web Crypto API
			var byteArray = new Uint32Array(1);
			window.crypto.getRandomValues(byteArray);
			
			// Convert the typed integer to a string so we can check the length
			var randomNum = byteArray[0].toString();
			
			// For every integer in the random number
			for (var i=0, length = randomNum.length; i < length; i++)
			{
				// Convert each integer to a single bit. If the integer is (0-4) then output a 0 bit, if the integer 
				// is (5-9) then output a 1 bit. This will provide a uniform distribution of bits from the numbers 0-9.
				randomBits += (randomNum.charAt(i) < 5) ? '0' : '1';
			}
		}
		
		// Shorten to exactly 512 bits because above process will sometimes return more bits 
		// than necessary due to the varying length of numbers returned from the Web Crypto API
		randomBits = randomBits.substr(0, nonceBitLength);
		
		// Hash the bits to prevent leakage of internal RNG state (in case there is a bug in the Web Crypto API)
		var randomBitsHex = this.convertBinaryToHexadecimal(randomBits);
		var hashedRandomBitsHex = this.secureHash('keccak-512', randomBitsHex);
				
		// Convert the bits to hexadecimal
		return hashedRandomBitsHex;
	},
	
	/**
	 * Test that the server and database connection is working from the client
	 * @param {string} serverAddressAndPort
	 * @param {string} serverKey
	 */
	testServerConnection: function(serverAddressAndPort, serverKey)
	{
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
			common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseDataJson)
			{
				// If the server response is authentic
				if (validResponse)
				{
					// Convert from JSON to object
					var responseData = JSON.parse(responseDataJson);

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
					common.showStatus('error', 'Error contacting server. Double check you are connected to the network and that the client and server configurations are correct. Another possibility is that the data was modified in transit by an attacker.');
				}
			});
		}
	},
		
	/**
	 * Sends a request to the server and performs a specific API action on the server
	 * @param {object} data The data to be sent to the server
	 * @param {string} serverAddressAndPort The server address and port
	 * @param {string} serverKey The hexadecimal server key
	 * @param {string} callbackFunction The name of the callback function to run when complete
	 */
	sendRequestToServer: function(data, serverAddressAndPort, serverKey, callbackFunction)
	{
		// Fix the url for any excess slashes
		var fullServerAddress = common.standardiseUrl(serverAddressAndPort, 'index.php');
		
		// Add a random nonce and the current timestamp to the data to be sent
		data['nonce'] = common.getRandomNonce();
		data['timestamp'] = common.getCurrentUtcTimestamp();
		
		// Convert to JSON and MAC the request data
		var requestDataJson = JSON.stringify(data);			
		var requestMac = this.authenticateRequest(requestDataJson, serverKey);
		
		// Create AJAX request to chat server
		$.ajax(
		{
			url: fullServerAddress,
			type: 'POST',
			dataType: 'json',
			timeout: 14000,					// Timeout at 14 seconds
			data: {
				'data': requestDataJson,
				'mac': requestMac
			}
		})
		.done(function(responseData)
		{
			// Check if the response was really from the server
			var validResponse = common.validateServerResponse(serverKey, responseData, requestMac);

			// Return back to the calling function so it can process the response
			callbackFunction(validResponse, responseData.data);
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
	 * @param {string} dataJson The JSON data to be sent to the server
	 * @param {string} serverKey The server key as a hexadecimal string
	 * @returns {string} Returns the MAC as a hexadecimal string
	 */
	authenticateRequest: function(dataJson, serverKey)
	{
		// Convert the data to hexadecimal so it's in the same format as the key
		var dataJsonBinary = common.convertTextToBinary(dataJson);
		var dataJsonHex = common.convertBinaryToHexadecimal(dataJsonBinary);	

		// MAC the response by doing Hash(K, M)
		return common.secureHash('skein-512', serverKey + dataJsonHex);
	},
	
	/**
	 * Validates the server response to make sure it came back from the real server. It also checks 
	 * that the response it sent was a direct response to the request it was sent. It does this by 
	 * performing a MAC using the Skein-512 hash algorithm on the request data and the response data 
	 * with the server key then comparing that with the MAC sent back from the server.
	 * @param {string} serverKey The hexadecimal server key
	 * @param {object} responseData The data from the response which should contain the JSON data and the MAC
	 * @param {string} requestMac The MAC of the data sent to the server
	 * @returns {Boolean} Whether the response was valid or not
	 */
	validateServerResponse: function(serverKey, responseData, requestMac)
	{
		// Check the data actually came back from the request
		if ((responseData.data !== undefined) && (responseData.mac !== undefined))
		{
			// Validate the response from the server			
			var validResponse = common.validateResponseMac(serverKey, responseData.data, requestMac, responseData.mac);
			
			// Return if the response was valid or not
			return validResponse;
		}
		
		// Return failure
		return false;
	},
		
	/**
	 * Function to validate the response from the server
	 * @param {string} serverKey The server key
	 * @param {string} responseDataJson The server response JSON data
	 * @param {string} requestMac The MAC that was sent to the server	 
	 * @param {string} responseMac The server response MAC	 
	 * @returns {boolean} Returns whether the server response is valid or not
	 */
	validateResponseMac: function(serverKey, responseDataJson, requestMac, responseMac)
	{
		// Convert the response data to hexadecimal
		var responseDataJsonBinary = common.convertTextToBinary(responseDataJson);
		var responseDataJsonHex = common.convertBinaryToHexadecimal(responseDataJsonBinary);
		
		// Perform the MAC - the order should match the PHP code
		var macToCheck = common.secureHash('skein-512', serverKey + responseDataJsonHex + requestMac);
		
		// Check the calculated MAC matches the one from the server
		return (macToCheck === responseMac) ? true : false;
	},
	
	/**
	 * Saves just the server connection details to local storage
	 * @param {string} serverAddressAndPort
	 * @param {string} serverKey
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
	 * @return {boolean}
	 */
	checkLocalStorageSupported: function()
	{
		try	{
			return 'localStorage' in window && window['localStorage'] !== null;
		}
		catch (e)
		{
			return false;
		}
	},
	
	/**
	 * Checks if the HTML5 Web Workers are supported
	 * @returns {boolean}
	 */
	checkWebWorkerSupported: function()
	{
		return !!window.Worker;
	},
	
	/**
	 * Checks if the HTML5 Web Crypto API getRandomValues functon is supported
	 * @returns {boolean}
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
		catch (e)
		{
			return false;
		}
	},
	
	/**
	 * Checks if HTML5 Offline Web Application Cache is supported
	 * @returns {boolean}
	 */
	checkOfflineWebApplicationSupported: function()
	{
		return !!window.applicationCache;
	},
	
	/**
	 * Shows how long it took to process the data up to this point
	 * @param {string} message The status message to be displayed
	 * @param {boolean} showTimeElapsed Whether to show how long it has taken so far, turn this off if just starting the process
	 */
	showProcessingMessage: function(message, showTimeElapsed)
	{
		// Current time
		var currentTime = new Date();
		
		// Calculate time taken in milliseconds and seconds
		var milliseconds = currentTime.getTime() - common.startTime.getTime();
		var seconds = (milliseconds / 1000).toFixed(3);
		
		// Show the time the process started if applicable
		var timeElapsedMessage = (showTimeElapsed) ? ' Total time elapsed: ' + milliseconds + ' ms (' + seconds + ' s)' : '';
			
		// Show status on page
		$('.processingStatus').html(message + timeElapsedMessage);
	},
		
	/**
	 * Formats the number with thousands separator
	 * @param {integer} num Pass in number e.g. 2000000
	 * @returns {string} Returns in format 2,000,000
	 */
	formatNumberWithCommas: function(num)
	{
		return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
	},
	
	/**
	 * Capitalises the first letter of a string
	 * @param {string} text
	 * @returns {string}
	 */
	capitaliseFirstLetter: function(text)
	{
		return text.charAt(0).toUpperCase() + text.slice(1);
	},
	
	/**
	 * Configure the Export Pads dialog to open and all functionality within
	 */
	initExportPadsDialog: function()
	{
		// Configure button to open entropy collection settings dialog
		$('#btnOpenExportPadsSettings').click(function()
		{					
			$('#exportPadsSettings').dialog('open');
		});

		// Configure entropy collection settings dialog
		$('#exportPadsSettings').dialog(
		{
			autoOpen: false,
			create: function (event)
			{
				// Set the dialog position as fixed before opening the dialog. See: http://stackoverflow.com/a/6500385
				$(event.target).parent().css('position', 'fixed');
			},
			resizable: false,
			width: 'auto'
		});
		
		// Initialise other functionality within the dialog
		common.dynamicallySetNicknameTextEntry();
		common.hideOptionsDependingOnExportMethod();
		common.initCreateServerKeyButton();
		common.initExportPadsButton();
		common.preloadServerConnectionDetails();
		common.initTestServerConnectionButton();
	},
	
	/**
	 * When the number of users changes, enable/disable options in the Export for user 
	 * select box and dynamically alter the number of user nicknames they can enter
	 */
	dynamicallySetNicknameTextEntry: function()
	{		
		$('#numOfUsers').change(function()
		{
			// Get the number of users
			var numOfUsers = parseInt($(this).val());
			var options = '';
			var nicknames = '';

			// Build the dropdown options dynamically
			for (var i=0; i < numOfUsers; i++)
			{
				options += '<option value="' + common.userList[i] + '">' + common.userList[i] + '</option>';
			}

			// Build list of users so the user can edit the user nicknames
			for (var i=0; i < numOfUsers; i++)
			{
				// Build the HTML to be rendered inside the dialog
				var nicknameCapitalised = common.capitaliseFirstLetter(common.userList[i]);
				nicknames += '<label>' + nicknameCapitalised + '</label> '
						  +  '<input id="nickname-' + common.userList[i] + '" type="text" maxlength="12" value="' + nicknameCapitalised + '"><br>';
			}

			// Display the options
			$('#exportForUser').html(options);
			$('.nicknames').html(nicknames);
		});
	},
	
	/**
	 * Hide or show the last option in the dialog if the export method is changed
	 */
	hideOptionsDependingOnExportMethod: function()
	{		
		$('#exportMethod').change(function()
		{
			var exportMethod = $(this).val();

			// If the pads will be exported for actual use show the Export for User option
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard') || (exportMethod === 'localDatabase'))
			{
				$('.exportForUserRow').show();
			}
			else {
				// Otherwise export for testing so hide the Export for User option
				$('.exportForUserRow').hide();
			}					
		});
	},
	
	/**
	 * Creates a 512 bit server key from the random, extracted 
	 * data and puts it in the export dialog's text field
	 */
	initCreateServerKeyButton: function()
	{
		$('#btnCreateServerKey').click(function()
		{
			// Check there is enough data to create a 512 bit key (128 hexadecimal symbols)
			if (common.randomDataHexadecimal.length < 128)
			{
				common.showStatus('error', 'Not enough bits remaining to create a full 512 bit key.');
			}
			else {
				// Take the first 512 bits of the extracted data and convert it to hexadecimal
				var serverKeyHex = common.randomDataHexadecimal.slice(0, 128);

				// After removing the first 512 bits, use the remainder of the bits for the one-time pads
				common.randomDataHexadecimal = common.randomDataHexadecimal.slice(128);

				// Put it in the text field
				$('#serverKey').val(serverKeyHex);
			}
		});
	},
	
	/**
	 * Initialise the button to export the one-time pads or random data for external testing
	 */
	initExportPadsButton: function()
	{
		// Export the pads
		$('#btnExportPads').click(function()
		{
			// Get the selected export method
			var exportMethod = $('#exportMethod').val();

			// Export to text, file or database depending on user selection
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard') || (exportMethod === 'localDatabase'))
			{
				var numOfUsers = parseInt($('#numOfUsers').val());
				var exportForUser = $('#exportForUser').val();
				var serverAddressAndPort = $('#serverAddressAndPort').val();
				var serverKey = $('#serverKey').val();						
				var userNicknames = {};

				// Loop through the number of users
				for (var i=0; i < numOfUsers; i++)
				{
					// Get the user, nickname, then filter the nickname field so only A-z and 0-9 characters allowed
					var user = common.userList[i];
					var nickname = $('#nickname-' + common.userList[i]).val();
						nickname = nickname.replace(/[^A-Za-z0-9]/g, '');

					// If the nickname field has nothing, then use the default user name e.g. Alpha, Bravo
					if (nickname === '')
					{
						// Capitalise the default user
						nickname = common.userList[i];
						nickname = common.capitaliseFirstLetter(nickname);
					}

					// Store the nickname as a key next to the user
					userNicknames[user] = nickname;
				}

				// Export the pads
				common.preparePadsForExport(numOfUsers, userNicknames, exportForUser, exportMethod, serverAddressAndPort, serverKey, common.randomDataHexadecimal);
			}
			else {
				// Otherwise export the random data for testing using external methods
				common.prepareRandomDataForExternalTesting(exportMethod, common.randomDataBinary, common.randomDataHexadecimal);
			}
		});
	},
	
	/**
	 * Preload values into the text boxes if they already have connection settings in local storage
	 */
	preloadServerConnectionDetails: function()
	{
		// If they already have connection settings in local storage
		if (db.padData.info.serverAddressAndPort !== null)
		{
			// Load from local storage into the text fields
			$('#serverAddressAndPort').val(db.padData.info.serverAddressAndPort);
			$('#serverUsername').val(db.padData.info.serverUsername);
			$('#serverKey').val(db.padData.info.serverKey);
		}
	},
	
	/**
	 * Test the server connection when the button is clicked
	 */
	initTestServerConnectionButton: function()
	{						
		$('#testServerConnection').click(function()
		{
			// Get values from text inputs
			var serverAddressAndPort = $('#serverAddressAndPort').val();
			var serverKey = $('#serverKey').val();

			// Check connection and show success or failure message on screen
			common.testServerConnection(serverAddressAndPort, serverKey);
		});
	}
};