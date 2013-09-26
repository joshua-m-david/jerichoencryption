/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software, design and associated documentation files (the "Software"), 
	to deal in the Software including without limitation the rights to use, copy, 
	modify, merge, publish, distribute, and to permit persons to whom the Software 
	is furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies of the Software and any other software that utilises part or all
	   of the Software (the "Derived Software").
	2) Neither the Software nor any Derived Software may be sold, published, 
	   distributed or otherwise dealt with for financial gain without the express
	   consent of the copyright holder.
	3) Derived Software must not use the same name as the Software.
	4) The Software and Derived Software must not be used for evil purposes.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

/**
 * Various and common functions used by multiple pages
 */
var common = {
	
	// Define lengths of message attributes
	padIdentifierSize: 7,		// Size of the pad identifier in ASCII. The first 7 characters of pad are used only to identify which pad was used.
	messageSize: 100,			// The max length of a plaintext message in ASCII.
	messageLengthSize: 3,		// An attribute to define how long the actual message was in ASCII without any padding. Always 3 digits e.g. 070, 005, 138.
	messageTimestampSize: 10,	// The UNIX timestamp of when the message was sent
	macAlgorithmSize: 1,		// The index of the MAC algorithm to use to verify the message integrity and authenticity
	macSize: 64,				// The Message Authentication Code
	totalMessagePartsSize: 114,	// The total length of the message parts in ASCII (message + message length + timestamp + mac algorithm index)
	totalPadSize: 185,			// The total length of each pad in ASCII
	
	// Hexadecimal representation for above variables
	padIdentifierSizeHex: 14,
	messageSizeHex: 200,
	messageLengthSizeHex: 6,
	messageTimestampSizeHex: 20,
	macAlgorithmSizeHex: 2,
	macSizeHex: 128,
	totalMessagePartsSizeHex: 228,	
	totalPadSizeHex: 370,
	
	// Binary representation for above variables
	padIdentifierSizeBinary: 56,
	messageSizeBinary: 800,
	messageLengthSizeBinary: 24,
	messageTimestampSizeBinary: 80,
	macAlgorithmSizeBinary: 8,
	macSizeBinary: 512,
	totalMessagePartsSizeBinary: 912,
	totalPadSizeBinary: 1480,
	
	// Set the possible hashing algorithms to use for hashing the entropy. Note: 
	// these algorithms (and libraries) must be capable of working inside a Web Worker
	hashAlgorithms: ['sha2-512', 'sha3-512', 'whirlpool-512'],
	
	// MAC algorithms to be used
	macAlgorithms: ['hmac-sha2-512', 'hmac-sha3-512', 'hmac-skein-512'],
	
	/**
	 * Allowed printable ASCII chars from hexadecimal 21 - 7E (decimal 32 - 126)
	 */
	allPossibleChars: [
		' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 
		'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 
		'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'
	],
		
	/**
	 * Calculates the length of the plaintext message without any padding then formats it as a 3 digit string. In other words
	 * it will left pad the value with zeros up to the message length size (3 chars) so we have a consistent length for this field
	 * @param {string} plaintextMessage The plaintext message
	 * @return {string} Returns the original length of the message before padding e.g. 070, 005, 138.
	 */
	getOriginalPlaintextLength: function(plaintextMessage)
	{
		var messageLength = plaintextMessage.length;
		
		// If the message is somehow bigger than the allowed message size (maybe they bypassed the text field maxlength)
		if (messageLength > this.messageSize)
		{
			// Return the max length allowed, the message will be truncated by the padMessage function
			return common.leftPadding(this.messageSize, '0', this.messageLengthSize).toString();
		}
		else {
			// Return the actual size
			return common.leftPadding(messageLength, '0', this.messageLengthSize).toString();
		}
	},
	
	/**
	 * Pad a message with random numbers up to the length of the message. Random numbers will be added to the 
	 * right of the message. This is so that all messages will be the same length to frustrate cryptanalysis.
	 * @param {string} plaintextMessage The plaintext message to be padded
	 * @return {string} Returns a string with length up to the maximum string length
	 */
	padMessage: function(plaintextMessage)
	{		
		var currentMessageLength = plaintextMessage.length;
		
		// If the message is somehow bigger than the allowed message size (maybe they bypassed the 
		// text field maxlength), then truncate it up to the maximum message size
		if (currentMessageLength > this.messageSize)
		{
			return plaintextMessage.substr(0, this.messageSize);
		}
		else if (currentMessageLength == this.messageSize)
		{
			// If it's already the max length just return it
			return plaintextMessage;
		}
		else {
			// Otherwise add random numbers up to message size
			while (currentMessageLength < this.messageSize)
			{
				// Collect a random number
				var byteArray = new Uint32Array(1);
				window.crypto.getRandomValues(byteArray);
				
				// Add to the plaintext and update the current length
				plaintextMessage += byteArray[0].toString();
				currentMessageLength = plaintextMessage.length;
			}
			
			// Sometimes the getRandomValues returns variable sized numbers and it would put it oversize so truncate it
			return plaintextMessage.substr(0, this.messageSize);
		}
	},
	
	/**
	 * Get the current UNIX timestamp in UTC and make sure it's 10 characters long
	 * @return {string} The current timestamp
	 */
	getCurrentUtcTimestamp: function()
	{
		var currentTimestamp = Math.floor(Date.now() / 1000);		
		return this.leftPadding(currentTimestamp, '0', 10);
	},
	
	/**
	 * Gets the current local date and time
	 * @return {string} Returns the string in format: Mon 14 Jul 2014 19:37:21
	 */
	getCurrentLocalDateTime: function()
	{
		return this.formatDateTimeFromDateObject(new Date());
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
		
		// Return date formatted
		return this.formatDateTimeFromDateObject(date);
	},
	
	/**
	 * Gets the current local date and time from a date object passed in
	 * @param {date} date A JavaScript date object
	 * @return {string} Returns the string in format: Mon 14 Jul 2014 19:37:21
	 */
	formatDateTimeFromDateObject: function(date)
	{
		// Short names for days and months
		var dayNamesShort = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
		var monthNamesShort = ['Jan', 'Feb', 'Mar', 'Apr', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
		
		// Build string		
		var dateTime = dayNamesShort[date.getDay()] + ' ' + date.getDate() + ' ' + monthNamesShort[date.getMonth()] + ' ' + date.getFullYear() + ' '  
                     + this.formatTimeFromDateObject(date);
		
		return dateTime;
	},
	
	/**
	 * Gets the current local time from a date object passed in
	 * @param {date} date A JavaScript date object
	 * @return {string} Returns the string in format: 19:37:21
	 */
	formatTimeFromDateObject: function(date)
	{	
		return this.leftPadding(date.getHours(), '0', 2) + ":" + this.leftPadding(date.getMinutes(), '0', 2)  + ":" + this.leftPadding(date.getSeconds(), '0', 2);
	},
		
	/**
	 * Gets a random integer inbetween the minimum and maxium passed in. It gets a random number from the Web 
	 * Crypto API and then uses rejection sampling (see http://en.wikipedia.org/wiki/Rejection_sampling).
	 * Depending on the maximum value wanted it will get a 8 bit, 16 bit or 32 bit unsigned integer from the 
	 * API. For example if a small number between 0 and 10 is wanted it will just get an 8 bit number from the 
	 * API rather than a 32 bit number which is unnecessary.
	 * @param {number} min The minimum number allowed. The minimum this function will allow is 0.
	 * @param {number} max The maximum number allowed. The maximum this function will allow is 4294967295.
	 * @returns {number} A random number between the minimum and maximum
	 */
	getRandomIntInRange: function(min, max)
	{
		var maxRange = null;
		var byteArray = null;
		var range = max - min + 1;
		
		// If the maximum is less than 255, get a small 8 bit unsigned integer
		if ((max >= 1) && (max <= 255))
		{
			maxRange = 256;
			byteArray = new Uint8Array(1);
		}
		else if ((max >= 256) && max <= 65535)
		{
			// If the maximum is inbetween 256 and 65535, get a random 16 bit unsigned integer
			maxRange = 65536;
			byteArray = new Uint16Array(1);
		}
		else {
			// Otherwise get a 32 bit unsigned random integer
			maxRange = 4294967296;
			byteArray = new Uint32Array(1);
		}
		
		// Fill the byte array with a random number
		window.crypto.getRandomValues(byteArray);

		// If the random number is outside of the range, get another
		if (byteArray[0] >= Math.floor(maxRange / range) * range)
		{
			return this.getRandomIntInRange(min, max);
		}

		return min + (byteArray[0] % range);
	},
	
	/**
	 * Perform a Fisher Yates shuffle with help from the Web Crypto API rather than Math.random(). It uses the 
	 * algorithm specified here: http://bost.ocks.org/mike/shuffle/ which basically loops through the array 
	 * backwards, and each time through it swaps the current item with a random item.
	 * @param {array} dataArray The array to be shuffled
	 * @returns {array} Returns the shuffled array
	 */ 
	shuffleArray: function(dataArray)
	{
		// Initialisations
		var counter = dataArray.length, temp, index;

		// While there are elements in the array
		while (counter > 0)
		{
			// Get a random number between 0 and current counter
			index = common.getRandomIntInRange(0, counter - 1);

			// Decrease counter
			counter--;

			// And swap the last element with it
			temp = dataArray[counter];
			dataArray[counter] = dataArray[index];
			dataArray[index] = temp;
		}

		return dataArray;
	},
		
	/**
	 * Gets the index of a random MAC algorithm to use to create and verify the MAC
	 * @return {number} Returns a number (array index) referencing the algorithm in the macAlgorithms array
	 */
	getRandomMacAlgorithmIndex: function()
	{
		// Set min and max
		var min = 0;
		var max = this.macAlgorithms.length - 1;
		
		// Get random index
		return this.getRandomIntInRange(min, max);
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
		var padForMac = pad.substr(startIndex, common.totalPadSizeHex);
		
		return padForMac;
	},
		
	/**
	 * Generate a Message Authentication Code for the message. This is to 
	 * verify the data integrity and the authentication of each message sent.
	 * @param {string} macAlgorithmIndex The MAC algorithm to use
	 * @param {string} pad The pad (key)
	 * @param {string} ciphertextMessage The ciphertext (message)
	 * @return {string} The MAC of the message and pad
	 */
	createMac: function(macAlgorithmIndex, pad, ciphertextMessage)
	{
		// Get which algorithm to use and generate the MAC
		var macAlgorithm = this.macAlgorithms[macAlgorithmIndex];
		
		// Run the MAC algorithm
		return this.secureMac(macAlgorithm, pad, ciphertextMessage);		
	},
	
	/**
	 * Encrypt or decrypt the MAC with part of the one-time pad
	 * @param {string} padForMac Part of the pad to use for encrypting/decrypting the MAC
	 * @param {string} mac The MAC or ciphertext MAC
	 * @returns {string} Returns the encrypted or decrypted MAC in hexadecimal
	 */		
	encryptOrDecryptMac: function(padForMac, mac)
	{
		// Convert the pad and MAC to binary
		var padForMacBinary = common.convertHexadecimalToBinary(padForMac);
		var macBinary = common.convertHexadecimalToBinary(mac);	
		
		// Perform the encryption/decryption then convert the result back to hexadecimal
		var xoredMacBinary = common.encryptOrDecrypt(padForMacBinary, macBinary);
		var xoredMac = common.convertBinaryToHexadecimal(xoredMacBinary);
		
		return xoredMac;
	},
	
	/**
	 * Function for the receiver of a message to validate the message received by comparing the MAC. Then they can 
	 * check the integrity and authentication of the message by comparing the MAC to what was sent with the message. 
	 * The sender and receiver have a shared secret which is the one-time pad and the algorithm to be used to verify 
	 * the MAC is encoded with the message.
	 * @param {string} macAlgorithmIndex
	 * @param {string} pad The full pad as a hexadecimal string
	 * @param {string} ciphertextMessage The ciphertext of the message as a hexadecimal string	 
	 * @param {string} mac The plaintext MAC to be checked as a hexadecimal string
	 * @return {boolean} Returns true if valid, false if not 
	 */
	validateMac: function(macAlgorithmIndex, pad, ciphertextMessage, mac)
	{		
		// Make sure the macAlgorithmIndex contains positive integer only
		if (/^\d+$/.test(macAlgorithmIndex))
		{
			// Convert to an integer
			macAlgorithmIndex = parseInt(macAlgorithmIndex);
		}
		else {
			// Otherwise if it's not an integer it could indicate the MAC index part has been altered in the message by an attacker so set it 
			// to 0 (the first algorithm) so the code won't error but will now likely fail validation due to incorrect algorithm being checked
			macAlgorithmIndex = 0;
		}
		
		// Recreate the MAC, if it matches the one sent, then message hasn't been altered
		var macToTest = this.createMac(macAlgorithmIndex, pad, ciphertextMessage);
		return (macToTest == mac) ? true : false;
	},
		
	/**
	 * Uses a Fisher-Yates Shuffle to mix up the order of the hash algorithms.
	 * This method works better for arrays with few items than the Knuth shuffle above.
	 * @param {array} hashAlgorithms The list of hash algorithms to shuffle
	 * @return {array} The shuffled hash algorithms
	 */
	shuffleAlgorithms: function(hashAlgorithms)
	{
		// Initialisations
		var counter = hashAlgorithms.length, temp, index, byteArray, randomNum;

		// While there are elements in the array
		while (counter > 0)
		{
			// Get a random number
			byteArray = new Uint8Array(1);
			window.crypto.getRandomValues(byteArray);
			randomNum = '0.' + byteArray[0].toString();
			
			// Get random index		
			index = Math.floor(randomNum * counter);

			// Decrease counter by 1
			counter--;

			// And swap the last element with it
			temp = hashAlgorithms[counter];
			hashAlgorithms[counter] = hashAlgorithms[index];
			hashAlgorithms[index] = temp;
		}

		return hashAlgorithms;
	},
	
	/**
	 * Prepares the message to be encrypted, basically just appends the plaintext, message length, message timestamp and mac algorithm index
	 * together then converts them to a binary string. The message portion should now be 143 characters and is ready to be encrypted
	 * @param {string} plaintextMessageWithPadding The plaintext and any padding
	 * @param {string} messageLength The length of the actual message minus padding
	 * @param {string} messageTimestamp The current UNIX timestamp in UTC
	 * @param {number} macAlgorithmIndex The index of the algorithm to use in creating and verifying the MAC
	 * @return {string} Returns binary string of all message parts
	 */
	prepareMessageForEncryption: function(plaintextMessageWithPadding, messageLength, messageTimestamp, macAlgorithmIndex)
	{		
		var messageParts = plaintextMessageWithPadding + messageLength.toString() + messageTimestamp.toString() + macAlgorithmIndex.toString();		
		var messagePartsBinary = this.convertTextToBinary(messageParts);
		
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
	 * @param {string} decryptedPlaintextMessageParts The plaintext message parts joined together
	 * @return {array} Returns the message parts separated out into an array with keys 'messagePlaintextWithPadding', 'messageLength', 'messageTimestamp'
	 */
	getSeparateMessageParts: function(decryptedPlaintextMessageParts)
	{
		var messagePlaintextWithPadding = decryptedPlaintextMessageParts.substr(0, this.messageSize);
		var actualMessageLength = decryptedPlaintextMessageParts.substr(this.messageSize, this.messageLengthSize);
		var messageTimestamp = decryptedPlaintextMessageParts.substr(this.messageSize + this.messageLengthSize, this.messageTimestampSize);
		var macAlgorithmIndex = decryptedPlaintextMessageParts.substr(this.messageSize + this.messageLengthSize + this.messageTimestampSize, this.macSize);
		
		return {
			'messagePlaintextWithPadding': messagePlaintextWithPadding,
			'messageLength': actualMessageLength,
			'messageTimestamp': messageTimestamp,
			'macAlgorithmIndex': macAlgorithmIndex
		};
	},
	
	/**
	 * Removes padding from the message portion. This checks to make sure the message length is 
	 * in the correct range for a message to avoid DOS and/or buffer overflow attacks.
	 * @param {string} plaintextMessageWithPadding The plaintext message with padding on it
	 * @param {string} actualMessageLength The actual message length
	 * @return {string} Returns the original plaintext message
	 */
	removePaddingFromMessage: function(plaintextMessageWithPadding, actualMessageLength)
	{
		// Check that the length only contains positive integers only
		if (/^\d+$/.test(actualMessageLength))
		{
			// Convert to an integer
			var actualMessageLengthInt = parseInt(actualMessageLength);

			// Check the message length is in the correct range for a message
			if ((actualMessageLengthInt >= 1) && (actualMessageLengthInt <= common.messageSize))
			{
				// Get the actual message length
				return plaintextMessageWithPadding.substr(0, actualMessageLength);
			}
		}
		
		// On failure, the fallback is to return the full message including any padding
		return plaintextMessageWithPadding.substr(0, common.messageSize);
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
	 * Converts text to binary string
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
	 * MAC as well. The last parameters are just for testing the output and not normally used as this method will 
	 * use random padding, get the current timestamp for the message and random MAC algorithm as well.
	 * @param {string} plaintextMessage The actual plaintext written by the user
	 * @param {string} pad The pad as a hexadecimal string
	 * @param {string} testPlaintextPadded Testing parameter to manually pad the plaintext so we can test the output is what is expected
	 * @param {string} testCurrentTimestamp Testing parameter to use a given timestamp so we can test the output is what is expected
	 * @param {string} testMacAlgorithmIndex Testing parameter to use a given macAlgorithmIndex so we can test the output is what is expected
	 * @return {array} Returns the ciphertext and MAC to be sent. Array keys returned: 'ciphertext' and 'mac'
	 */
	encryptAndAuthenticateMessage: function(plaintextMessage, pad, testPlaintextPadded, testCurrentTimestamp, testMacAlgorithmIndex)
	{
		// Get the original length of the plaintext
		var originalPlaintextLength = common.getOriginalPlaintextLength(plaintextMessage);
		
		// Get the message with random variable length padding, but use the padding if it's passed in (for testing purposes)
		var plaintextWithPadding = common.padMessage(plaintextMessage);
		if (testPlaintextPadded !== undefined)
		{
			plaintextWithPadding = testPlaintextPadded;
		}
		
		// Get the current timestamp, but use the timestamp if it's passed in (for testing purposes)
		var timestamp = common.getCurrentUtcTimestamp();
		if (testCurrentTimestamp !== undefined)
		{
			timestamp = testCurrentTimestamp;
		}
		
		// Get a random MAC algorithm to use, but use the algorithm if it's passed in (for testing purposes)
		var randomMacAlgorithmIndex = common.getRandomMacAlgorithmIndex();
		if (testMacAlgorithmIndex !== undefined)
		{
			randomMacAlgorithmIndex = testMacAlgorithmIndex;
		}
		
		// Format message parts into binary for encryption
		var messagePartsBinary = common.prepareMessageForEncryption(plaintextWithPadding, originalPlaintextLength, timestamp, randomMacAlgorithmIndex);
		
		// Format pad for encryption
		var padBinary = common.convertHexadecimalToBinary(pad);
		var padIdentifier = common.getPadIdentifier(padBinary);
		var padMessagePartsBinary = common.getPadMessageParts(padBinary);
		
		// Encrypt the message, combine the pad and ciphertext, then convert to hex for transport
		var encryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, messagePartsBinary);
		var completeCiphertextBinary = common.combinePadIdentifierAndCiphertext(padIdentifier, encryptedMessagePartsBinary);
		var ciphertextHex = common.convertBinaryToHexadecimal(completeCiphertextBinary);
		
		// Create MAC for message
		var mac = common.createMac(randomMacAlgorithmIndex, pad, ciphertextHex);
		var padForMac = common.getPadPartForMac(pad);
		var ciphertextMac = common.encryptOrDecryptMac(padForMac, mac);
		
		// Return ciphertext and encrypted MAC
		return {
			'ciphertext': ciphertextHex,
			'mac': ciphertextMac
		};
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
	 * Wrapper function to decrypt a received message and compare the MAC to see if it is valid or not. It will return 
	 * the plaintext, the timestamp of when the message was sent, and whether the message was validated or not.
	 * @param {string} ciphertext The ciphertext received in hexadecimal string format
	 * @param {string} pad The pad to be used to decrypt the message. The pad to use can be found from the message identifier (first x symbols in the ciphertext)
	 * @param {string} ciphertextMac The encrypted MAC of the received message
	 * @return {array} Returns an array with the following keys 'plaintext', 'timestamp', 'valid'
	 */
	decryptAndVerifyMessage: function(ciphertext, pad, ciphertextMac)
	{
		// Get the ciphertext message parts (no message identifier)
		var ciphertextBinaryConvertedFromHex = common.convertHexadecimalToBinary(ciphertext);
		var ciphertextMessageParts = common.getPadMessageParts(ciphertextBinaryConvertedFromHex);
		
		// Get the pad message parts (no message identifier)
		var padBinary = common.convertHexadecimalToBinary(pad);
		var padMessagePartsBinary = common.getPadMessageParts(padBinary);
				
		// Decrypt the message parts, and convert to ASCII plaintext
		var decryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, ciphertextMessageParts);
		var decryptedPlaintextMessageParts = common.convertBinaryToText(decryptedMessagePartsBinary);
				
		// Find out the actual plaintext and time the message was sent
		var messageParts = common.getSeparateMessageParts(decryptedPlaintextMessageParts);	
		var messagePlaintextWithPadding = messageParts.messagePlaintextWithPadding;
		var actualMessageLength = messageParts.messageLength;
		var messageTimestamp = messageParts.messageTimestamp;
		var macAlgorithmIndex = messageParts.macAlgorithmIndex;
		
		// Remove padding from plaintext
		var plaintextMessage = common.removePaddingFromMessage(messagePlaintextWithPadding, actualMessageLength);
		
		// Validate the message
		var padForMac = common.getPadPartForMac(pad);
		var mac = common.encryptOrDecryptMac(padForMac, ciphertextMac);		
		var macValidation = common.validateMac(macAlgorithmIndex, pad, ciphertext, mac);
				
		// Return all important parts back
		return {
			'plaintext': plaintextMessage,		// The decrypted message
			'timestamp': messageTimestamp,		// Time the message was sent
			'valid': macValidation				// Whether the message is valid (HMAC matched or not)
		};
	},
		
	/**
	 * Create the one-time pads from our collected entropy which has been hashed and shuffled
	 * @param {string} hashedAndShuffledEntropyString
	 */
	createPads: function(hashedAndShuffledEntropyString)
	{
		var lengthOfEntropy = hashedAndShuffledEntropyString.length;
		
		// Loop through all the entropy hexadecimal chars
		for (var i=0, padNum=0;  i < lengthOfEntropy;  i += this.totalPadSizeHex, padNum++)
		{
			// Get the number of characters for the pad
			var pad = hashedAndShuffledEntropyString.substr(i, this.totalPadSizeHex);
			
			// If near the end of the string and we don't have enough for one more pad, don't use the remainder
			if (pad.length < this.totalPadSizeHex)
			{
				break;
			}
			
			// Store the pad in an object that can be easily retrieved later
			var padInfo = {
				'padNum': padNum,											// Numeric key for the pad from 0 - n. First user sends using even numbered pads, second user odd
				'padIdentifier': pad.substr(0, this.padIdentifierSizeHex),	// First x characters of the pad to identify which pad to use, separated for faster DB lookup
				'pad': pad													// The actual pad
			};
			
			// Add to array of all pads
			db.padData.pads.push(padInfo);
		}
		
		// Can show the buttons for testing now that we have data
		$('.testingButtons input').attr('disabled', false);
		
		// Show completion message
		common.showStatus('success', 'Processing entropy complete.');
	},
	
	/**
	 * Export the pads to either clipboard, textfile or to the local machine database for each user.
	 * User 1 is sending messages using odd numbered pads, user 2 will send using even numbered pads. This 
	 * prevents each user from using each other's pads which could cause them to use a pad more than once.
	 * If a pad is used more than once cryptanalysis is possible e.g. http://www.cryptosmith.com/archives/70
	 * @param {string} exportMethod How the pads will be exported. Pass in 'clipboard', 'textFile' or 'localDatabase'
	 * @param {number} user Who the pads are being exported for. Pass in 1 for the first user or 2 for the second user.
	 * @param {string} serverAddressAndPort The server address to send/receive messages
	 * @param {string} serverUsername The username to connect to the server and send/receive messages
	 * @param {string} serverPassword The password to connect to the server and send/receive messages
	 */
	preparePadsForExport: function(exportMethod, user, serverAddressAndPort, serverUsername, serverPassword)
	{	
		// Decide if this user is using even or odd numbered pads
		var usingEvenNumberedPads = (user == 1) ? true : false;		
		
		// Set information in memory storage
		db.padData.info.user = parseInt(user);
		db.padData.info.usingEvenNumberedPads = usingEvenNumberedPads;
		db.padData.info.serverAddressAndPort = serverAddressAndPort;
		db.padData.info.serverUsername = serverUsername;
		db.padData.info.serverPassword = serverPassword;
				
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
			if ((window.File && window.FileReader && window.FileList && window.Blob) == false)
			{
				alert('The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new text file.');
			}
			else {
				// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
				var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
				var filename = 'one-time-pads-user-' + user + '.txt';
				saveAs(blob, filename);
			}
		}
		else {
			// Save to current machine local database
			db.savePadDataToDatabase();
			
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
			if ((window.File && window.FileReader && window.FileList && window.Blob) == false)
			{
				alert('The File APIs are not fully supported in this browser, try exporting to clipboard then pasting to a new text file.');
			}
			else {
				// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
				var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
				var filename = 'one-time-pads-backup-user-' + db.padData.info.user + '.txt';
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
		var fileInfo = 'Pads loaded: ' + file.name + ', ' + file.type + ', ' + file.size + ' Bytes.';
		
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
	 * If user 1 then they will get the first even numbered pad in the database
	 * If user 2 then they will get the first odd numbered pad in the database
	 * @return {string|false} Returns the pad to be used, or false if none available
	 */
	getPadToEncryptMessage: function()
	{
		// Initialisations
		var numOfPads = db.padData.pads.length;
		var usingEvenNumberedPads = db.padData.info.usingEvenNumberedPads;		
		var padIndex = null;
		var pad = null;
		
		// For each pad in memory find the first one that we can send
		for (var i=0; i < numOfPads; i++)
		{
			// If this is user 1 then they will load the first even numbered pad
			if ((usingEvenNumberedPads) && (db.padData.pads[i].padNum % 2 == 0))
			{
				padIndex = i;
				break;
			}
			else if ((usingEvenNumberedPads === false) && (db.padData.pads[i].padNum % 2 == 1))
			{
				// Otherwise user 2 will load the first odd numbered pad
				padIndex = i;
				break;
			}
		}

		// If it couldn't find a pad to use (maybe sent all messages) return false, and calling function can show error
		if (padIndex === null)
		{
			return false;
		}
		
		// Get the pad to be returned
		pad = db.padData.pads[padIndex].pad;
		
		// Remove from in memory pad array and update the database so that pad can't be used again
		db.padData.pads.splice(padIndex, 1);
		db.savePadDataToDatabase();		
		
		// Return the pad
		return pad;
	},
	
	/**
	 * Gets the pad to decrypt the message. It finds the right pad based on the first x letters in the ciphertext
	 * which is the pad identifer. The database is then searched for the pad with the same pad identifier. After the 
	 * pad is found, it is returned to the calling function and the pad is removed from the local database.
	 * @param {string} ciphertextHex The ciphertext in hexadecimal format
	 * @return {object} Returns an object with properties 'padIndex', 'padNum', 'padIdentifier' and 'pad'
	 */
	getPadToDecryptMessage: function(ciphertextHex)
	{
		// Initialisations
		var padIdentifier = this.getPadIdentifierFromCiphertext(ciphertextHex);
		var numOfPads = db.padData.pads.length;		
		var padIndex = null;
		var padNum = null;
		var pad = null;
		
		// For each pad in memory find the first one that we can send
		for (var i=0; i < numOfPads; i++)
		{
			if (padIdentifier == db.padData.pads[i].padIdentifier)
			{
				padIndex = i;
			}
		}
		
		// If it couldn't find a pad to use (maybe false message) return false, and calling function can show error
		if (padIndex === null)
		{
			return false;
		}
		
		// Get the pad to be returned
		padNum = db.padData.pads[padIndex].padNum;
		pad = db.padData.pads[padIndex].pad;
		
		// Remove from in memory pad array and update the database so that pad can't be used again
		db.padData.pads.splice(padIndex, 1);
		db.savePadDataToDatabase();		
				
		// Return the pad and index in the database where it is
		return {
			'padIndex': padIndex,
			'padNum': padNum,
			'padIdentifier': padIdentifier,
			'pad': pad	
		};
	},
	
	/**
	 * Fixes the URL depending on if the user entered a URL with a slash on the end or not
	 * @param {string} serverAddress The url of the server where the files are e.g. http://mydomain.com or http://mydomain.com/otpchat/
	 * @param {string} page The page to be accessed e.g. send-message.php
	 * @return {string} The correct url e.g. http://mydomain/otpchat/send-message.php
	 */
	standardiseUrl: function(serverAddress, page)
	{		
		// If the user has entered a server address with a slash on the end then just append the page name
		if (serverAddress.charAt(serverAddress.length - 1) == '/')
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
		// Escape for XSS just incase a message is coming back from the server
		message = this.htmlEncodeEntities(message);
		
		// Remove existing CSS classes and add the class depending on the type of message
		$('#statusMessage').removeClass('success error').addClass(type);
		
		// Show the message for 5 seconds then fade it out
		$('#statusMessage').html(message).show().delay(7000).fadeOut(300);
	},
		
	/**
	 * Wrapper around the various library hash functions, as some like Whirlpool produce uppercase hex, which needs to be lowercased to be consistent.
	 * @param {string} algorithm The name of the algorithm to run
	 * @param {string} message The string to be hashed
	 */
	secureHash: function(algorithm, message)
	{
		switch (algorithm)
		{
			// SHA-2 (512 bit) - FIPS PUB 180-2 standard.
			case 'sha2-512':
				return CryptoJS.SHA512(message).toString();
			
			// SHA-3 Keccak (512 bit) - Winner of the NIST hash function competition. Uses original Keccak algorithm.
			case 'sha3-512':
				return CryptoJS.SHA3(message, { outputLength: 512 });
			
			// Whirlpool (512 bit) - Part of ISO/IEC 10118-3 standard.
			case 'whirlpool-512':
				return Whirlpool(message).toLowerCase();	
		}
	},
		
	/**
	 * Function to create a Message Authentication Code based on the algorithm chosen.
	 * The HMAC algorithm is summarised as: HMAC (K,m) = H((key ⊕ opad) ∥ H((key ⊕ ipad) ∥ message)).
	 * @param {string} algorithm The MAC algorithm name. Pass in 'hmac-sha2-512', 'hmac-sha3-512' or 'hmac-skein-512'
	 * @param {string} key The one-time pad
	 * @param {string} message The ciphertext message
	 * @return {string} Returns string of hexadecimal characters
	 */
	secureMac: function(algorithm, key, message)
	{
		switch (algorithm)
		{
			 // HMAC with SHA-2 (512 bit) bit algorithm - FIPS PUB 180-2 standard.
			case 'hmac-sha2-512':
				return CryptoJS.HmacSHA512(message, key).toString();
			
			// HMAC with SHA-3 Keccak (512 bit) bit algorithm - Winner of the NIST hash function competition. Uses original Keccak algorithm.
			case 'hmac-sha3-512':
				return CryptoJS.HmacSHA3(message, key).toString();
			
			// HMAC with Skein (512 bit) algorithm - Finalist of the NIST hash function competition.
			case 'hmac-skein-512':
				return Digest.skein512(message, key).hex();
		}
	},
			
	/**
	 * Test that the server and database connection is working from the client
	 * @param {string} serverAddressAndPort
	 * @param {string} serverUsername
	 * @param {string} serverPassword
	 */
	testServerConnection: function(serverAddressAndPort, serverUsername, serverPassword)
	{
		// If they didn't enter the server address show error
		if (serverAddressAndPort == '')
		{
			common.showStatus('error', 'Enter the server address and port.');
		}
		else if ((serverUsername == '' || serverPassword == ''))
		{
			common.showStatus('error', 'You need to have a username and password or anyone can access the server messaging API.');
		}
		else {
			// Fix the url for any excess slashes
			var serverAddress = common.standardiseUrl(serverAddressAndPort, 'test-connection.php');

			// Create AJAX request to chat server
			$.ajax(
			{
				url: serverAddress,
				type: 'POST',
				dataType: 'json',
				timeout: 10000,							// Timeout at 10 seconds
				data: {
					'username': serverUsername,			// Username to connect to the server
					'password': serverPassword			// Password to connect to the server
				},
				success: function(data)
				{
					// Get message back from server, and protect against XSS
					var statusMessage = common.htmlEncodeEntities(data.statusMessage);

					// If it saved to the database
					if (data.success)
					{
						common.showStatus('success', statusMessage);
					}
					else {
						// Otherwise show error message from the server (e.g. database error)
						common.showStatus('error', statusMessage);
					}
				},
				error: function(jqXHR, textStatus, errorThrown)
				{
					// Display error
					common.showStatus('error', 'Error contacting server, check you are connected to the internet and that the server setup is correct. ' + errorThrown);
				}
			});
		}
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
			if ((smallNumByteArray[0].length != 0) && (mediumNumByteArray[0].length) != 0 && (largeNumByteArray[0].length != 0))
			{
				return true;
			}
			
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
	}
};