/**
 * Salsa20js - Salsa20/20 JavaScript implementation
 * https://github.com/salsa20js/salsa20js
 * 
 * Copyright (c) 2015 Joshua M. David
 * Released under the MIT License
 * https://github.com/salsa20js/salsa20js/blob/master/LICENSE.md
 */

// Use ECMAScript 5's strict mode
'use strict';

/**
 * Encrypt and decrypt wrapper interface functions for the user
 */
var Salsa20 = {
	
	/**
	 * A wrapper function for the Salsa20 encryption of a message 
	 * @param {String|Uint8Array} key A hexadecimal string e.g. 'ab0de1f2...' or array of bytes e.g. [0, 255, 22, ...] equal to 128 bits or 256 bits
	 * @param {String|Uint8Array} message The plaintext message. This can be an array of bytes, a ASCII/UTF-8 string or also a hexadecimal string e.g. 'ab0de1f2...' if { inputTextType: 'hex' } is passed in the options object.
	 * @param {String|Uint8Array|Number} nonce A 64-bit one time cryptographic nonce i.e. the message number. This can be input as a hexadecimal string of 16 symbols, a byte array of 8 bytes or an integer between 0 and 2^53 - 1 inclusive.
	 * @param {Number} counter An integer specifying the block to start encrypting from. Normally a 0 should be passed. If encrypting part of a large file it is also possible to enter the block number and it will start encrypting from that point. The maximum integer allowed for JavaScript is 2^53 - 1 (9007199254740991).
	 * @param {Object} options Optional object with additional options:
	 *		inputTextType: 'hex' - The input message will be a hex string, otherwise by default it will parse it as an ASCII/UTF-8 string
	 *		returnType: 'hex' - Returns the encrypted data as a hex string, otherwise by default it will return an array of bytes
	 * @returns {Uint8Array|String} Returns an array of bytes or a hexadecimal string
	 */
	encrypt: function(key, message, nonce, counter, options)
	{
		// If the options are unset, set to a blank object
		options = options || {};
		
		// Normalise the various input formats to what is required for the encryption function
		key = this.core.util.parseKey(key);
		message = this.core.util.parseMessage(message, options);
		nonce = this.core.util.parseNonce(nonce);
		counter = this.core.util.parseCounter(counter, message.length);
		
		// Encrypt starting from the specified counter
		var encryptedBytes = this.core.encryption(key, message, nonce, counter);
				
		// If the return type requested is hex, convert the bytes to hex
		if (options.hasOwnProperty('returnType') && (options.returnType === 'hex'))
		{
			return this.core.util.bytesToHex(encryptedBytes);
		}
		else {
			// By default return a byte array
			return encryptedBytes;
		}
	},
	
	/**
	 * A wrapper function for the Salsa20 encryption of a message
	 * @param {String|Uint8Array} key A hexadecimal string e.g. 'ab0de1f2...' or array of bytes e.g. [0, 255, 22, ...] equal to 128 bits or 256 bits
	 * @param {String|Uint8Array} ciphertext The ciphertext message. This can be an array of bytes or also a hexadecimal string e.g. 'ab0de1f2...' if { inputTextType: 'hex' } is passed in the options object. Otherwise a byte array is used as default.
	 * @param {String|Uint8Array|Number} nonce A hex string of 16 symbols, a byte array of 8 bytes or an integer between 0 and 2^53 - 1 inclusive
	 * @param {Number} counter An integer specifying the block to start decrypting from. The default should be 0. If decrypting part of a large file it is also possible to enter the block number and it will start decrypting from that point. The maximum integer allowed for JavaScript is 2^53 - 1 (9007199254740991).
	 * @param {Object} options Optional object with additional options:
	 *		inputTextType: 'hex' - The input ciphertext will be a hex string, otherwise by default it will parse it as an array of bytes
	 *		returnType: 'hex' - Returns the encrypted data as a hex string, otherwise by default it will return an ASCII/UTF-8 string
	 * @returns {String} By default it will return an ASCII/UTF-8 string, unless the { returnType: 'hex' } option is passed
	 */
	decrypt: function(key, ciphertext, nonce, counter, options)
	{
		// If the options are unset, set to a blank object
		options = options || {};
		
		// Normalise the various input formats to what is required for the encryption function
		key = this.core.util.parseKey(key);
		ciphertext = this.core.util.parseMessage(ciphertext, options);
		nonce = this.core.util.parseNonce(nonce);
		counter = this.core.util.parseCounter(counter, ciphertext.length);
		
		// Decrypt starting from the specified counter
		var decryptedBytes = this.core.encryption(key, ciphertext, nonce, counter);
		
		// If the return type requested is hex, convert the bytes to hex
		if (options.hasOwnProperty('returnType') && (options.returnType === 'hex'))
		{
			return this.core.util.bytesToHex(decryptedBytes);
		}
		else {
			// Decode from bytes to UTF-8 string
			return this.core.util.bytesToUtf8String(decryptedBytes);
		}
	},
		
	/**
	 * A wrapper function to generate a Salsa20 keystream based on a key, nonce and start counter. This can be used if 
	 * you just want the raw keystream bytes e.g. for use in a cascade cipher. The keystream will be at least the length 
	 * of the 'length' parameter entered and the number of random bytes returned will be the first multiple of the 
	 * Salsa20 block size (64 bytes) after that. For example: length 53, returns 64 bytes and length 77, returns 128 bytes.
	 * @param {String|Uint8Array} key A hexadecimal string e.g. 'ab0de1f2...' or array of bytes e.g. [0, 255, 22, ...] equal to 128 bits or 256 bits
	 * @param {Number} length An integer representing the minimum length of the keystream required
	 * @param {String|Uint8Array|Number} nonce A 64-bit one time cryptographic nonce i.e. the message number. This can be input as a hexadecimal string of 16 symbols, a byte array of 8 bytes or an integer between 0 and 2^53 - 1 inclusive.
	 * @param {Number} counter An integer specifying the block to start keystream generation from. Normally a `0` should be passed in. The maximum integer allowed for JavaScript is `9007199254740991` (2^53 - 1).
	 * @param {Object} options Optional object with additional options:
	 *		returnType: 'hex' - Returns the keystream as a hex string, otherwise by default it will return an array of bytes
	 * @returns {Uint8Array|String} Returns an array of bytes or a hexadecimal string
	 */
	generateKeystream: function(key, length, nonce, counter, options)
	{
		// If the options are unset, set to a blank object
		options = options || {};
		
		// Normalise the various input formats to what is required
		key = this.core.util.parseKey(key);
		nonce = this.core.util.parseNonce(nonce);
		counter = this.core.util.parseCounter(counter, length);
		
		// Create the keystream
		var keystream = this.core.generateKeystream(key, length, nonce, counter);
		
		// If the return type requested is hex, convert the bytes to hex
		if (options.hasOwnProperty('returnType') && (options.returnType === 'hex'))
		{
			return this.core.util.bytesToHex(keystream);
		}
		else {
			// By default return a byte array
			return keystream;
		}
	}
};

/**
 * Core Salsa20 specification functions
 */
Salsa20.core = {

	/**
	 * The quarterround function from Section 3 of the spec
	 * @param {Number} yWord0 A 32 bit decimal word
	 * @param {Number} yWord1 A 32 bit decimal word
	 * @param {Number} yWord2 A 32 bit decimal word
	 * @param {Number} yWord3 A 32 bit decimal word
	 * @returns {Uint32Array} zWords Returns a modified array of four 32 bit decimal words
	 */
	quarterRound: function(yWord0, yWord1, yWord2, yWord3)
	{
		var sum = null;
		var leftRotation = null;
		var zWords = new Uint32Array(4);

		// z1 = y1 ⊕ ((y0 + y3) <<< 7)
		sum = this.util.sumWords(yWord0, yWord3);
		leftRotation = this.util.leftRotate(sum, 7);
		zWords[1] = this.util.xorWords(yWord1, leftRotation);

		// z2 = y2 ⊕ ((z1 + y0) <<< 9)
		sum = this.util.sumWords(zWords[1], yWord0);
		leftRotation = this.util.leftRotate(sum, 9);
		zWords[2] = this.util.xorWords(yWord2, leftRotation);

		// z3 = y3 ⊕ ((z2 + z1) <<< 13)
		sum = this.util.sumWords(zWords[2], zWords[1]);
		leftRotation = this.util.leftRotate(sum, 13);
		zWords[3] = this.util.xorWords(yWord3, leftRotation);

		// z0 = y0 ⊕ ((z3 + z2) <<< 18)
		sum = this.util.sumWords(zWords[3], zWords[2]);
		leftRotation = this.util.leftRotate(sum, 18);
		zWords[0] = this.util.xorWords(yWord0, leftRotation);

		return zWords;
	},

	/**
	 * The rowround function from Section 4 of the spec
	 * @param {Uint32Array} yWords A 16-word array consisting of 32 bit decimal words
	 * @returns {Uint32Array} zWords Returns a transformed 16-word array consisting of 32 bit decimal words
	 */
	rowRound: function(yWords)
	{		
		var zWords = new Uint32Array(16);
		var transformedWords = null;

		// (z0, z1, z2, z3) = quarterround(y0, y1, y2, y3)
		transformedWords = this.quarterRound(yWords[0], yWords[1], yWords[2], yWords[3]);
		zWords[0] = transformedWords[0];
		zWords[1] = transformedWords[1];
		zWords[2] = transformedWords[2];
		zWords[3] = transformedWords[3];

		// (z5, z6, z7, z4) = quarterround(y5, y6, y7, y4)
		transformedWords = this.quarterRound(yWords[5], yWords[6], yWords[7], yWords[4]);

		zWords[5] = transformedWords[0];
		zWords[6] = transformedWords[1];
		zWords[7] = transformedWords[2];
		zWords[4] = transformedWords[3];

		// (z10, z11, z8, z9) = quarterround(y10, y11, y8, y9)
		transformedWords = this.quarterRound(yWords[10], yWords[11], yWords[8], yWords[9]);
		zWords[10] = transformedWords[0];
		zWords[11] = transformedWords[1];
		zWords[8] = transformedWords[2];
		zWords[9] = transformedWords[3];

		// (z15, z12, z13, z14) = quarterround(y15, y12, y13, y14)
		transformedWords = this.quarterRound(yWords[15], yWords[12], yWords[13], yWords[14]);
		zWords[15] = transformedWords[0];
		zWords[12] = transformedWords[1];
		zWords[13] = transformedWords[2];
		zWords[14] = transformedWords[3];

		return zWords;
	},

	/**
	 * The columnround function from Section 5 of the spec
	 * @param {Uint32Array} xWords A 16-word array consisting of 32 bit decimal words
	 * @returns {Uint32Array} yWords Returns a transformed 16-word array consisting of 32 bit decimal words
	 */
	columnRound: function(xWords)
	{
		var yWords = new Uint32Array(16);
		var transformedWords = null;

		// (y0, y4, y8, y12) = quarterround(x0, x4, x8, x12)
		transformedWords = this.quarterRound(xWords[0], xWords[4], xWords[8], xWords[12]);
		yWords[0] = transformedWords[0];
		yWords[4] = transformedWords[1];
		yWords[8] = transformedWords[2];
		yWords[12] = transformedWords[3];

		// (y5, y9, y13, y1) = quarterround(x5, x9, x13, x1)
		transformedWords = this.quarterRound(xWords[5], xWords[9], xWords[13], xWords[1]);
		yWords[5] = transformedWords[0];
		yWords[9] = transformedWords[1];
		yWords[13] = transformedWords[2];
		yWords[1] = transformedWords[3];

		// (y10, y14, y2, y6) = quarterround(x10, x14, x2, x6)
		transformedWords = this.quarterRound(xWords[10], xWords[14], xWords[2], xWords[6]);
		yWords[10] = transformedWords[0];
		yWords[14] = transformedWords[1];
		yWords[2] = transformedWords[2];
		yWords[6] = transformedWords[3];

		// (y15, y3, y7, y11) = quarterround(x15, x3, x7, x11)
		transformedWords = this.quarterRound(xWords[15], xWords[3], xWords[7], xWords[11]);
		yWords[15] = transformedWords[0];
		yWords[3] = transformedWords[1];
		yWords[7] = transformedWords[2];
		yWords[11] = transformedWords[3];

		return yWords;
	},

	/**
	 * The doubleround function from Section 6 of the spec
	 * @param {Uint32Array} xWords A 16-word array consisting of 32 bit decimal words
	 * @returns {Uint32Array} xWords Returns a transformed 16-word array consisting of 32 bit decimal words
	 */
	doubleRound: function(xWords)
	{
		return this.rowRound(this.columnRound(xWords));
	},

	/**
	 * The littleendian function from Section 7 of the spec
	 * @param {Number} byte0 An integer from 0 - 255 representing a byte
	 * @param {Number} byte1 An integer from 0 - 255 representing a byte
	 * @param {Number} byte2 An integer from 0 - 255 representing a byte
	 * @param {Number} byte3 An integer from 0 - 255 representing a byte
	 * @returns {Number} Returns the resulting decimal word of 32 bits
	 */
	littleEndian: function(byte0, byte1, byte2, byte3)
	{
		var wordArray = new Uint32Array(1);

		// Calculate b0 + (2^8 * b1) + (2^16 * b2) + (2^24 * b3)
		// Using the typed array to clamp the result to a 32 bit unsigned integer
		wordArray[0] = byte0;
		wordArray[0] += (Math.pow(2, 8) * byte1);
		wordArray[0] += (Math.pow(2, 16) * byte2);
		wordArray[0] += (Math.pow(2, 24) * byte3);

		return wordArray[0];
	},

	/**
	 * The inverse of the littleendian function
	 * @param {Number} word A 32 bit decimal word
	 * @returns {Uint8Array} Returns a 4-byte sequence e.g. [6, 75, 30, 9]
	 */
	littleEndianInverse: function(word)
	{
		var bytes = new Uint8Array(4);

		// Sends a 32 bit word back to a 4 byte sequence in a littleendian way using the logical right shift 
		// operator, so that the least significant byte goes first and the most significant byte goes last
		bytes[0] = word & 0xff;
		bytes[1] = (word >>> 8) & 0xff;
		bytes[2] = (word >>> 16) & 0xff;
		bytes[3] = (word >>> 24) & 0xff;

		return bytes;
	},

	/**
	 * The Salsa20 hash function from Section 8 of the spec
	 * @param {Uint8Array} xBytes A 64-byte sequence e.g. [211, 159, 13, 115, ...]
	 * @returns {Uint8Array} A modified 64-byte sequence
	 */
	hash: function(xBytes)
	{
		var xWords = new Uint32Array(16);
		var resultBytes = new Uint8Array(this.util.outputByteLength);

		// Convert bytes to littleendian words
		// x0 = littleendian(x[0], x[1], x[2], x[3]),
		// x1 = littleendian(x[4], x[5], x[6], x[7]),
		// ...
		// x15 = littleendian(x[60], x[61], x[62], x[63]).
		for (var i = 0, j = 0;  i < this.util.outputByteLength;  i += 4, j++)
		{
			xWords[j] = this.littleEndian(xBytes[i], xBytes[i + 1], xBytes[i + 2], xBytes[i + 3]);
		}

		// Set to be input into doubleround multiple times
		var zWords = xWords;

		// Perform doubleround 10 times
		for (var i = 0; i < 10; i++)
		{
			zWords = this.doubleRound(zWords);
		}

		// Perform littleendian −1 (z0 + x0) through to littleendian −1 (z15 + x15)
		for (var resultIndex = 0, i = 0;  i < 16;  resultIndex += 4, i++)
		{
			// Add the z and x words in the brackets first then perform the inverse littleendian
			var sumWords = this.util.sumWords(zWords[i], xWords[i]);
			var inverseEndianBytes = this.littleEndianInverse(sumWords);

			// Add the bytes to the result array
			resultBytes[resultIndex] = inverseEndianBytes[0];
			resultBytes[resultIndex + 1] = inverseEndianBytes[1];
			resultBytes[resultIndex + 2] = inverseEndianBytes[2];
			resultBytes[resultIndex + 3] = inverseEndianBytes[3];
		}

		return resultBytes;
	},

	/**
	 * Constants for the 16 byte (128 bit) key
	 * τ0 τ1 τ2 τ3 is "expand 16-byte k" in ASCII
	 */
	constants16: [
		new Uint8Array([101, 120, 112, 97]),	// τ0 "expa"
		new Uint8Array([110, 100, 32, 49]),		// τ1 "nd 1"
		new Uint8Array([54, 45, 98, 121]),		// τ2 "6-by"
		new Uint8Array([116, 101, 32, 107])		// τ3 "te k"
	],

	/**
	 * Constants for the 32 byte (256 bit) key
	 * σ0 σ1 σ2 σ3 is "expand 32-byte k" in ASCII
	 */
	constants32: [
		new Uint8Array([101, 120, 112, 97]),	// σ0 "expa"
		new Uint8Array([110, 100, 32, 51]),		// σ1 "nd 3"
		new Uint8Array([50, 45, 98, 121]),		// σ2 "2-by"
		new Uint8Array([116, 101, 32, 107])		// σ3 "te k"
	],

	/**
	 * The Salsa20 expansion function from Section 9 of the spec
	 * @param {Uint8Array} nonce A 16 byte sequence for the nonce and counter
	 * @param {Uint8Array} key0 A 16 byte (128 bit) sequence for the key
	 * @param {Uint8Array} key1 An optional additional 16 byte (128 bit) sequence to make up a full 256 bit key
	 * @returns {Uint8Array} Returns a 64 byte sequence which is the expansion of (k, n) into Salsa20 k(n)
	 */
	expansion: function(nonce, key0, key1)
	{
		var inputBytes = new Uint8Array(64);

		// If using a 32 byte (256 bit) key
		if (key1.length !== 0)
		{
			// Salsa20 k0,k1(n) = Salsa20(σ0, k0, σ1, n, σ2, k1, σ3)
			this.util.updateArray(inputBytes, this.constants32[0], 0);	// 4 bytes
			this.util.updateArray(inputBytes, key0, 4);					// 16 bytes
			this.util.updateArray(inputBytes, this.constants32[1], 20);	// 4 bytes
			this.util.updateArray(inputBytes, nonce, 24);				// 16 bytes
			this.util.updateArray(inputBytes, this.constants32[2], 40);	// 4 bytes
			this.util.updateArray(inputBytes, key1, 44);				// 16 bytes
			this.util.updateArray(inputBytes, this.constants32[3], 60);	// 4 bytes
		}
		else {
			// Otherwise use the 16 byte (128 bit key)
			// Salsa20 k(n) = Salsa20(τ0, k, τ1, n, τ2, k, τ3)
			this.util.updateArray(inputBytes, this.constants16[0], 0);	// 4 bytes
			this.util.updateArray(inputBytes, key0, 4);					// 16 bytes
			this.util.updateArray(inputBytes, this.constants16[1], 20);	// 4 bytes
			this.util.updateArray(inputBytes, nonce, 24);				// 16 bytes
			this.util.updateArray(inputBytes, this.constants16[2], 40);	// 4 bytes
			this.util.updateArray(inputBytes, key0, 44);				// 16 bytes
			this.util.updateArray(inputBytes, this.constants16[3], 60);	// 4 bytes
		}

		// Perform the hash
		return this.hash(inputBytes);
	},

	/**
	 * The Salsa20 encryption function from Section 10 of the spec. This function is used for encryption and decryption.
	 * @param {Uint8Array} key A 16-byte sequence for the 128 bit key or 32-byte sequence for the 256 bit key
	 * @param {Uint8Array} message An arbitrary length byte sequence for the plaintext or ciphertext message
	 * @param {Uint8Array} nonce An 8-byte nonce / unique message number (less than 2^53 - 1)
	 * @param {Number} counter An integer counter (less than 2^53 - 1) to start encryption/decryption from, default is usually 0
	 * @returns {Uint8Array} Returns an array of bytes (the plaintext or ciphertext message)
	 */
	encryption: function(key, message, nonce, counter)
	{
		// Get the message length
		var messageLength = message.length;
		
		// Generate the keystream, then XOR that with the ciphertext or plaintext message
		var keystream = this.generateKeystream(key, messageLength, nonce, counter);
		var xoredBytes = this.xorKeystreamAndMessage(keystream, message, messageLength);
		
		return xoredBytes;
	},
	
	/**
	 * Generates the keystream based on a key, nonce and start counter. The keystream will be at least the length 
	 * of the lengthRequired parameter entered and a multiple of the Salsa20 block size (64 bytes).
	 * @param {Uint8Array} key A 16-byte sequence for the 128 bit key or 32-byte sequence for the 256 bit key
	 * @param {Uint8Array} lengthRequired The minimum length of the keystream required
	 * @param {Uint8Array} nonce An 8-byte nonce / unique message number (less than 2^53 - 1)
	 * @param {Number} counter An integer counter (less than 2^53 - 1) to start encryption/decryption from, default is usually 0
	 * @returns {Uint8Array} Returns an array of bytes with the length as a multiple of the Salsa20 block size
	 */
	generateKeystream: function(key, lengthRequired, nonce, counter)
	{
		// Split the key into separate 16 byte arrays for the expansion function
		var keys = this.util.splitKey(key);

		// Find number of 64 byte keystream blocks and keystream bytes to create
		var numBlocksToGenerate = Math.ceil(lengthRequired / this.util.outputByteLength);		
		var numKeystreamBytes = numBlocksToGenerate * this.util.outputByteLength;
		var keystreamBytes = new Uint8Array(numKeystreamBytes);

		// Find the stop counter value to exit keystream generation
		var maxCounter = counter + numBlocksToGenerate;
		var counterAndNonceBytes = new Uint8Array(16);

		// Fill the first 8 bytes of the array with the nonce bytes
		this.util.updateArray(counterAndNonceBytes, nonce, 0);

		// Generate the keystream
		for (var block = 0;  counter < maxCounter;  block += 64, counter++)
		{
			// Convert the counter to fixed 8 byte array
			var counterBytes = this.util.numToEightByteArray(counter);

			// Fill the last 8 bytes of the array with the new counter bytes
			// This forms the nonce + counter (16 bytes) input into the expansion function
			this.util.updateArray(counterAndNonceBytes, counterBytes, 8);

			// Generate 64 byte block keystream using the Salsa20 expansion function
			var expansionBytes = this.expansion(counterAndNonceBytes, keys.key0, keys.key1);

			// Build output
			this.util.updateArray(keystreamBytes, expansionBytes, block);
		}
		
		return keystreamBytes;
	},
	
	/**
	 * Encrypts the plaintext or decrypts the ciphertext by XORing the keystream with the plaintext/ciphertext bytes. 
	 * This implicitly makes the output the same length as the input plaintext/ciphertext.
	 * @param {Uint8Array} keystreamBytes The full keystream in bytes, this should be at least the same length as the message bytes
	 * @param {Uint8Array} messageBytes The ciphertext or plaintext message bytes
	 * @param {Uint8Array} messageLength The length of the ciphertext/plaintext message in bytes
	 * @returns {Uint8Array} Returns the encrypted/decrypted ciphertext/message bytes
	 */
	xorKeystreamAndMessage: function(keystreamBytes, messageBytes, messageLength)
	{
		// Pre-allocate space in the typed array
		var xoredBytes = new Uint8Array(messageLength);
		
		// XOR each byte of the message with the corresponding keystream byte
		for (var i = 0;  i < messageLength;  i++)
		{
			// XOR the two bytes together
			xoredBytes[i] = keystreamBytes[i] ^ messageBytes[i];
		}

		return xoredBytes;
	}
};

/**
 * Helper utility functions
 */
Salsa20.core.util = {
	
	/**
	 * The core of Salsa20 is a hash function with 64-byte input and 64-byte output length
	 * @type Number
	 */
	outputByteLength: 64,

	/**
	 * The maximum integer size in JavaScript (Number.MAX_SAFE_INTEGER or 9007199254740991 or 2^53 - 1)
	 * @type Number
	 */
	maxInteger: Math.pow(2, 53) - 1,

	/**
	 * Converts a hexadecimal string to a byte array
	 * @param {String} hexString A string of hexadecimal symbols
	 * @returns {Uint8Array} Returns a byte array e.g. [34, 255, 0, 64]
	 */
	hexToBytes: function(hexString)
	{		
		// Calculate the length of the string in bytes
		var stringLength = hexString.length;
		var numOfBytes = stringLength / 2;

		// Create a buffer with a Uint8Array view referring to the buffer
		var buffer = new ArrayBuffer(numOfBytes);
		var byteArray = new Uint8Array(buffer);

		for (var i = 0, byteIndex = 0;  i < stringLength;  i += 2, byteIndex++)
		{
			// Convert the hex to a byte
			var byteHex = hexString.substring(i, i + 2);
			var byte = parseInt(byteHex, 16);

			byteArray[byteIndex] = byte;
		}

		return byteArray;
	},

	/**
	 * Converts a byte array to a hexadecimal string
	 * @param {Uint8Array} byteArray A byte array e.g. [34, 255, 0, 64]
	 * @returns {String} Returns A string of hexadecimal symbols
	*/
	bytesToHex: function(byteArray)
	{
		var hexString = '';

		for (var i = 0, length = byteArray.length; i < length; i++)
		{				
			// Convert the decimal to a byte, adding padding if necessary
			var hex = byteArray[i].toString(16);
			var hexPadded = this.leftPadding(hex, '0', 2);

			hexString += hexPadded;
		}

		return hexString;
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
		var charsToAdd = (totalCharacters - inputString.length) / padCharacter.length;

		// Add padding onto the string
		for (var i = 0; i < charsToAdd; i++)
		{
			inputString = padCharacter + inputString;
		}

		return inputString;
	},

	/**
	 * Converts a hex word e.g. 0xc0a8787e or 'c0a8787e' to 32 bit decimal equivalent i.e. 3232266366
	 * @param {String} hexWord A hexadecimal word of 32 bits
	 * @returns {Number} Returns a 32 bit integer
	 */
	hexToDec: function(hexWord)
	{		
		return parseInt(hexWord, 16);
	},

	/**
	 * Converts a decimal or integer to a hexadecimal word of 32 bits e.g. 3232266366 becomes 'c0a8787e'
	 * @param {Number} decimalNum
	 * @returns {String} Returns a hexadecimal word of length 32 bits (8 hexadecimal chars)
	 */
	decToHex: function(decimalNum)
	{
		// Convert to hexadecimal and pad to 4 bytes (8 hexadecimal chars)
		var hexWord = decimalNum.toString(16);
		var paddedHexWord = this.leftPadding(hexWord, '0', 8);

		return paddedHexWord;
	},

	/**
	 * Adds two decimal words of length 32 bits together
	 * @param {Number} wordA A decimal word of 32 bits
	 * @param {Number} wordB A decimal word of 32 bits
	 * @returns {Number} Returns the resulting decimal word of 32 bits
	 */
	sumWords: function(wordA, wordB)
	{
		// Store result in 32 bit typed array which will clamp the result to 32 bits
		var wordArray = new Uint32Array(1);

		// Add the two numbers
		wordArray[0] = wordA + wordB;

		return wordArray[0];
	},

	/**
	 * Exclusive ORs two 32 bit decimal words together
	 * @param {Number} wordA A decimal word of 32 bits
	 * @param {Number} wordB A decimal word of 32 bits
	 * @returns {Number} Returns the resulting decimal word of 32 bits
	 */
	xorWords: function(wordA, wordB)
	{
		// Store result in 32 bit typed array which will clamp the result to 32 bits
		var wordArray = new Uint32Array(1);

		// XOR the two numbers
		wordArray[0] = wordA ^ wordB;

		return wordArray[0];
	},

	/**
	 * Left rotates a decimal word to the specified number of bits
	 * @param {Number} wordA A decimal word of 32 bits
	 * @param {Number} numBitsToRotate An integer of the number of bits to rotate
	 * @returns {Number} Returns the resulting decimal word of 32 bits
	 */
	leftRotate: function(wordA, numBitsToRotate)
	{
		// Store result in 32 bit typed array which will clamp the result to 32 bits
		var wordArray = new Uint32Array(1);

		// Left rotate the number by the number of bits
		wordArray[0] = (wordA << numBitsToRotate | (wordA >>> (32 - numBitsToRotate)));

		return wordArray[0];
	},

	/**
	 * Converts an array of hex words to a typed array of decimal words
	 * @param {Array} hexWords An array of 32 bit hexadecimal words e.g. ['e7e8c006', 'c4f9417d', ...]
	 * @returns {Uint32Array} Returns a typed array of decimal 32 bit words e.g. [3232266366, 3232266366, ...]
	 */
	hexWordsToDecWords: function(hexWords)
	{		
		// Create a buffer with a Uint32Array view referring to the buffer
		var arrayLength = hexWords.length;		
		var decWords = new Uint32Array(arrayLength);

		for (var i = 0; i < arrayLength; i++)
		{			
			// Convert the 32 bit hex word to decimal			
			decWords[i] = this.hexToDec(hexWords[i]);
		}

		return decWords;
	},

	/**
	 * Updates a typed array with data from another array. The update can start from a start index which avoids 
	 * overwriting values before the start index in the typed array. Support for the concat operation on typed arrays 
	 * is not well supported so this function is needed for now. Because typed arrays reference the same block of 
	 * memory it will update the passed in array.
	 * @param {Uint32Array|Uint8Array} arrayToFill The typed array to be filled with data
	 * @param {Uint32Array|Uint8Array} arrayToFillFrom The contents of this typed array will be added to the first array
	 * @param {Number} startIndex An integer starting from 0 to reference the index to start adding at in the current array
	 */
	updateArray: function(arrayToFill, arrayToFillFrom, startIndex)
	{
		for (var i = 0, length = arrayToFillFrom.length;  i < length;  i++)
		{
			arrayToFill[startIndex + i] = arrayToFillFrom[i];
		}
	},

	/**
	 * Converts a nonce or counter to a fixed 8 byte (64 bit) array
	 * @param {Number} num An integer e.g. nonce or counter to be converted to fixed 8 byte array
	 * @returns {Uint8Array} Returns an array of bytes with a total size of 8 bytes
	 */
	numToEightByteArray: function(num)
	{
		// Convert to hex
		var counterHex = num.toString(16);

		// Add padding to make up 64 bits (4 bits per symbol x 16)
		var paddedCounterHex = this.leftPadding(counterHex, '0', 16);

		// Convert to bytes
		return this.hexToBytes(paddedCounterHex);
	},

	/**
	 * Separates a key evenly into two parts for input into the expansion function. 
	 * This is required because JavaScript's regular slice function is not currently implemented for typed arrays.
	 * @param {Uint8Array} key A 16-byte sequence for the 128 bit key or 32-byte sequence for the 256 bit key
	 * @returns {Object} Returns an object with 'key0' and 'key1'
	 */
	splitKey: function(key)
	{	
		var key0 = new Uint8Array(16);
		var key1 = new Uint8Array(16);

		// If 128 bit key, return the first 16 bytes as key0 and an empty array for the last key
		if (key.length === 16)
		{
			return { 
				key0: key,
				key1: new Uint8Array(0)
			};
		}

		// Otherwise if 256 bit key, loop through the bytes in the key
		for (var i = 0, newKeyIndex = 0;  i < 32;  newKeyIndex++, i++)
		{
			// If 16 bytes already filled, reset the index for the second array
			if (i === 16)
			{
				newKeyIndex = 0;
			}

			// Store first half of key in key0
			if (i < 16)
			{
				key0[newKeyIndex] = key[i];
			}
			else {
				// Store second half of key in key1
				key1[newKeyIndex] = key[i];
			}
		}

		return {
			key0: key0,
			key1: key1
		};
	},

	/**
	 * Exclusive OR two bytes together
	 * @param {Number} byteA An integer from 0 - 255 inclusive
	 * @param {Number} byteB An integer from 0 - 255 inclusive
	 * @returns {Number} Returns an integer from 0 - 255 inclusive
	 */
	xorTwoBytes: function(byteA, byteB)
	{
		// Create a typed array which will clamp the result to a single byte within the range of 0 - 255
		var resultByte = new Uint8Array(1);

		// XOR the two bytes
		resultByte[0] = byteA ^ byteB;

		return resultByte[0];
	},

	/**
	 * Parses the key input by the user and normalises it to a byte array
	 * @param {String|Uint8Array} key A hexadecimal string e.g. 'ab0de1f2...' or array of bytes e.g. [0, 255, 22, ...] equal to 128 bits or 256 bits
	 * @returns {Uint8Array} Returns an array of bytes
	 */
	parseKey: function(key)
	{
		// If string, convert the key from hexadecimal string to byte array
		if (typeof key === 'string')
		{				
			key = this.hexToBytes(key);
		}
		else if ((key instanceof Uint8Array) === false)
		{
			throw new Error('Incorrect parameter type for the key, it should be an array of bytes or hex string');
		}

		// Get key length in bytes
		var keyLength = key.length;

		// Checks the key is the correct size of 16 bytes (128 bits) or 32 bytes (256 bits)
		if ((keyLength === 16) || (keyLength === 32))
		{
			// Key should be byte array now
			return key;
		}

		throw new Error('Incorrect key length, only 16 bytes (128 bits) or 32 bytes (256 bits) accepted');
	},

	/**
	 * Converts a message from a hexadecimal string or UTF-8 to a byte array
	 * @param {String|Uint8Array} message The message of an arbitrary length as a UTF-8 string, hexadecimal string, or array of bytes
	 * @param {Object} options Optional object with additional options:
	 *		inputTextType: 'hex' - The input message plaintext or ciphertext
	 * @returns {Uint8Array} Returns a byte array
	 */
	parseMessage: function(message, options)
	{
		// If a hexadecimal or UTF-8 string
		if (typeof message === 'string')
		{
			// Check it is a hex string by checking the options property
			if ((typeof options !== 'undefined') && (options.hasOwnProperty('inputTextType')) && (options.inputTextType === 'hex'))
			{
				// Convert from hexadecimal string
				message = this.hexToBytes(message);
			}
			else {
				// Convert from UTF-8 string
				message = this.utf8StringToBytes(message);
			}
		}
		else if ((message instanceof Uint8Array) === false)
		{
			throw new Error('Incorrect parameter type for the message, it should be a string, hex string or array of bytes');
		}

		// The maximum counter in the spec is 2^64, but JavaScript can't go higher than 2^53 - 1 for an integer. Multiply 
		// this max counter by the output bytes of Salsa20 function (64 bytes) which gives 576460752303424000 bytes = 512 PiB
		if (message.length > (this.maxInteger * this.outputByteLength))
		{
			throw new Error('Should not encrypt more than 512 petabytes of data under a single nonce, try splitting the data and encrypting under separate nonces');
		}

		return message;
	},

	/**
	 * Converts the nonce to a fixed size byte array
	 * @param {Uint8Array|String|Number} nonce A byte array of 8 bytes, a hex string of 16 symbols, or an integer between 0 and 2^53 - 1 inclusive
	 * @returns {Uint8Array} Returns a byte array of 8 bytes
	 */
	parseNonce: function(nonce)
	{
		// If an array of bytes
		if ((nonce instanceof Uint8Array) && (nonce.length === 8))
		{
			// Convert the typed array to a regular array
			return nonce;
		}

		// If a hexadecimal string with 16 hex digits in length
		else if ((typeof nonce === 'string') && (nonce.length === 16))
		{
			return this.hexToBytes(nonce);
		}

		// If a positive integer
		else if ((typeof nonce === 'number') && (nonce % 1 === 0) && (nonce >= 0))
		{
			// Check that it does not exceed integer limit in JavaScript (2^53 - 1)
			if (nonce <= this.maxInteger)
			{
				return this.numToEightByteArray(nonce);
			}

			throw new Error('The nonce size has exceeded the max integer limit of JavaScript (' + this.maxInteger + ')');
		}

		throw new Error('Incorrect parameter for the nonce, it should be a hex string (16 symbols), array of bytes (8 bytes) or a positive integer');
	},

	/**
	 * Checks the counter is formulated correctly
	 * @param {Number} counter An integer from 0 to 2^53 - 1 (max integer allowed in JavaScript)
	 * @param {Number} messageLength The message length in number of bytes
	 * @returns {Number} Returns an integer
	 */
	parseCounter: function(counter, messageLength)
	{
		// Throw exception if not a positive integer
		if ((typeof counter !== 'number') || (counter % 1 !== 0) || (counter < 0))
		{
			throw new Error('The counter size should be an integer from 0 to ' + this.maxInteger);
		}

		// The maximum number of keystream bytes that can be created from this start counter
		var maxKeystreamBytes = ((this.maxInteger - counter) * this.outputByteLength) + this.outputByteLength;

		// Check that enough keystream bytes can be generated to encrypt the message from this counter position 
		// without overflowing JavaScript's maximum integer limit
		if (messageLength > maxKeystreamBytes)
		{
			throw new Error(
				'The message is longer than the number of keystream bytes that can be generated from this start ' +
				'counter position. Consider splitting the message into smaller parts. Start counter: ' + 
				counter + '. Max message bytes that can be ' + 'encrypted/decrypted from this counter position: ' + 
				maxKeystreamBytes + '. Num of message bytes: ' + messageLength
			);
		}

		return counter;
	},

	/**
	 * Encodes an ASCII/UTF-8 string into an array of bytes
	 * @param {String} unicodeString
	 * @returns {Uint8Array}
	 */
	utf8StringToBytes: function(unicodeString)
	{
		// Encode all Unicode chars
		var utf8ByteString = unescape(encodeURIComponent(unicodeString));
		var length = utf8ByteString.length;

		for (var i = 0, utf8Bytes = new Uint8Array(length);  i < length;  i++)
		{
			// Get the decimal representation of each character and update the byte array
			utf8Bytes[i] = utf8ByteString.charCodeAt(i);
		}

		return utf8Bytes;
	},

	/**
	 * Decodes an array of bytes to an ASCII/UTF-8 string
	 * @param {Uint8Array} bytes
	 * @returns {String}
	 */
	bytesToUtf8String: function(bytes)
	{		
		// Get the char code for each byte
		for (var i = 0, string = '', length = bytes.length;  i < length;  i++)
		{
			var byte = bytes[i];

			string += String.fromCharCode(byte);
		}

		// Decode string back to UTF-8
		return decodeURIComponent(escape(string));
	}
};