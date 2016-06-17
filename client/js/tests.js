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

// On page load run QUnit tests
$(document).ready(function()
{
	// Initialise test data
	var pad = '72fa270d9148a82c056a62e32c5dbb916db2cba99efbc2c49533c5349bdeaeb4ec307e588b0cb125b4c23f07ccbac5d30b7736903cfb37a72ca6c189185546d401b48210cf46468a5615f2b63eaa7c415592a5bdad98bf47b3f49058ae278d7194567240a66f11755ead65cd194a36f30f7cf98d6c60fd45eca00a845922fc5d411f70a8b3d9c0dfaf69df60c42f6aec429ef479f3caa312ded2944546b93b49e09a53e679c999c99900a6bd93f93d2c2fcd387cb28625ab6c6bbd24baf9251c'; // Generated from TRNG
	var plaintextMessage = 'The quick brown fox jumps over the lazy dog';	
	var plaintextMessageMax = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps';
	var plaintextMessageMaxExceeded = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.';
	var plaintextMessageLength = common.messageSize;
	var plaintextMessageTimestamp = 1374237870;
	var plaintextMessageMacAlgorithmIndex = 0;		// skein-512 - see common.macAlgorithms[0]
	var testRngKey = 'cb125b4c23f07ccbac5d30b7736c429ef479f3caa312ded2944546b93b1ca704';	// 256 bits
	
	// If the currently loaded database is the same as the blank default schema then load a default failsafe RNG key 
	// and nonce for testing functions that use getRandomBits(), otherwise it will use the user's current one. This 
	// check prevents overwriting the user's real key with a default testing one.
	if ((JSON.stringify(db.padData) === JSON.stringify(db.padDataSchema)))
	{		
		db.padData.info.failsafeRngKey = testRngKey;
		db.padData.info.failsafeRngNonce = 0;
	}
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test if HTML5 Local Storage is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var localStorageSupported = common.checkLocalStorageSupported();
	var testWrite = true;
	var testRead = true;
	var testRemove = true;
	
	try {
		// Try writing some data to localStorage which will throw an exception if unavailable
		localStorage.setItem('testWrite', 'jericho');
	}
	catch (exception)
	{
		testWrite = false;
		console.error(exception);
	}
	
	try {
		// Try reading from localStorage
		testRead = localStorage.getItem('testWrite');
	}
	catch (exception)
	{
		testRead = false;
	}
	
	try {
		// Try removing from localStorage
		localStorage.removeItem('testWrite');
	}
	catch (exception)
	{
		testRemove = false;
	}
	
	test("Test if HTML5 Local Storage is supported in this browser", function()
	{
		ok(localStorageSupported === true, 'Local storage enabled: ' + localStorageSupported);
		ok(testWrite === true, 'Local storage write ability: ' + testWrite);
		ok(testRead === 'jericho', 'Local storage read ability: ' + ((testRead === 'jericho') ? true : false));
		ok(testRemove === true, 'Local storage remove ability: ' + testRemove);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Workers are supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webWorkersSupported = common.checkWebWorkerSupported();
	
	test("Test if HTML5 Web Workers are supported in this browser", function()
	{
		ok(webWorkersSupported === true);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Crypto API is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webCryptoApiSupported = common.checkWebCryptoApiSupported();
	
	test("Test if HTML5 Web Crypto API is supported in this browser", function()
	{
		ok(webCryptoApiSupported === true);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test if HTML5 Offline Web Application Cache is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var offlineWebApplicationCacheSupported = common.checkOfflineWebApplicationSupported();
	
	test("Test if HTML5 Offline Web Application Cache is supported in this browser", function()
	{
		ok(offlineWebApplicationCacheSupported === true);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test left padding of binary number so it is 8 bits long
	 * ------------------------------------------------------------------
	 */
	
	var testBinaryFrom7to8bit = common.leftPadding('1100001', '0', 8);
	var testNumeric = common.leftPadding(43, '0', 3);
	var testNumericLengthExtensionNotNeeded = common.leftPadding(130, '0', 3);
		
	test("Test left padding of numbers to certain length", function()
	{
		ok(testBinaryFrom7to8bit === '01100001', testBinaryFrom7to8bit);
		ok(testNumeric === '043', testNumeric);
		ok(testNumericLengthExtensionNotNeeded === '130', testNumericLengthExtensionNotNeeded);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test conversion of small integer to hexadecimal
	 * ------------------------------------------------------------------
	 */
	
	test("Test conversion of small integer to hexadecimal", function()
	{
		ok(common.convertSingleByteIntegerToHex(0) === '00');
		ok(common.convertSingleByteIntegerToHex(3) === '03');
		ok(common.convertSingleByteIntegerToHex(7) === '07');
		ok(common.convertSingleByteIntegerToHex(10) === '0a');
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Test conversion of large integer to hexadecimal
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Test conversion of large integer to hexadecimal", function()
	{
		var hexResultA = common.convertIntegerToHex(10000);
		var hexResultB = common.convertIntegerToHex('10000');
		var hexResultC = common.convertIntegerToHex(100000);
		var hexResultD = common.convertIntegerToHex(123);
		var hexResultE = common.convertIntegerToHex(123456789);
		var hexResultF = common.convertIntegerToHex(Number.MAX_SAFE_INTEGER);
		
		ok(hexResultA === '2710', '10000 converted to hex ' + hexResultA + ' should equal 2710 with even length ' + hexResultA.length);
		ok(hexResultB === '2710', '"10000" converted to hex ' + hexResultB + ' should equal 2710 with even length ' + hexResultB.length);
		ok(hexResultC === '0186a0', '100000 converted to hex ' + hexResultC + ' should equal 0186a0 with even length ' + hexResultC.length);
		ok(hexResultD === '7b', '123 converted to hex ' + hexResultD + ' should equal 7b with even length ' + hexResultD.length);
		ok(hexResultE === '075bcd15', '123456789 converted to hex ' + hexResultE + ' should equal 075bcd15 with even length ' + hexResultE.length);
		ok(hexResultF === '1fffffffffffff', '10000 converted to hex ' + hexResultF + ' should equal 1fffffffffffff with even length ' + hexResultF.length);
	});
		
	/*
	 * ------------------------------------------------------------------
	 * Get random bits from the Web Crypto API and XOR it with Salsa20 keystream
	 * ------------------------------------------------------------------
	 */
	
	test("Get random bits from the Web Crypto API and XOR it with Salsa20 keystream", function()
	{
		var failsafeRngNonceA = 0;
		var requiredNumOfBitsA = 17;
		var rngRandomBitsA = common.getEncryptedRandomBits(requiredNumOfBitsA, testRngKey, failsafeRngNonceA, 'binary');
		var rngRandomBitsLengthA = rngRandomBitsA.length;
		var expectedNumOfBitsA = requiredNumOfBitsA;		// Already binary

		var failsafeRngNonceB = 1;
		var requiredNumOfBitsB = 128;
		var rngRandomBitsB = common.getEncryptedRandomBits(requiredNumOfBitsB, testRngKey, failsafeRngNonceB, 'hexadecimal');
		var rngRandomBitsLengthB = rngRandomBitsB.length;
		var expectedNumOfBitsB = requiredNumOfBitsB / 4;	// Convert to hex length

		var randomBits0Hex = common.getEncryptedRandomBits(0, testRngKey, 2, 'hexadecimal');
		var randomBits0Bin = common.getEncryptedRandomBits(0, testRngKey, 3, 'binary');

		var randomBits9Hex = common.getEncryptedRandomBits(9, testRngKey, 4, 'hexadecimal');
		var randomBits9Bin = common.getEncryptedRandomBits(9, testRngKey, 5, 'binary');

		var randomBits11Hex = common.getEncryptedRandomBits(11, testRngKey, 6, 'hexadecimal');
		var randomBits11Bin = common.getEncryptedRandomBits(11, testRngKey, 7, 'binary');

		var randomBits128Hex = common.getEncryptedRandomBits(128, testRngKey, 8, 'hexadecimal');
		var randomBits128Bin = common.getEncryptedRandomBits(128, testRngKey, 9, 'binary');

		var randomBits512Hex = common.getEncryptedRandomBits(512, testRngKey, 10, 'hexadecimal');
		var randomBits512Bin = common.getEncryptedRandomBits(512, testRngKey, 11, 'binary');

		var randomBits768Hex = common.getEncryptedRandomBits(768, testRngKey, 12, 'hexadecimal');
		var randomBits768Bin = common.getEncryptedRandomBits(768, testRngKey, 13, 'binary');

		var randomBits1024Hex = common.getEncryptedRandomBits(1024, testRngKey, 14, 'hexadecimal');
		var randomBits1024Bin = common.getEncryptedRandomBits(1024, testRngKey, 15, 'binary');

		var randomBits1536Hex = common.getEncryptedRandomBits(1536, testRngKey, 16, 'hexadecimal');
		var randomBits1536Bin = common.getEncryptedRandomBits(1536, testRngKey, 17, 'binary');

		var nonceA = common.getEncryptedRandomBits(512, testRngKey, 18, 'hexadecimal');
		var nonceB = common.getEncryptedRandomBits(512, testRngKey, 19, 'hexadecimal');
		var nonceC = common.getEncryptedRandomBits(512, testRngKey, 20, 'hexadecimal');
		var noRepeat = (nonceA !== nonceB) && (nonceA !== nonceC) && (nonceB !== nonceC);

		// Test wrapper function
		var currentNonce = db.padData.info.failsafeRngNonce;
		var randomBitsFromWrapperFunction = common.getRandomBits(128, 'hexadecimal');
		var expectedNewNonce = currentNonce + 1;
		var expectedRandomBitLength = 128 / 4;
		
		ok(rngRandomBitsLengthA === expectedNumOfBitsA, 'Random bits ' + rngRandomBitsA + ' of length ' + rngRandomBitsLengthA + ' should equal length ' + expectedNumOfBitsA);
		ok(rngRandomBitsLengthB === expectedNumOfBitsB, 'Random bits ' + rngRandomBitsB + ' of length ' + rngRandomBitsLengthB + ' should equal length ' + expectedNumOfBitsB);
		
		ok(randomBits0Hex.length === 0, '0 random bits hex: ' + randomBits0Hex);
		ok(randomBits0Bin.length === 0, '0 random bits: ' + randomBits0Bin);
		
		ok(randomBits9Hex.length === 2, '9 random bits hex requested, should be truncated to 8 bits: ' + randomBits9Hex);
		ok(randomBits9Bin.length === 9, '9 random bits: ' + randomBits9Bin);
		
		ok(randomBits11Hex.length === 2, '11 random bits hex, should be truncated to 8 bits: ' + randomBits11Hex);
		ok(randomBits11Bin.length === 11, '11 random bits: ' + randomBits11Bin);
		
		ok(randomBits128Hex.length === 32, '128 random bits hex ' + randomBits128Hex);
		ok(randomBits128Bin.length === 128, '128 random bits: ' + randomBits128Bin);
		
		ok(randomBits512Hex.length === 128, '512 random bits hex: ' + randomBits512Hex);
		ok(randomBits512Bin.length === 512, '512 random bits: ' + randomBits512Bin);
		
		ok(randomBits768Hex.length === 192, '768 random bits hex: ' + randomBits768Hex);
		ok(randomBits768Bin.length === 768, '768 random bits: ' + randomBits768Bin);
		
		ok(randomBits1024Hex.length === 256, '1024 random bits hex: ' + randomBits1024Hex);
		ok(randomBits1024Bin.length === 1024, '1024 random bits: ' + randomBits1024Bin);
		
		ok(randomBits1536Hex.length === 384, '1536 random bits hex: ' + randomBits1536Hex);
		ok(randomBits1536Bin.length === 1536, '1536 random bits: ' + randomBits1536Bin);
		
		// Check lengths equals 128 hexadecimal chars (512 bits)
		ok(nonceA.length === 128, nonceA);
		ok(nonceB.length === 128, nonceB);
		ok(nonceC.length === 128, nonceC);
		
		// Check no repeating nonces
		ok(noRepeat === true, 'No repeat: ' + noRepeat.toString());
		
		// Check random bits and nonce incremented correctly using the wrapper function
		ok(randomBitsFromWrapperFunction.length === expectedRandomBitLength, 'Wrapper function random 128 bits: ' + randomBitsFromWrapperFunction + ' with length: ' + randomBitsFromWrapperFunction.length + ' in hex');
		ok(db.padData.info.failsafeRngNonce === expectedNewNonce, 'Wrapper function old nonce was: ' + currentNonce + ' and nonce is now: ' + db.padData.info.failsafeRngNonce);
	});
	
	/*
	 * ------------------------------------------------------------------
	 * Pad the message with random bits up to the maximum message size
	 * ------------------------------------------------------------------
	 */
	var plaintextMessageBinary = common.convertTextToBinary(plaintextMessage);
	var paddingInfo = common.padMessage(plaintextMessageBinary);
	var plaintextPaddedBinary = paddingInfo.plaintextWithPaddingBinary;
	var originalPlaintextLength = paddingInfo.actualMessageLength;
	var plaintextPaddedText = common.convertBinaryToText(plaintextPaddedBinary);
		
	test("Pad the message with random bits up to the maximum message size", function()
	{
		ok(originalPlaintextLength === 43, plaintextPaddedText);
		ok(plaintextPaddedBinary.length === common.messageSizeBinary, plaintextPaddedText);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test padding function on max length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxBinary = common.convertTextToBinary(plaintextMessageMax);	
	var paddingInfoMaxPadded = common.padMessage(plaintextMessageMaxBinary);
	var plaintextMessageMaxPadded = paddingInfoMaxPadded.plaintextWithPaddingBinary;
	var originalPlaintextLengthMaxPadded = paddingInfoMaxPadded.actualMessageLength;
		
	test("Test padding function on max length plaintext", function()
	{
		// Message should be same, ie no padding added
		ok(plaintextMessageMaxBinary === plaintextMessageMaxPadded, plaintextMessageMaxPadded);
		ok(originalPlaintextLengthMaxPadded === common.messageSize, originalPlaintextLengthMaxPadded);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test padding function on oversize length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxExceededBinary = common.convertTextToBinary(plaintextMessageMaxExceeded);
	var paddingInfoMaxExceededPadded = common.padMessage(plaintextMessageMaxExceededBinary);
	var plaintextMessageMaxExceededPadded = paddingInfoMaxExceededPadded.plaintextWithPaddingBinary;
	var plaintextMessageMaxExceededPaddedLength = paddingInfoMaxExceededPadded.actualMessageLength;
	var plaintextMessageMaxExceededPaddedText = common.convertBinaryToText(plaintextMessageMaxExceededPadded);
	
	test("Test padding function on oversize length plaintext", function()
	{
		// Message should be truncated, ie no padding added
		ok(plaintextMessageMaxExceededPadded === plaintextMessageMaxBinary, plaintextMessageMaxExceededPaddedText);
		ok(plaintextMessageMaxExceededPaddedLength === common.messageSize, plaintextMessageMaxExceededPaddedLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get the current timestamp in UTC and test conversion to binary
	 * ------------------------------------------------------------------
	 */
	
	var timestamp = common.getCurrentUtcTimestamp();
	var timestampBinary = common.convertIntegerToBinary(timestamp, common.messageTimestampSizeBinary);
	var timestampLengthBinary = timestampBinary.length;
	
	var timestampBinaryB = common.convertIntegerToBinary(plaintextMessageTimestamp, common.messageTimestampSizeBinary);
	var timestampLengthBinaryB = timestampBinary.length;
	
	test("Get the current timestamp in UTC and test conversion to binary", function()
	{
		ok(timestampLengthBinary === common.messageTimestampSizeBinary, 'Bits = ' + timestampLengthBinary);
		ok(timestampLengthBinaryB === common.messageTimestampSizeBinary, 'Bits = ' + timestampLengthBinaryB);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Convert the binary timestamp back to an integer then a date
	 * ------------------------------------------------------------------
	 */
	
	var convertedFromBinaryTimestamp = common.convertBinaryToInteger(timestampBinaryB);
		
	test("Convert the binary timestamp back to an integer then a date", function()
	{
		ok(convertedFromBinaryTimestamp == plaintextMessageTimestamp, convertedFromBinaryTimestamp);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Convert the max length plaintext to binary
	 * ------------------------------------------------------------------
	 */
	
	// Use the maximum length one for the remainder of tests for easier testing
	var plaintextMessageMaxBinary = common.convertTextToBinary(plaintextMessageMax);
	var plaintextMessageMaxBinaryLength = plaintextMessageMaxBinary.length;
		
	test("Convert the max length plaintext to binary", function()
	{
		ok(plaintextMessageMaxBinaryLength === common.messageSizeBinary, plaintextMessageMaxBinaryLength);
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Get a random MAC algorithm depending on the last byte of the pad
	 * ------------------------------------------------------------------
	 */
		
	// Try different end bytes on the end of the key
	var randomMacIndex = common.getRandomMacAlgorithmIndex(pad);
	var testRandomMacIndexB = common.getRandomMacAlgorithmIndex('ab');
	var testRandomMacIndexC = common.getRandomMacAlgorithmIndex('14');
	var testRandomMacIndexD = common.getRandomMacAlgorithmIndex('df');
	
	// Get the corresponding algorithm
	var randomMacAlgorithm = common.macAlgorithms[randomMacIndex];
	var testRandomMacAlgorithmB = common.macAlgorithms[testRandomMacIndexB];
	var testRandomMacAlgorithmC = common.macAlgorithms[testRandomMacIndexC];
	var testRandomMacAlgorithmD = common.macAlgorithms[testRandomMacIndexD];
	
	test("Get a random MAC algorithm depending on the last byte of the pad", function()
	{
		ok(randomMacIndex === 0, randomMacIndex.toString() + ' ' + randomMacAlgorithm);
		ok(testRandomMacIndexB === 1, testRandomMacIndexB.toString() + ' ' + testRandomMacAlgorithmB);
		ok(testRandomMacIndexC === 0, testRandomMacIndexC.toString() + ' ' + testRandomMacAlgorithmC);
		ok(testRandomMacIndexD === 1, testRandomMacIndexD.toString() + ' ' + testRandomMacAlgorithmD);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Prepare message for encryption
	 * ------------------------------------------------------------------
	 */
		
	var messagePartsBinary = common.prepareMessageForEncryption(plaintextMessageMaxBinary, plaintextMessageLength, plaintextMessageTimestamp);
	var messagePartsBinaryLength = messagePartsBinary.length;
		
	test("Prepare message for encryption", function()
	{
		ok(messagePartsBinaryLength === common.messageSizeBinary + common.messageLengthSizeBinary + common.messageTimestampSizeBinary, messagePartsBinary);
		ok(messagePartsBinaryLength === common.totalMessagePartsSizeBinary, messagePartsBinaryLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Reverse message parts or not depending on second last byte of pad
	 * ------------------------------------------------------------------
	 */
		
	var testReversal = common.reverseMessageParts('af42', '0101');
	var testNoReversal = common.reverseMessageParts('ae42', '0101');
	var messagePartsBinaryReversed = common.reverseMessageParts(pad, messagePartsBinary);
		
	test("Reverse message parts or not depending on second last byte of pad", function()
	{
		ok(testReversal === '1010', testReversal);
		ok(testNoReversal === '0101', testNoReversal);
		ok(messagePartsBinaryReversed === messagePartsBinary.split('').reverse().join(''), messagePartsBinaryReversed);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Convert the one-time pad from hexadecimal to binary
	 * ------------------------------------------------------------------
	 */
	
	var padBinary = common.convertHexadecimalToBinary(pad);
	var padBinaryLength = padBinary.length;
	
	test("Convert one-time pad from hexadecimal to binary", function()
	{		
		ok(padBinaryLength === common.totalPadSizeBinary, padBinaryLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get the pad identifier from pad in binary
	 * ------------------------------------------------------------------
	 */
	
	var padIdentifier = common.getPadIdentifier(padBinary);
	var padIdentifierLength = padIdentifier.length;
	
	test("Get the pad identifier from pad in binary", function()
	{
		ok(padIdentifierLength === common.padIdentifierSizeBinary, padIdentifierLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get one-time pad message parts in binary
	 * ------------------------------------------------------------------
	 */
	
	var padMessagePartsBinary = common.getPadMessageParts(padBinary);
	var padMessagePartsBinaryLength = padMessagePartsBinary.length;
			
	test("Get one-time pad message parts in binary", function()
	{
		ok(padMessagePartsBinaryLength === common.messageSizeBinary + common.messageLengthSizeBinary + common.messageTimestampSizeBinary, padMessagePartsBinaryLength);
		ok(padMessagePartsBinaryLength === common.totalMessagePartsSizeBinary, padMessagePartsBinaryLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Encrypt the message parts with the pad message parts
	 * ------------------------------------------------------------------
	 */
	
	// Test basic truth table: wikipedia.org/wiki/Xor#Truth_table
	var testPlaintext = '0011';
	var testPad = '0101';
	var testCiphertext = common.xorBits(testPad, testPlaintext);
	
	// Test encrypting the plaintext parts
	var encryptedMessagePartsBinary = common.xorBits(padMessagePartsBinary, messagePartsBinaryReversed);
	var encryptedMessagePartsBinaryLength = encryptedMessagePartsBinary.length;
		
	test("Encrypt the message parts with the pad message parts", function()
	{
		ok(testCiphertext === '0110', testCiphertext);
		ok(encryptedMessagePartsBinary === '01011001001010011111110111101000111000111110001010010011101101010010011111000011111001001100111110110111011010001001110111000110101100100111101111000101100010110111001010011111000010000110100000100010010000101011111001111010111111101001110100100110101101010101000101010010001101000001100100000011010100101110010001000011111001010000111111010001001000001011111000111000101101011001000111001001110110101010001000001111100001111010111011111011000100001101000000011111010000101110010000010100101110011010100010110000110001000001000000010001001001000111000010101000000001001111001001000101111100111000010010001111101110011101100101111110010010010110000110110111011010101100111011011110100110000010001100101011011001111011101001010010001111001110011011001000100110010001010110111011010100000001101111001011100110110001110101010100110000001001010100001011000010100001011101111011001000100010011011111001100100110010101000110110101001000000101001011101100001001110101001110111', encryptedMessagePartsBinary);
		ok(encryptedMessagePartsBinaryLength === common.totalMessagePartsSizeBinary, encryptedMessagePartsBinaryLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * XOR two hexadecimal strings together
	 * ------------------------------------------------------------------
	 */
	
	test("XOR two hexadecimal strings together", function()
	{
		var firstStringA = 'a7d9';		// 1010011111011001
		var secondStringA = 'c72a';		// 1100011100101010
		var resultA = common.xorHex(firstStringA, secondStringA);
		var expectedResultA = '60f3';	// 0110000011110011
		
		var firstStringB = '3';		// 0011
		var secondStringB = '5';	// 0101
		var resultB = common.xorHex(firstStringB, secondStringB);
		var expectedResultB = '6';	// 0110
		
		var firstStringC =  '0123456789abcdef';						// 0000000100100011010001010110011110001001101010111100110111101111
		var secondStringC = 'fedcba0987654321';						// 1111111011011100101110100000100110000111011001010100001100100001
		var resultC = common.xorHex(firstStringC, secondStringC);
		var expectedResultC = 'ffffff6e0ece8ece';					// 1111111111111111111111110110111000001110110011101000111011001110
		
		ok(resultA === expectedResultA, firstStringA + ' XOR ' + secondStringA + ' should equal ' + expectedResultA + ', actual result ' + resultA);
		ok(resultB === expectedResultB, firstStringB + ' XOR ' + secondStringB + ' should equal ' + expectedResultB + ', actual result ' + resultB);
		ok(resultC === expectedResultC, firstStringC + ' XOR ' + secondStringC + ' should equal ' + expectedResultC + ', actual result ' + resultC);
	});
	
	/*
	 * ------------------------------------------------------------------
	 * Combine pad identifier and the ciphertext message parts
	 * ------------------------------------------------------------------
	 */
	
	var completeCiphertextBinary = common.combinePadIdentifierAndCiphertext(padIdentifier, encryptedMessagePartsBinary);
		
	test("Combine pad identifier and the ciphertext message parts", function()
	{
		ok(completeCiphertextBinary.length === common.padIdentifierSizeBinary + common.totalMessagePartsSizeBinary);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Convert the complete ciphertext binary to hexadecimal
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextHex = common.convertBinaryToHexadecimal(completeCiphertextBinary);
		
	test("Convert the complete ciphertext binary to hexadecimal", function()
	{
		ok(ciphertextHex === '72fa270d9148a85929fde8e3e293b527c3e4cfb7689dc6b27bc58b729f08682242be7afe9d26b5515234190352e443e50fd120be38b591c9daa20f87aefb10d01f42e414b9a8b0c410112470a804f245f3848fb9d97e4961b76acede98232b67ba523ce6c89915bb501bcb9b1d54c0950b0a177b2226f9932a36a40a5d84ea77');
		ok(ciphertextHex.length === common.padIdentifierSizeHex + common.totalMessagePartsSizeHex);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test hashing with Keccak 512 bit
	 * ------------------------------------------------------------------
	 */
	
	// Test Vector for keccak-512 from Known-answer and Monte Carlo test results http://keccak.noekeon.org/files.html 
	// in the LongMsgKAT_512.txt file. This tests every 8th test vector which is a multiple of 8 bits or full byte. 
	// Len = 2048
	var keccacTestVectorMessageA = '724627916C50338643E6996F07877EAFD96BDF01DA7E991D4155B9BE1295EA7D21C9391F4C4A41C75F77E5D27389253393725F1427F57914B273AB862B9E31DABCE506E558720520D33352D119F699E784F9E548FF91BC35CA147042128709820D69A8287EA3257857615EB0321270E94B84F446942765CE882B191FAEE7E1C87E0F0BD4E0CD8A927703524B559B769CA4ECE1F6DBF313FDCF67C572EC4185C1A88E86EC11B6454B371980020F19633B6B95BD280E4FBCB0161E1A82470320CEC6ECFA25AC73D09F1536F286D3F9DACAFB2CD1D0CE72D64D197F5C7520B3CCB2FD74EB72664BA93853EF41EABF52F015DD591500D018DD162815CC993595B195';
	var keccacTestVectorCorrectResultA = '4E987768469F546296AD1A43D54C0A0A6C87E7E4E26B686612B1E5B1554B689BFFD56D6A4B454CE4A5717625BBAD321F8D05F19C225259646F21416AA2D7C2ED';
	var keccacTestVectorResultA = common.secureHash('keccak-512', keccacTestVectorMessageA.toLowerCase());
	
	// Len = 2552
	var keccacTestVectorMessageB = '3139840B8AD4BCD39092916FD9D01798FF5AA1E48F34702C72DFE74B12E98A114E318CDD2D47A9C320FFF908A8DBC2A5B1D87267C8E983829861A567558B37B292D4575E200DE9F1DE45755FAFF9EFAE34964E4336C259F1E66599A7C904EC02539F1A8EAB8706E0B4F48F72FEC2794909EE4A7B092D6061C74481C9E21B9332DC7C6E482D7F9CC3210B38A6F88F7918C2D8C55E64A428CE2B68FD07AB572A8B0A2388664F99489F04EB54DF1376271810E0E7BCE396F52807710E0DEA94EB49F4B367271260C3456B9818FC7A72234E6BF2205FF6A36546205015EBD7D8C2527AA430F58E0E8AC97A7B6B793CD403D517D66295F37A34D0B7D2FA7BC345AC04CA1E266480DEEC39F5C88641C9DC0BD1358158FDECDD96685BBBB5C1FE5EA89D2CB4A9D5D12BB8C893281FF38E87D6B4841F0650092D447E013F20EA934E18';
	var keccacTestVectorCorrectResultB = '3D370DC850BC7E159CEE3F24D9E915B5B1306FF403C32C7A3A3844F3FC8D90E35F56D83BDD9C637BC45E440E1F27CCD56B6B3872EC19101BBE31845108DCE929';
	var keccacTestVectorResultB = common.secureHash('keccak-512', keccacTestVectorMessageB.toLowerCase());
	
	// Len = 3056
	var keccacTestVectorMessageC = '023D91AC532601C7CA3942D62827566D9268BB4276FCAA1AE927693A6961652676DBA09219A01B3D5ADFA12547A946E78F3C5C62DD880B02D2EEEB4B96636529C6B01120B23EFC49CCFB36B8497CD19767B53710A636683BC5E0E5C9534CFC004691E87D1BEE39B86B953572927BD668620EAB87836D9F3F8F28ACE41150776C0BC6657178EBF297FE1F7214EDD9F215FFB491B681B06AC2032D35E6FDF832A8B06056DA70D77F1E9B4D26AE712D8523C86F79250718405F91B0A87C725F2D3F52088965F887D8CF87206DFDE422386E58EDDA34DDE2783B3049B86917B4628027A05D4D1F429D2B49C4B1C898DDDCB82F343E145596DE11A54182F39F4718ECAE8F506BD9739F5CD5D5686D7FEFC834514CD1B2C91C33B381B45E2E5335D7A8720A8F17AFC8C2CB2BD88B14AA2DCA099B00AA575D0A0CCF099CDEC4870FB710D2680E60C48BFC291FF0CEF2EEBF9B36902E9FBA8C889BF6B4B9F5CE53A19B0D9399CD19D61BD08C0C2EC25E099959848E6A550CA7137B63F43138D7B651';
	var keccacTestVectorCorrectResultC = '218A55796529149F29CC4A19C80E05C26F048ABC9894AD79F11BAC7C28DE53BDC9BDB8BE4984F924640867FCFCE42310ADFA949E2B2568FFA0795FBB3203DE65';
	var keccacTestVectorResultC = common.secureHash('keccak-512', keccacTestVectorMessageC.toLowerCase());
	
	// Len = 3560
	var keccacTestVectorMessageD = '20FF454369A5D05B81A78F3DB05819FEA9B08C2384F75CB0AB6AA115DD690DA3131874A1CA8F708AD1519EA952C1E249CB540D196392C79E87755424FEE7C890808C562722359EEA52E8A12FBBB969DD7961D2BA52037493755A5FA04F0D50A1AA26C9B44148C0D3B94D1C4A59A31ACA15AE8BD44ACB7833D8E91C4B86FA3135A423387B8151B4133ED23F6D7187B50EC2204AD901AD74D396E44274E0ECAFAAE17B3B9085E22260B35CA53B15CC52ABBA758AF6798FBD04ECEECED648F3AF4FDB3DED7557A9A5CFB7382612A8A8F3F45947D1A29CE29072928EC193CA25D51071BD5E1984ECF402F306EA762F0F25282F5296D997658BE3F983696FFA6D095C6369B4DAF79E9A5D3136229128F8EB63C12B9E9FA78AFF7A3E9E19A62022493CD136DEFBB5BB7BA1B938F367FD2F63EB5CA76C0B0FF21B9E36C3F07230CF3C3074E5DA587040A76975D7E39F4494ACE5486FCBF380AB7558C4FE89656335B82E4DB8659509EAB46A19613126E594042732DD4C411F41AA8CDEAC71C0FB40A94E6DA558C05E77B6182806F26D9AFDF3DA00C69419222C8186A6EFAD600B410E6CE2F2A797E49DC1F135319801FA6F396B06F975E2A190A023E474B618E7';
	var keccacTestVectorCorrectResultD = '116AE94C86F68F96B8AEF298A9F5852CC9913A2AD3C3C344F28DCC9B29292A716FAF51DD04A9433D8A12572E1DBC581A7CDC4E50BC1CA9051DDBC121F2E864E2';
	var keccacTestVectorResultD = common.secureHash('keccak-512', keccacTestVectorMessageD.toLowerCase());
	
	// Len = 4064
	var keccacTestVectorMessageE = '4FBDC596508D24A2A0010E140980B809FB9C6D55EC75125891DD985D37665BD80F9BEB6A50207588ABF3CEEE8C77CD8A5AD48A9E0AA074ED388738362496D2FB2C87543BB3349EA64997CE3E7B424EA92D122F57DBB0855A803058437FE08AFB0C8B5E7179B9044BBF4D81A7163B3139E30888B536B0F957EFF99A7162F4CA5AA756A4A982DFADBF31EF255083C4B5C6C1B99A107D7D3AFFFDB89147C2CC4C9A2643F478E5E2D393AEA37B4C7CB4B5E97DADCF16B6B50AAE0F3B549ECE47746DB6CE6F67DD4406CD4E75595D5103D13F9DFA79372924D328F8DD1FCBEB5A8E2E8BF4C76DE08E3FC46AA021F989C49329C7ACAC5A688556D7BCBCB2A5D4BE69D3284E9C40EC4838EE8592120CE20A0B635ECADAA84FD5690509F54F77E35A417C584648BC9839B974E07BFAB0038E90295D0B13902530A830D1C2BDD53F1F9C9FAED43CA4EED0A8DD761BC7EDBDDA28A287C60CD42AF5F9C758E5C7250231C09A582563689AFC65E2B79A7A2B68200667752E9101746F03184E2399E4ED8835CB8E9AE90E296AF220AE234259FE0BD0BCC60F7A4A5FF3F70C5ED4DE9C8C519A10E962F673C82C5E9351786A8A3BFD570031857BD4C87F4FCA31ED4D50E14F2107DA02CB5058700B74EA241A8B41D78461658F1B2B90BFD84A4C2C9D6543861AB3C56451757DCFB9BA60333488DBDD02D601B41AAE317CA7474EB6E6DD';
	var keccacTestVectorCorrectResultE = 'DEA56BDABBC6D24183CF7BDE1E1F78631B2B0230C76FF2F43075F2FDE77CF052769276CAD98DA62394EC62D77730F5761489585E093EA7315F3592717C485C84';
	var keccacTestVectorResultE = common.secureHash('keccak-512', keccacTestVectorMessageE.toLowerCase());
	
	// Len = 4568
	var keccacTestVectorMessageF = 'FE06A4706468B369F7624F62D04F9FAC020F05152F13E350016B2A29EFFF9A393940C138553356B0E2848C01B622B95FFA11AB07585F7DCBBF90E9F8EC5FA2FB7B4CEE0D0A4E8D33490ABD058CF3BB85F0CD9B1BD3E9823082D70B1A92ACA6F2C87216B4BA09FEDDCAA4CF254336146CC75604FB1F286918FA2434CA36BE2621049438A400BDEEA6C657F0301503CD7E6E38350838F60EA7F001755DA4142CE4579B39029DA83F1646B7ECB9947EE89ABA377099B82026960B9EE600779BF00D6EB0CD09226DB6915A7ADED27E6749E2CBC2C8B030CE1850EBFBE24C0658F29E9E709CD10DB8A77EFDEFC90FDD7B9AD7A7E0334412A53D248C4C12BF2987B7ACCD2A8A602F184583AA560C016093B56B100154477B834664E6B85A19F8DC909B4D79816AF12266C731E29A304E9BED8EF1C8030365B7DEAF3D436957308117C7C5767E0CDA6E342DDAF824233CBF4E699DC667357CB35C602AC6BDDEE71B352AF55CB93941A1A6301A9904447AF9EE486114D57AE03901F10084ADC0096E465E2EAD2496273112F2FAE626E230D42EC22EA10A8289B3E35EEE42150769D6E663A3CA29174316EC93A24F148D984053B8F98664EACA3E0DEA0B42E8EE30F81A2CD6E42C189A25FECB6E643E693E1F8871B837C3F5FF2AAFD1650A465DC8E5C1993BE65CFFD87F2C680C86B0AD3118834A5F2E490015137BA945C2775DBD77FB3E5C67819A9A7A94A656FC4761659C5B30ED2AC55A6D249B700BC9C93D590490AAAAA75A9FC34A90D5A9106F2860BDE19FE5815436068A7F8EA4636A';
	var keccacTestVectorCorrectResultF = '2E6236117C4F99478BFF204A443C64777CC0D658A24605E810E5FF12F279BC326C439111A911583176280D63C4BF9C69F40729CB976996AE7765E591004CD799';
	var keccacTestVectorResultF = common.secureHash('keccak-512', keccacTestVectorMessageF.toLowerCase());
	
	// Len = 5072
	var keccacTestVectorMessageG = 'D0FF6E045F4B636F75A389799F314066644854821B6E7AE4047ADFDE2D0C0E02C250F0BE582BEC94011189B964A8AF430F5921ED9D9F4446E4C788515B89CA69E5F7CDFCCC9E83E8F9460145B43DDC41C07CC512B7E6FDD0E1E7AABA29A6C016CCB7BD54B145F3951EAB9BC4908F623E5A9B0C5B36056292540B79FD15C53457DC74A65FD773A34D6B313A056F79BC29A3FAC15F6A1446BFAEEAAFBAC8ECF8168DDE5F6AE6B6E579BD3CE74E7ABFADF361D0FD32D56586A8D2D4FF4CFDF8A750FAFDE4C2E9EB32B06847FA30B13CC273532D1A23C8257F80C60B8FA94FA976F534145CD61C41C0A511B62CADD5848CEFF643F83CE43F8E6969C5A559AFAD60E310599A34B2E5E029FBDDF2988FCE59269C7128A1FC79A74B154D8AA2850DCFDBF594684E74099E37882B440367C1DD3003F61CAFB46AC75D30E677AF54559A5DAB70C506CF61A9C35E0E56E1430746916DDEEC8D89B0C10DAA02C5D7E9F42621D2B312EAFFC9FF306297952A32D26C2148570AEC90501CA739CE5E689E7066D9580A4FC25E2023897C74C6856273133E1275A0D275DC5B75DB724CD12C9C01BB95AB5A227B7850020630506096878D289923177183EA9282A4C78EC212D2E898CB99D81A3364DF20927EE34D4475A5CF5CDB24088ED75B60201922E9C972D8556CA75F8274D15F3FB88A6B42C766DEF6B21329DEE7C457446DDE8C26405FE5D0309A04229F449E8490CF9000EE8DF400CB7C7EE831BD7059D24088FB42D61681CDE45050FCA78FF64D9C8D1F58B55F802FA5D2F2E723F3E4EED4338B060D31C8ACC46D26870BD45D0DE0798D48E32AAD1A6D4322E69F5E72309B9D7FA1F24BB1D63FF09ED47391C232497BF222C542A70975C8292D275197A4CA';
	var keccacTestVectorCorrectResultG = 'C8EE158CC1AD478A5B16645BCB3A54A38C7A554AB5840D13FA07C70C18A35E3035FB64445A9B65DA06EB7CFA5BD3C921B20D150CFB73213154283840B728DE1E';
	var keccacTestVectorResultG = common.secureHash('keccak-512', keccacTestVectorMessageG.toLowerCase());
		
	test("Test hashing with Keccak 512 bit", function()
	{
		ok(keccacTestVectorResultA === keccacTestVectorCorrectResultA.toLowerCase(), keccacTestVectorResultA);
		ok(keccacTestVectorResultB === keccacTestVectorCorrectResultB.toLowerCase(), keccacTestVectorResultB);
		ok(keccacTestVectorResultC === keccacTestVectorCorrectResultC.toLowerCase(), keccacTestVectorResultC);
		ok(keccacTestVectorResultD === keccacTestVectorCorrectResultD.toLowerCase(), keccacTestVectorResultD);
		ok(keccacTestVectorResultE === keccacTestVectorCorrectResultE.toLowerCase(), keccacTestVectorResultE);
		ok(keccacTestVectorResultF === keccacTestVectorCorrectResultF.toLowerCase(), keccacTestVectorResultF);
		ok(keccacTestVectorResultG === keccacTestVectorCorrectResultG.toLowerCase(), keccacTestVectorResultG);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test hashing with Skein 512 bit
	 * ------------------------------------------------------------------
	 */
	
	// Test Vectors for Skein-512-512 from http://www.skein-hash.info/sites/default/files/skein1.3.pdf - spaces removed for simplicity
	var testMessage = 'FF';
	var testCorrectResultA = '71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A';
	var testResultA = common.secureHash('skein-512', testMessage.toLowerCase());
	
	var testMessageB = 'FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0';
	var testCorrectResultB = '45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B';
	var testResultB = common.secureHash('skein-512', testMessageB.toLowerCase());
	
	var testMessageC = 'FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180';
	var testCorrectResultC = '91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7';
	var testResultC = common.secureHash('skein-512', testMessageC.toLowerCase());
	
	test("Test hashing with Skein 512 bit", function()
	{
		ok(testResultA === testCorrectResultA.toLowerCase(), testResultA);
		ok(testResultB === testCorrectResultB.toLowerCase(), testResultB);
		ok(testResultC === testCorrectResultC.toLowerCase(), testResultC);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test creation of MAC for chat program
	 * ------------------------------------------------------------------
	 */
	
	var mac = common.createMessageMac(plaintextMessageMacAlgorithmIndex, pad, ciphertextHex);	// skein-512
	var macB = common.createMessageMac(1, pad, ciphertextHex);									// keccak-512
	
	test("Test creation of MAC for chat program", function()
	{
		ok(mac === '925cfd85ad06bc345e8e5b832557295641eee29762a3165eda7449da0c9079508722b81f5f7824c3348ec4ae1de91dc70fd2f21173713c44052d7a8096ca7cae', mac);
		ok(macB === 'd2c736ced072f3ad127efada92300427af569d39e04531d254b53b26bfe953cf3dd100c22962e0e1292405c36d44e232c2aaa5891ee82d5d7a34750270b80b97', macB);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get MAC part of the one-time pad to use for encrypting the MAC
	 * ------------------------------------------------------------------
	 */

	var padForMac = common.getPadPartForMac(pad);
	var padForMacLength = padForMac.length;

	test("Get MAC part of the one-time pad to use for encrypting the MAC", function()
	{
		ok(padForMac === '411f70a8b3d9c0dfaf69df60c42f6aec429ef479f3caa312ded2944546b93b49e09a53e679c999c99900a6bd93f93d2c2fcd387cb28625ab6c6bbd24baf9251c', padForMac);
		ok(padForMacLength === common.macSizeHex, padForMacLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Encrypt the MAC with one-time pad
	 * ------------------------------------------------------------------
	 */
	
	var encryptedMac = common.encryptOrDecryptMac(padForMac, mac);
	var encryptedMacLength = encryptedMac.length;
	
	test("Encrypt the MAC with one-time pad", function()
	{
		ok(encryptedMac === 'd3438d2d1edf7cebf1e784e3e17843ba037016ee9169b54c04a6dd9f4a29421967b8ebf926b1bd0aad8e62138e1020eb201fca6dc1f719ef6946c7a42c3359b2', encryptedMac);
		ok(encryptedMacLength === common.macSizeHex, encryptedMacLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Convert the ciphertext hexadecimal back to binary
	 * ------------------------------------------------------------------
	 */
		
	var ciphertextBinaryConvertedFromHex = common.convertHexadecimalToBinary(ciphertextHex);
	
	test("Convert the ciphertext hexadecimal back to binary", function()
	{
		ok(ciphertextBinaryConvertedFromHex === completeCiphertextBinary);
		ok(ciphertextBinaryConvertedFromHex.length === common.padIdentifierSizeBinary + common.totalMessagePartsSizeBinary);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get message ciphertext parts from ciphertext
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextMessageParts = common.getPadMessageParts(ciphertextBinaryConvertedFromHex);
	var ciphertextMessagePartsLength = ciphertextMessageParts.length;
	
	test("Get message ciphertext parts from ciphertext", function()
	{
		ok(ciphertextMessageParts === encryptedMessagePartsBinary, ciphertextMessageParts);
		ok(ciphertextMessagePartsLength === common.totalMessagePartsSizeBinary);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Decrypt binary ciphertext message parts to binary plaintext message parts
	 * ------------------------------------------------------------------
	 */
	
	var decryptedMessagePartsBinary = common.xorBits(padMessagePartsBinary, ciphertextMessageParts);
	var decryptedMessagePartsBinaryLength = decryptedMessagePartsBinary.length;;
	
	test("Decrypt ciphertext message parts to plaintext message parts binary", function()
	{
		ok(decryptedMessagePartsBinary === messagePartsBinaryReversed, decryptedMessagePartsBinary);
		ok(decryptedMessagePartsBinaryLength === common.totalMessagePartsSizeBinary, decryptedMessagePartsBinaryLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Reverse binary plaintext message parts back to original order
	 * ------------------------------------------------------------------
	 */
	
	var decryptedUnreversedMessagePartsBinary = common.reverseMessageParts(pad, decryptedMessagePartsBinary);
		
	test("Reverse binary plaintext message parts back to original order", function()
	{
		ok(decryptedUnreversedMessagePartsBinary === messagePartsBinary, decryptedUnreversedMessagePartsBinary);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Split up ASCII plaintext message parts
	 * ------------------------------------------------------------------
	 */		
	
	var messageParts = common.getSeparateMessageParts(decryptedUnreversedMessagePartsBinary);	
	var messagePlaintextWithPaddingBinary = messageParts.messagePlaintextWithPaddingBinary;
	var actualMessageLength = messageParts.messageLength;
	var messageTimestamp = messageParts.messageTimestamp;
	
	test("Split up ASCII plaintext message parts", function()
	{
		ok(messagePlaintextWithPaddingBinary === plaintextMessageMaxBinary, messagePlaintextWithPaddingBinary);
		ok(actualMessageLength === plaintextMessageLength, actualMessageLength);
		ok(messageTimestamp === plaintextMessageTimestamp, messageTimestamp);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get plaintext message without padding
	 * ------------------------------------------------------------------
	 */	
		
	// Test removal of padding for message
	var messageWithoutPaddingBinary = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, actualMessageLength);
	var messageWithoutPaddingBinaryLength = messageWithoutPaddingBinary.length;
	
	// Extra tests to make sure only digits allowed
	var lengthOfMessageTestA = '1';		// min
	var lengthOfMessageTestB = 'abc';	// non digit
	var lengthOfMessageTestC = '-99';	// negative
	var lengthOfMessageTestD = '255';	// max int for 1 byte
	var lengthOfMessageTestE = '300';	// exceed max message size
	var lengthOfMessageTestF = '0';		// below min
	
	// Test removing the padding (the last 3 should fail the checks and return the full message with padding)
	var messageWithoutPaddingA = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestA);
	var messageWithoutPaddingB = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestB);
	var messageWithoutPaddingC = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestC);
	var messageWithoutPaddingD = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestD);
	var messageWithoutPaddingE = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestE);
	var messageWithoutPaddingF = common.removePaddingFromMessage(messagePlaintextWithPaddingBinary, lengthOfMessageTestF);
	
	test("Get plaintext message without padding", function()
	{
		ok(messageWithoutPaddingBinaryLength === common.messageSizeBinary, messageWithoutPaddingBinaryLength);
		ok(messageWithoutPaddingBinary === plaintextMessageMaxBinary, common.convertBinaryToText(messageWithoutPaddingBinary));
		
		ok(messageWithoutPaddingA.length === 8, common.convertBinaryToText(messageWithoutPaddingA));
		ok(messageWithoutPaddingB.length === common.messageSizeBinary, common.convertBinaryToText(messageWithoutPaddingB));
		ok(messageWithoutPaddingC.length === common.messageSizeBinary, common.convertBinaryToText(messageWithoutPaddingC));
		ok(messageWithoutPaddingD.length === common.messageSizeBinary, common.convertBinaryToText(messageWithoutPaddingD));
		ok(messageWithoutPaddingE.length === common.messageSizeBinary, common.convertBinaryToText(messageWithoutPaddingE));
		ok(messageWithoutPaddingF.length === common.messageSizeBinary, common.convertBinaryToText(messageWithoutPaddingF));
	});


	/*
	 * ------------------------------------------------------------------
	 * Basic encryption and decryption of all possible ASCII characters
	 * ------------------------------------------------------------------
	 */
	
	// Convert the pad and plaintext to binary
	var binaryPad = common.convertTextToBinary(pad);	
	var binaryPlaintext = common.convertTextToBinary(common.allPossibleChars.join(''));
	
	// Truncate pad to same length as plaintext
	var binaryPlaintextLength = binaryPlaintext.length;
	var binaryPadTruncated = binaryPad.substr(0, binaryPlaintextLength);
	
	// Encrypt and decrypt the message
	var binaryEncryptedMessage = common.xorBits(binaryPadTruncated, binaryPlaintext);
	var hexadecimalEncryptedMessage = common.convertBinaryToHexadecimal(binaryEncryptedMessage);
	var binaryDecryptedMessageFromHex = common.convertHexadecimalToBinary(hexadecimalEncryptedMessage);
	var binaryDecryptedMessage = common.xorBits(binaryPadTruncated, binaryDecryptedMessageFromHex);
	var asciiPlaintext = common.convertBinaryToText(binaryDecryptedMessage);
	
	test("Basic encryption and decryption of all possible ASCII characters", function()
	{
		ok(asciiPlaintext === common.allPossibleChars.join(''), asciiPlaintext);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Encrypt message to be ready for transport using random padding and random MAC
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextMessageAndMac = common.encryptAndAuthenticateMessage(plaintextMessage, pad);
	var ciphertextMessageAndMacLength = ciphertextMessageAndMac.length;

	test("Encrypt message to be ready for transport using random padding and random MAC", function()
	{
		// No point comparing the ciphertext or MAC to a fixed value because it will be different each time when the 
		// ciphertext is created with random padding and random MAC algorithm
		ok(ciphertextMessageAndMacLength === (common.padIdentifierSizeHex + common.totalMessagePartsSizeHex + common.macSizeHex), 'Concatenated ciphertext and MAC length: ' + ciphertextMessageAndMacLength + ' - ' + ciphertextMessageAndMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get the encrypted MAC from the end of the ciphertext
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextMac = common.getMacFromCiphertext(ciphertextMessageAndMac);
	var ciphertextMacLength = ciphertextMac.length;
	
	test("Get the encrypted MAC from the end of the ciphertext", function()
	{
		ok(ciphertextMacLength === common.macSizeHex, 'Ciphertext MAC length (hex): ' + ciphertextMacLength + ' - ' + ciphertextMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Decrypt the MAC
	 * ------------------------------------------------------------------
	 */
		
	var decryptedMac = common.encryptOrDecryptMac(padForMac, ciphertextMac);
	var decryptedMacLength = decryptedMac.length;
		
	test("Decrypt the MAC", function()
	{
		ok(decryptedMacLength === common.macSizeHex, 'MAC length (hex): ' + decryptedMacLength + ' - ' + decryptedMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get just the ciphertext without the ciphertext MAC
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextWithoutMac = common.getCiphertextWithoutMac(ciphertextMessageAndMac);
	var ciphertextWithoutMacLength = ciphertextWithoutMac.length;
	
	test("Get just the ciphertext without the ciphertext MAC", function()
	{
		ok(ciphertextWithoutMacLength === common.padIdentifierSizeHex + common.totalMessagePartsSizeHex, 'Ciphertext length (hex): ' + ciphertextWithoutMacLength + ' - ' + ciphertextWithoutMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test verification of MAC
	 * ------------------------------------------------------------------
	 */
	
	var randomMacAlgorithmIndex = common.getRandomMacAlgorithmIndex(pad);
	var validation = common.validateMac(randomMacAlgorithmIndex, pad, ciphertextWithoutMac, decryptedMac);
	
	test("Test verification of MAC", function()
	{
		ok(validation === true, validation);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Get the pad identifier from the ciphertext
	 * ------------------------------------------------------------------
	 */
	
	var padIdFromCiphertext = common.getPadIdentifierFromCiphertext(ciphertextMessageAndMac);
	var padIdFromCiphertextLength = padIdFromCiphertext.length;
		
	test("Get the pad identifier from the ciphertext", function()
	{
		ok(padIdFromCiphertext === '72fa270d9148a8', padIdFromCiphertext);
		ok(padIdFromCiphertextLength === common.padIdentifierSizeHex, padIdFromCiphertextLength);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Decrypt and verify message using random padding and random MAC with wrapper method
	 * ------------------------------------------------------------------
	 */
		
	var decryptionOutput = common.decryptAndVerifyMessage(ciphertextMessageAndMac, pad);
	
	test("Decrypt and verify message using random padding and random MAC with wrapper method", function()
	{
		ok(decryptionOutput.plaintext === plaintextMessage, decryptionOutput.plaintext);
		ok(decryptionOutput.valid === true, 'Message valid and authentic: ' + decryptionOutput.valid);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Strip non ASCII characters from plaintext
	 * ------------------------------------------------------------------
	 */
	
	var allAsciiChars = common.removeInvalidChars(common.allPossibleChars.join(''));
	var miscNonAllowedChars = common.removeInvalidChars('abc ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ xyz');
	var oversizePlaintext = common.removeInvalidChars(plaintextMessageMaxExceeded);
	
	test("Strip non ASCII characters from plaintext", function()
	{
		// All ASCII chars should still be there
		ok(allAsciiChars === common.allPossibleChars.join(''), allAsciiChars);
		ok(miscNonAllowedChars === 'abc  xyz', miscNonAllowedChars);
		ok(oversizePlaintext.length === common.messageSize, oversizePlaintext.length);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Fix the server URL for excess forward slashes
	 * ------------------------------------------------------------------
	 */
	
	test("Fix the server URL for excess forward slashes", function()
	{
		ok(common.normaliseUrl('http://localhost', 'send-message.php') === 'http://localhost/send-message.php');
		ok(common.normaliseUrl('http://localhost/', 'send-message.php') === 'http://localhost/send-message.php');
		ok(common.normaliseUrl('http://localhost/chatserver', 'send-message.php') === 'http://localhost/chatserver/send-message.php');
		ok(common.normaliseUrl('http://localhost/chatserver/', 'send-message.php') === 'http://localhost/chatserver/send-message.php');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test HTML output escaping for XSS
	 * ------------------------------------------------------------------
	 */
	
	var encodedStringA = common.htmlEncodeEntities('<script>alert("xss");</script>');
	var encodedStringB = common.htmlEncodeEntities("<script>alert('xss');</script>");
	var encodedStringC = common.htmlEncodeEntities("&<>\"'/");
	
	test("Test HTML output escaping for XSS", function()
	{
		ok(encodedStringA === '&lt;script&gt;alert(&quot;xss&quot;);&lt;&#x2F;script&gt;', encodedStringA);
		ok(encodedStringB === '&lt;script&gt;alert(&#x27;xss&#x27;);&lt;&#x2F;script&gt;', encodedStringB);
		ok(encodedStringC === '&amp;&lt;&gt;&quot;&#x27;&#x2F;', encodedStringC);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test escaping of message for XSS and linkifying
	 * ------------------------------------------------------------------
	 */
	
	var linkedTextA = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/wiki/One-time_pad is a type of encryption that is impossible to crack if used correctly.');
	var linkedTextB = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/wiki/One-time_pad?test=<script>alert("xss);</script>');
	var linkedTextC = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/<script>alert("xss);</script>/wiki/One-time_pad is a type of encryption');
		
	test("Test escaping of message for XSS and linkifying", function()
	{
		ok(linkedTextA === 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/wiki/One-time_pad">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;wiki&#x2F;O...</a> is a type of encryption that is impossible to crack if used correctly.', linkedTextA);
		ok(linkedTextB === 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/wiki/One-time_pad?test=">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;wiki&#x2F;O...</a>&lt;script&gt;alert(&quot;xss);&lt;&#x2F;script&gt;', linkedTextB);
		ok(linkedTextC === 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;</a>&lt;script&gt;alert(&quot;xss);&lt;&#x2F;script&gt;&#x2F;wiki&#x2F;One-time_pad is a type of encryption', linkedTextC);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test MAC of server request
	 * ------------------------------------------------------------------
	 */
	
	var requestData = {
		'user': 'alpha',
		'apiAction': 'testConnection',
		'nonce': '4d7adb79e3745a3bcc0655fc706208f9daf7a58f88ac38390024e8f136d2a2fccec5b7630a0c95aa68c2f65608b02c630e69ae25935a231c0d05c2d91e040394',
		'timestamp': 1399115283
	};
	var requestDataJson = JSON.stringify(requestData);
	var serverKey = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
	var requestMac = common.authenticateRequest(requestDataJson, serverKey);
	var requestMacLength = requestMac.length;
		
	test("Test MAC of server request", function()
	{
		// Check lengths equals 128 hexadecimal chars (512 bits)
		ok(requestMacLength === 128, requestMacLength);
		ok(requestMac === 'a4c495213131b3cb8c9240f9017c98be3e99b99b2cb88702e7b093e2b58be0699515ae7f6111f6903225d21e6fc547f6e75981a07c8f059ae560c9efbe36a7ca', requestMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test MAC response validation
	 * ------------------------------------------------------------------
	 */
	
	// Mock server response
	var responseDataJson = '{"success":true,"statusMessage":"Server and database connection successful."}';
	
	// Convert the data to hexadecimal so it's in the same format as the key
	var requestDataJsonBinary = common.convertTextToBinary(requestDataJson);
	var responseDataJsonBinary = common.convertTextToBinary(responseDataJson);
	var responseDataJsonHex = common.convertBinaryToHexadecimal(responseDataJsonBinary);
	
	// Mock server response MAC
	var responseMac = common.secureHash('skein-512', serverKey + responseDataJsonHex + requestMac);
	
	// Check MAC validation function
	var validResponse = common.validateResponseMac(serverKey, responseDataJson, requestMac, responseMac);
	
	test("Test MAC response validation", function()
	{
		ok(validResponse === true, validResponse);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test full authentication of server request and response from server
	 * ------------------------------------------------------------------
	 */
	
	/* Add forward slash in front to enable test. Change server address to match test server	 
	// Package the data to be sent to the server
	var data = {
		'user': 'alpha',
		'apiAction': 'testConnection'
	};
	var serverAddressAndPort = 'http://127.0.0.1/';
	var serverKey = '89975057bac787e526aba890440dd89f95f2ea14a1779dcd3ff4bac215418a7566dafb5bf19417ec6d152f636ba8eb3ac4bb823086da8541798f67c3a1055d2e';

	// Send a request off to the server to check the connection
	common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseData)
	{
		console.info('Valid response: ' + validResponse.toString());
		console.info(responseData);
	});	
	//*/
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test getting pad from local database to decrypt message
	 * ------------------------------------------------------------------
	 */
	
	// Use test user so not accidentally overwriting real pads
	var fromUser = 'test';
	
	// Add some test one-time pads to the local data
	db.padData.pads[fromUser] = [
	{
		"padNum":0,
		"padIdentifier":"162f699c1b5320",
		"pad":"162f699c1b532070262d7cf8c179a390b3e2bb2f790cc7fff4eb6a9ba6217a21031e236f862fc4e33bde00e9e0b0e285406f87195f3d65e46d0f318d07fbf96bf52c26211dad286c401c4dc21a8a946fc139d0b0bd0bb608b044db0c6039435dcf868ee890829c3b210a81eaeecc156df51c2c0d97cbbf4c3ff2ae636a39e6bd560473fe239ce69adc753b148641f660cc8a14aaadf7c381da1c5b41d7f182f0b45c375ba4db7a9269738b4d89b59fb4dac6128c58e8b6272d8ae51a5c6d3e8a"
	},
	{
		"padNum":1,
		"padIdentifier":"713bdf420eb9b6",
		"pad":"713bdf420eb9b604b6f61d4bb5312ddf29d7a184ebb8d8606e3452af9fc17a438b09def6d12cea23f625dc8002b8027f7acebfc3c72bf84f1d6a816cbe13391cbf78e978874b071ce00afc3608ad7e4a76089d157ff8d98a9fa437e01ba2a26f7e93e2fbdd2ef0c847e5a2b5dfb501d962841ea0505d7881580d06217f8575ab75d0606785d25b406d0255aa95e315928aa0859d090f85a6893567fb39b3f94d669e6bc3a2d8b7e141ac206831df2efe3016b396ee593eb110d75aa5136b5411"
	},
	{
		"padNum":2,
		"padIdentifier":"09a04c83a883be",
		"pad":"09a04c83a883be10809f9aa406c56983867cf5fa6781d1fbb5e8c8f6cbeef0d9225df27cccb5c49eca4d13653372058d8075f43fb3e4dc78f439f3902bef4592ab6ce3de1c9fb89922605e743ebb3e1d6809dc2c53ecd922ece21cffe42f9b2ebc4a227fb2225916275d73111ae77db626d73d0b5c218ccb803da30ae1a9d73ec21ff7a5affc843e0a69652faf41fc660014b76e108dc11898adb58ba10075bb552bc3d7cd3785b27abfc18eca97c6f11d7b7a04d6d7fb418e3ebc4060a1725f"
	},
	{
		"padNum":3,
		"padIdentifier":"d6b7fe388ba1fd",
		"pad":"d6b7fe388ba1fdc25d54ecd4c09736fe1d813e8890f88178b4173528f718c62d33a159d5b02d02a845383ee1da689f3793a87a86f29acbc04a70088d5f27ed8b9811cca083ab4e199b647ec64ae0efb790c7206e3748614e843135579466391ca41e7500b185645e4222c6561e36a6fe0445822476f4f7a748242ef9332e9b0f07bcf3ef0fd164bf89c7725eacb54850c8cef2f5759716bf7f1d8dc54bb3b743418767f64ab886be2c246d50101382c06ea79153e856577429f0586474d5d5c3"
	},
	{
		"padNum":4,
		"padIdentifier":"fd13d8b471d22d",
		"pad":"fd13d8b471d22d11a74b905fd453b5aa83cde52d7a5b8eb026204b078da163173ffde3fc1d94de357c5b86c108fb4f06905a04a1164c667ffc60c74e89a4de06b030a4bfb11be30b0d155aa0627346fbc62662517ef240b74d24ce6a789377776a3d60627a67cd8ba1b11aade6c517e8c4d6e7bab456de4bda3a6c744dfc5883ba7ad666e68c5134b9cc99a879a1df16a9810c0d7b67998b284f5c6626071186b657c5f11d9ad9ed11d7997e57da26936b62ed06c782bb6b0d0a802dec52b469"
	},
	{
		"padNum":5,
		"padIdentifier":"48aa7310d74c74",
		"pad":"48aa7310d74c74bf6290c467488be98e53b2999f92aa17f90b47711c6dd73d3a2e5db195c160ab0b51bd49fd71cd5ede556556e4d792763bafd0ef21767790089a860df9916c7b36a6be568e1f17946ee10667b08a913cc6353cb24a82576a0f4c3cedaa89d555913fab54692938b97ee526ed558f58b2da65121b3a11e727b38bdd2513db4fa4d80061e029b404e492080d76ad3635d1db044c45089e6cbdcc7711e98743f035ce0f32aaaa8dc8bd8026ef7de2313281ec18d4443a80201988"
	},
	{
		"padNum":6,
		"padIdentifier":"0bb16c9fb69fd6",
		"pad":"0bb16c9fb69fd619a79cf0bc14ea211f3f5ca103a8227e7147939e3add073d03b98f3ade361d538dd3479b6fc6bbcb8f3abc155e7dc4701a01f8fdfbcf18eb329996883e4fad57a56b824b95d668fa30c6dedcb0507d8594b919f6bb70f4bea7ed35695ac9b93cd96d441a7f4b8c1c68df47bceeb315c5a090f0a30e0bf7e57521350b18b2f79db4c965ba70c114625c70181fbce491caef2cfc87bbe18a9a29de28a3aab424e7b477cb2e697b4b1788bd5b924c4a50c38bf5c68b9ad40baadf"
	},
	{
		"padNum":7,
		"padIdentifier":"88caea32efc1c2",
		"pad":"88caea32efc1c2f678b8b45d94fb95fea7595b6166b60f8d4c779666fb9c91b3b0619f2d5b0a5b1cfd668f5bf93cc49a43277f033d6fd314095942faed509aeeeb5608beaec7debdb6c1586321814e843c29abf39c8373ddbb1b2ed2b7cc16a21e9b976bcaf64a598100af7e4e8becb16d5ef257d244746f60611a9ae156a6d3df3d4067a156d3a92831d83afcf5ce431275292e11e5b48d4e007968ddf05163c8e4d6c0585eab950c865cff5acc53e380857192dd7ae14a9c9aa93f98f23a61"
	}];
	
	// Set test ciphertext as just one of the pads, it should find it based on the padIdentifier
	var indexForFindingA = 0;
	var ciphertextForFindingA = db.padData.pads[fromUser][indexForFindingA].pad;
	var padIdentifierForFindingA = db.padData.pads[fromUser][indexForFindingA].padIdentifier;
	var foundPadDataA = common.getPadToDecryptMessage(ciphertextForFindingA, fromUser);
	
	var indexForFindingB = 1;
	var ciphertextForFindingB = db.padData.pads[fromUser][indexForFindingB].pad;
	var padIdentifierForFindingB = db.padData.pads[fromUser][indexForFindingB].padIdentifier;
	var foundPadDataB = common.getPadToDecryptMessage(ciphertextForFindingB, fromUser);
	
	var indexForFindingC = 2;
	var ciphertextForFindingC = db.padData.pads[fromUser][indexForFindingC].pad;
	var padIdentifierForFindingC = db.padData.pads[fromUser][indexForFindingC].padIdentifier;
	var foundPadDataC = common.getPadToDecryptMessage(ciphertextForFindingC, fromUser);
	
	var indexForFindingD = 3;
	var ciphertextForFindingD = db.padData.pads[fromUser][indexForFindingD].pad;
	var padIdentifierForFindingD = db.padData.pads[fromUser][indexForFindingD].padIdentifier;
	var foundPadDataD = common.getPadToDecryptMessage(ciphertextForFindingD, fromUser);
	
	var indexForFindingE = 4;
	var ciphertextForFindingE = db.padData.pads[fromUser][indexForFindingE].pad;
	var padIdentifierForFindingE = db.padData.pads[fromUser][indexForFindingE].padIdentifier;
	var foundPadDataE = common.getPadToDecryptMessage(ciphertextForFindingE, fromUser);
	
	var indexForFindingF = 5;
	var ciphertextForFindingF = db.padData.pads[fromUser][indexForFindingF].pad;
	var padIdentifierForFindingF = db.padData.pads[fromUser][indexForFindingF].padIdentifier;
	var foundPadDataF = common.getPadToDecryptMessage(ciphertextForFindingF, fromUser);
	
	var indexForFindingG = 6;
	var ciphertextForFindingG = db.padData.pads[fromUser][indexForFindingG].pad;
	var padIdentifierForFindingG = db.padData.pads[fromUser][indexForFindingG].padIdentifier;
	var foundPadDataG = common.getPadToDecryptMessage(ciphertextForFindingG, fromUser);
	
	// Test non existent pad id
	var foundPadDataH = common.getPadToDecryptMessage('16675d892a184a931f526343ba622c13817f6612e5bda52531a160e5f9cbaecfef2d48b976afde24b9876aa1fd372b744cbf80a80ea672f0ed63138c4beff4666760f0a749b19c3641a082b802574015680a6b2f4fe694d05b887f5dec86a6bab5bf143b9ce108fa84554d99ba9014d954a8961f965661329e6594d2a920a680a483653aaf0c92a06460970587b2c5ecc7a8062c58d28e9564fea4415d3d835a1e803b8eac222b5c1bd7f4d16f5fd1f1d3bfb10142f02ecce1c0f561d9ad6df9', fromUser);
	
	test("Test getting pad from local database to decrypt message", function()
	{
		ok(foundPadDataA.padIndex === indexForFindingA, foundPadDataA.padIndex);
		ok(foundPadDataA.padIdentifier === padIdentifierForFindingA, foundPadDataA.padIdentifier);
		ok(foundPadDataA.pad === ciphertextForFindingA, foundPadDataA.pad);
		
		ok(foundPadDataB.padIndex === indexForFindingB, foundPadDataB.padIndex);
		ok(foundPadDataB.padIdentifier === padIdentifierForFindingB, foundPadDataB.padIdentifier);
		ok(foundPadDataB.pad === ciphertextForFindingB, foundPadDataB.pad);
		
		ok(foundPadDataC.padIndex === indexForFindingC, foundPadDataC.padIndex);
		ok(foundPadDataC.padIdentifier === padIdentifierForFindingC, foundPadDataC.padIdentifier);
		ok(foundPadDataC.pad === ciphertextForFindingC, foundPadDataC.pad);
		
		ok(foundPadDataD.padIndex === indexForFindingD, foundPadDataD.padIndex);
		ok(foundPadDataD.padIdentifier === padIdentifierForFindingD, foundPadDataD.padIdentifier);
		ok(foundPadDataD.pad === ciphertextForFindingD, foundPadDataD.pad);
		
		ok(foundPadDataE.padIndex === indexForFindingE, foundPadDataE.padIndex);
		ok(foundPadDataE.padIdentifier === padIdentifierForFindingE, foundPadDataE.padIdentifier);
		ok(foundPadDataE.pad === ciphertextForFindingE, foundPadDataE.pad);
		
		ok(foundPadDataF.padIndex === indexForFindingF, foundPadDataF.padIndex);
		ok(foundPadDataF.padIdentifier === padIdentifierForFindingF, foundPadDataF.padIdentifier);
		ok(foundPadDataF.pad === ciphertextForFindingF, foundPadDataF.pad);
		
		ok(foundPadDataG.padIndex === indexForFindingG, foundPadDataG.padIndex);
		ok(foundPadDataG.padIdentifier === padIdentifierForFindingG, foundPadDataG.padIdentifier);
		ok(foundPadDataG.pad === ciphertextForFindingG, foundPadDataG.pad);
		
		// Test non existent pad id
		ok(foundPadDataH.padIndex === null, foundPadDataH.padIndex);
		ok(foundPadDataH.padIdentifier === '16675d892a184a', foundPadDataH.padIdentifier);
		ok(foundPadDataH.pad === null, foundPadDataH.pad);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test deleting received and verified messages
	 * ------------------------------------------------------------------
	 */
	
	// Remove even numbered pads
	var padIndexesToErase = [];
	padIndexesToErase.push({ 'index': 2, 'user': fromUser });
	padIndexesToErase.push({ 'index': 0, 'user': fromUser });	
	padIndexesToErase.push({ 'index': 4, 'user': fromUser });
	padIndexesToErase.push({ 'index': 6, 'user': fromUser });
	
	// Delete them
	chat.deleteVerifiedMessagePads(padIndexesToErase);
	
	test("Test deleting received and verified messages", function()
	{
		ok(db.padData.pads[fromUser].length === 4, 'Length = ' + db.padData.pads[fromUser].length);
		ok(db.padData.pads[fromUser][0].padIdentifier === '713bdf420eb9b6', db.padData.pads[fromUser][0].padNum);
		ok(db.padData.pads[fromUser][1].padIdentifier === 'd6b7fe388ba1fd', db.padData.pads[fromUser][1].padNum);
		ok(db.padData.pads[fromUser][2].padIdentifier === '48aa7310d74c74', db.padData.pads[fromUser][2].padNum);
		ok(db.padData.pads[fromUser][3].padIdentifier === '88caea32efc1c2', db.padData.pads[fromUser][3].padNum);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Sort decrypted messages by earliest sent timestamp
	 * ------------------------------------------------------------------
	 */
	
	var decryptedMessagesTest = [];
	decryptedMessagesTest.push({
		'padIdentifier': '162f699c1b5320',
		'fromUser': 'bravo',					
		'plaintext': 'Third',
		'timestamp': common.getCurrentUtcTimestamp(),
		'valid': true
	});
	decryptedMessagesTest.push({
		'padIdentifier': '713bdf420eb9b6',
		'fromUser': 'charlie',					
		'plaintext': 'Second',
		'timestamp': common.getCurrentUtcTimestamp() - 3,
		'valid': true
	});
	decryptedMessagesTest.push({
		'padIdentifier': '09a04c83a883be',
		'fromUser': 'delta',					
		'plaintext': 'First',
		'timestamp': common.getCurrentUtcTimestamp() - 7,
		'valid': true
	});
	decryptedMessagesTest.push({
		'padIdentifier': 'd6b7fe388ba1fd',
		'fromUser': 'delta',					
		'plaintext': 'Fifth',
		'timestamp': common.getCurrentUtcTimestamp() + 7,
		'valid': true
	});
	decryptedMessagesTest.push({
		'padIdentifier': 'fd13d8b471d22d',
		'fromUser': 'delta',					
		'plaintext': 'Fourth',
		'timestamp': common.getCurrentUtcTimestamp() + 3,
		'valid': true
	});
	var decryptedMessagesTest = chat.sortDecryptedMessagesByTimestamp(decryptedMessagesTest);
	
	test("Sort decrypted messages by earliest sent timestamp", function()
	{
		ok(decryptedMessagesTest[0].plaintext === 'First', decryptedMessagesTest[0].timestamp);
		ok(decryptedMessagesTest[1].plaintext === 'Second', decryptedMessagesTest[1].timestamp);
		ok(decryptedMessagesTest[2].plaintext === 'Third', decryptedMessagesTest[2].timestamp);
		ok(decryptedMessagesTest[3].plaintext === 'Fourth', decryptedMessagesTest[3].timestamp);
		ok(decryptedMessagesTest[4].plaintext === 'Fifth', decryptedMessagesTest[4].timestamp);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test removal of pad identifier and returning the remaining pad
	 * ------------------------------------------------------------------
	 */
	
	var padWithoutPadId = common.getPadWithoutPadIdentifier(pad);
	var padWithoutPadIdLength = padWithoutPadId.length;
	
	test("Test removal of pad identifier and returning the remaining pad", function()
	{
		ok(padWithoutPadIdLength === common.totalMessagePartsSizeHex + common.macSizeHex, 'Length = ' + padWithoutPadIdLength);
		ok(padWithoutPadId === '2c056a62e32c5dbb916db2cba99efbc2c49533c5349bdeaeb4ec307e588b0cb125b4c23f07ccbac5d30b7736903cfb37a72ca6c189185546d401b48210cf46468a5615f2b63eaa7c415592a5bdad98bf47b3f49058ae278d7194567240a66f11755ead65cd194a36f30f7cf98d6c60fd45eca00a845922fc5d411f70a8b3d9c0dfaf69df60c42f6aec429ef479f3caa312ded2944546b93b49e09a53e679c999c99900a6bd93f93d2c2fcd387cb28625ab6c6bbd24baf9251c', padWithoutPadId);
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Test AES-CTR 256 bit encryption against published test vectors
	 * ------------------------------------------------------------------
	 */	
	
	// Test vectors from NIST Special Publication 800-38A, 2001 edition, F.5.5 CTR-AES256.Encrypt
	var aesCtrKey = CryptoJS.enc.Hex.parse('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
	var aesCtrNonce = CryptoJS.enc.Hex.parse('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
	var aesCtrPlaintext = [
		'6bc1bee22e409f96e93d7e117393172a',		// Block 1
		'ae2d8a571e03ac9c9eb76fac45af8e51',		// Block 2
		'30c81c46a35ce411e5fbc1191a0a52ef',		// Block 3
		'f69f2445df4f9b17ad2b417be66c3710'		// Block 4
	];
	aesCtrPlaintext = aesCtrPlaintext.join('');
	var plaintextWordArray = CryptoJS.enc.Hex.parse(aesCtrPlaintext);
	
	var aesCtrEncryption = CryptoJS.AES.encrypt(plaintextWordArray, aesCtrKey, { iv: aesCtrNonce, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
	var aesCtrCiphertext = aesCtrEncryption.ciphertext.toString(CryptoJS.enc.Hex);
	var aesCtrCiphertextLength = aesCtrCiphertext.length;
	var aesCtrExpectedCiphertextLength = aesCtrPlaintext.length;	// 128 bits
	var aesCtrExpectedCiphertext = [
		'601ec313775789a5b7a7f504bbf3d228',
		'f443e3ca4d62b59aca84e990cacaf5c5',
		'2b0930daa23de94ce87017ba2d84988d',
		'dfc9c58db67aada613c2dd08457941a6'
	];
	aesCtrExpectedCiphertext = aesCtrExpectedCiphertext.join('');
	
	test("Test AES-CTR 256 bit encryption against published test vectors", function()
	{
		ok(aesCtrCiphertextLength === aesCtrExpectedCiphertextLength, 'Length ' + aesCtrCiphertextLength + ' should equal ' + aesCtrExpectedCiphertextLength);
		ok(aesCtrCiphertext === aesCtrExpectedCiphertext, 'Ciphertext ' + aesCtrCiphertext + ' should equal ' + aesCtrExpectedCiphertext);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test AES-CTR keystream generation
	 * ------------------------------------------------------------------
	 */	
	
	var aesKey = '33ba6d09f4524080487a94e083a39e0db7c446fafacf5109ed9dd33783a43b8c';
	var aesNonce = 'e6837ad86561a5c31304212c';
	var aesKeystreamLength = common.totalPadSize - common.padIdentifierSize;	// 192 bytes - 7 bytes
	var aesKeystream = dbCrypto.generateAesKeystream(aesKey, aesNonce, aesKeystreamLength);
	var aesKeystreamGeneratedLength = aesKeystream.length;
	var aesKeystreamLengthExpected = aesKeystreamLength * 2;	// Multiply by 2 to get the hex length = 370 hex symbols
		
	test("Test AES-CTR keystream generation", function()
	{
		ok(aesKeystreamGeneratedLength === aesKeystreamLengthExpected, 'Length ' + aesKeystreamGeneratedLength + ' should equal ' + aesKeystreamLengthExpected + ' - keystream hex: ' + aesKeystream);
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Test Salsa20 256 bit keystream generation
	 * ------------------------------------------------------------------
	 */	
	
	var salsaKey = '3637fda8046fa340dcc5d1510ed772efe4879165326b0666fd1df408b44ff63e';
	var salsaNonce = 100;
	var salsaKeystreamLength = common.totalPadSize - common.padIdentifierSize;	// 192 bytes - 7 bytes = 185 bytes
	var salsaKeystream = dbCrypto.generateSalsaKeystream(salsaKey, salsaNonce, salsaKeystreamLength);
	var salsaKeystreamGeneratedLength = salsaKeystream.length;
	var salsaExpectedKeystreamLength = salsaKeystreamLength * 2;	// Multiply by 2 to get the hex length = 370 hex symbols
	
	test("Test Salsa20 256 bit keystream generation", function()
	{
		ok(salsaKeystreamGeneratedLength === salsaExpectedKeystreamLength, 'Length ' + salsaKeystreamGeneratedLength + ' should equal ' + salsaExpectedKeystreamLength + ' - keystream hex: ' + salsaKeystream);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test database cascade stream cipher encryption
	 * ------------------------------------------------------------------
	 */	
	
	var aesCascadeKey = 'af619105b4c379e8030a9f249bf42199a46565ed19821d804c149a3626011e76';
	var salsaCascadeKey = '71798aa7fd661eeaeace4929d30c50a18d3d1b1840d07daa6d0335d0216e5489';
	var aesCascadeNonce = 'ff977a97094eb18f12e53692';
	var salsaCascadeNonce = 0;
	var data = common.convertTextToBinary(plaintextMessage);
	    data = common.convertBinaryToHexadecimal(data);
	
	var cascadeCiphertext = dbCrypto.cascadeEncrypt(aesCascadeKey, salsaCascadeKey, aesCascadeNonce, salsaCascadeNonce, data);
	var cascadeCiphertextLength = cascadeCiphertext.length;
	var expectedLength = plaintextMessage.length * 2;	// Multiply by 2 to get the hex length = 370 hex symbols
	var ciphertextAscii = common.convertHexadecimalToBinary(cascadeCiphertext);
	    ciphertextAscii = common.convertBinaryToText(ciphertextAscii);
	
	test("Test database cascade stream cipher encryption", function()
	{
		ok(cascadeCiphertextLength === expectedLength, 'Ciphertext length ' + cascadeCiphertextLength + ' should equal ' + expectedLength + '. Plaintext "' + plaintextMessage + '" encrypted under AES-CTR key "' + aesCascadeKey + '" and Salsa20 key "' + salsaCascadeKey + '" results in ciphertext "' + cascadeCiphertext + '" or "' + ciphertextAscii + '" in ASCII encoding.');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test database cascade MAC using Skein and Keccak
	 * ------------------------------------------------------------------
	 */	
	
	var keccakMacKey = '23976b12678cb35c187e6f7122bcd8a2ea8415021565a0186617bc455ee3c2f4d25af7e238e7a93b11f660d152cc6ce2f191e4aaa68d0dc73e40b8986eac9200';
	var skeinMacKey = 'e627fb01d11d71b10dbcf1fe50300da87e022acdd3dc8166a369d04fa894fad6590bec64233f460d0e2b477a590baec966578f8bdab37ef21af0b97243d6827d';
	var cascadeMac = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, cascadeCiphertext);
	var cascadeMacLength = cascadeMac.length;
	var expectedCascadeMacLength = 128;			// 128 hex symbols = 512 bits
	
	test("Test database cascade MAC using Skein and Keccak", function()
	{
		ok(cascadeMacLength === expectedCascadeMacLength, 'Digest length ' + cascadeMacLength + ' should equal ' + expectedCascadeMacLength + '. Ciphertext "' + cascadeCiphertext + '" MACed under Keccak-512 key "' + keccakMacKey + '" and Skein-512 key "' + skeinMacKey + '" results in the cascade MAC digest "' + cascadeMac + '".');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test database row level cascade encrypt and MAC
	 * ------------------------------------------------------------------
	 */	
	
	var dbEncAesKey = '0abe3c109e5baafd9fd8eef26ff4dc420971b530dbce5dd054baf5055728fa09';
	var dbEncSalsaKey = '93d00583375358157d6c25c01ad123afe1a69a5274e5ccd1378bf06876437a3f';
	var dbEncKeccakKey = '30d5ec01e43e0884eb843201b47bcf585c397ec20450ee50820f1ca56945c16c9991eaa08b13a0e2475b5dc709b7b892e84450882c40f70df05ccbd6c283aadd';
	var dbEncSkeinKey = '054f4f55a5a6ece495de2789cde143987476d7b6ec7b8564f09df7b730ce5daa456177d50211f1f9c29358c92297aa213361ad9145cd6acfbfc656df8a11f1c0';
	var dbEncUserCallSign = 'alpha';
	var dbEncPadNumber = 137;
	var dbEncPadHex = '72fa270d9148a82c056a62e32c5dbb916db2cba99efbc2c49533c5349bdeaeb4ec307e588b0cb125b4c23f07ccbac5d30b7736903cfb37a72ca6c189185546d401b48210cf46468a5615f2b63eaa7c415592a5bdad98bf47b3f49058ae278d7194567240a66f11755ead65cd194a36f30f7cf98d6c60fd45eca00a845922fc5d411f70a8b3d9c0dfaf69df60c42f6aec429ef479f3caa312ded2944546b93b49e09a53e679c999c99900a6bd93f93d2c2fcd387cb28625ab6c6bbd24baf9251c'; // Generated from TRNG
	var dbEncResult = dbCrypto.cascadeEncryptAndMac(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbEncPadNumber, dbEncPadHex);
	
	var dbEncExpectedCiphertextLength = common.totalPadSizeHex - common.padIdentifierSizeHex;
	var dbEncExpectedCiphertext = '8e4b2d3ab40b353e6bb2a3fca6184276d1ff77f4c37c9dde83cf44928311eabfedc72ff6b0a0a72a463aca6d1693889071e7c098584689e0838c23b7b2532bf2a809125482dd9b393b6bb40fbb9d93d76c5a1b994bf4bcc0a62ec87faf799c18e6bf391c7a3a5a6c7f10e96df40319ffc114a493345f9998600f8571049d45aa0bc58d4a1e73f7c690d70efaee2849762121efb7426d18c605a982e0e26e006c2bb41e7a85ed7727e6640459863c7b0bb0d73caf0c629cba6f';
	var dbEncExpectedMacLength = 128; // 512 bits
	var dbEncExpectedMac = '967f88214d30e914ed25e225579dcb4a8d8502b80f9e84eb764c42d1ff92cf05d59855452e9b3bd36fa750bd180252b353aeaac5d9b86a038663b05e3525ee1d';
		
	test("Test database row level cascade encrypt and MAC", function()
	{
		ok(dbEncResult.ciphertextHex.length === dbEncExpectedCiphertextLength, 'Encrypted pad length ' + dbEncResult.ciphertextHex.length + ' should equal ' + dbEncExpectedCiphertextLength);
		ok(dbEncResult.ciphertextHex === dbEncExpectedCiphertext, 'Encrypted pad ' + dbEncResult.ciphertextHex + ' should equal ' + dbEncExpectedCiphertext);
		
		ok(dbEncResult.macHex.length === dbEncExpectedMacLength, 'MAC length ' + dbEncResult.macHex.length + ' should equal ' + dbEncExpectedMacLength);
		ok(dbEncResult.macHex === dbEncExpectedMac, 'MAC ' + dbEncResult.macHex + ' should equal ' + dbEncExpectedMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test database row level cascade verify MAC and decrypt
	 * ------------------------------------------------------------------
	 */	
	
	var dbDecPadId = common.getPadIdentifierFromCiphertext(dbEncPadHex);
	var dbDecPadCiphertext = dbEncResult.ciphertextHex;
	var dbDecMac = dbEncResult.macHex;
	var dbDecPad = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbEncPadNumber, dbDecPadId, dbDecPadCiphertext, dbDecMac);
	var dbDecExpectedDecryptedPad = common.getPadWithoutPadIdentifier(dbEncPadHex);
		
	var dbDecTamperedCallSign = 'bravo';
	var dbDecTamperedCallSignResult = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbDecTamperedCallSign, dbEncPadNumber, dbDecPadId, dbDecPadCiphertext, dbDecMac);
	var dbDecTamperedCallSignExpectedResult = false;
	
	var dbDecTamperedPadNum = 138;
	var dbDecTamperedPadNumResult = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbDecTamperedPadNum, dbDecPadId, dbDecPadCiphertext, dbDecMac);
	var dbDecTamperedPadNumExpectedResult = false;
	
	var dbDecTamperedPadId = '82fa270d9148a8';
	var dbDecTamperedPadIdResult = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbEncPadNumber, dbDecTamperedPadId, dbDecPadCiphertext, dbDecMac);
	var dbDecTamperedPadIdExpectedResult = false;
	
	var dbDecTamperedPadCiphertext = 'aa4b2d3ab40b353e6bb2a3fca6184276d1ff77f4c37c9dde83cf44928311eabfedc72ff6b0a0a72a463aca6d1693889071e7c098584689e0838c23b7b2532bf2a809125482dd9b393b6bb40fbb9d93d76c5a1b994bf4bcc0a62ec87faf799c18e6bf391c7a3a5a6c7f10e96df40319ffc114a493345f9998600f8571049d45aa0bc58d4a1e73f7c690d70efaee2849762121efb7426d18c605a982e0e26e006c2bb41e7a85ed7727e6640459863c7b0bb0d73caf0c629cba6f';
	var dbDecTamperedPadCiphertextResult = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbEncPadNumber, dbDecPadId, dbDecTamperedPadCiphertext, dbDecMac);
	var dbDecTamperedPadCiphertextExpectedResult = false;
	
	var dbDecTamperedMac = '067f88214d30e914ed25e225579dcb4a8d8502b80f9e84eb764c42d1ff92cf05d59855452e9b3bd36fa750bd180252b353aeaac5d9b86a038663b05e3525ee1d';
	var dbDecTamperedMacResult = dbCrypto.cascadeVerifyMacAndDecrypt(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncUserCallSign, dbEncPadNumber, dbDecPadId, dbDecPadCiphertext, dbDecTamperedMac);
	var dbDecTamperedMacExpectedResult = false;
		
	test("Test database row level cascade verify MAC and decrypt", function()
	{
		ok(dbDecPad === dbDecExpectedDecryptedPad, 'Decrypted pad ' + dbDecPad + ' should equal ' + dbDecExpectedDecryptedPad);
		
		ok(dbDecTamperedCallSignResult === dbDecTamperedCallSignExpectedResult, 'Tampered call sign ' + dbDecTamperedCallSignResult + ' should equal false');
		ok(dbDecTamperedPadNumResult === dbDecTamperedPadNumExpectedResult, 'Tampered pad number ' + dbDecTamperedPadNumResult + ' should equal false');
		ok(dbDecTamperedPadIdResult === dbDecTamperedPadIdExpectedResult, 'Tampered pad id ' + dbDecTamperedPadIdResult + ' should equal false');		
		ok(dbDecTamperedPadCiphertextResult === dbDecTamperedPadCiphertextExpectedResult, 'Tampered pad ' + dbDecTamperedPadCiphertextResult + ' should equal false');
		ok(dbDecTamperedMacResult === dbDecTamperedMacExpectedResult, 'Tampered pad ' + dbDecTamperedMacResult + ' should equal false');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test PBKDF2-SHA1 against test vectors from RFC 6070 to prove PBKDF2 with CryptoJS works
	 * Add <script src="js/lib/cryptojs-sha1.js"></script> to run in tests.html
	 * ------------------------------------------------------------------
	 */
	
	/*
	// P = "password" (8 octets), S = "salt" (4 octets), c = 1, dkLen = 20
	var passphrase = 'password';
	var salt = CryptoJS.enc.Latin1.parse('salt');
	var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 160/32, hasher: CryptoJS.algo.SHA1, iterations: 1 });
	var keyHexA = key.toString(CryptoJS.enc.Hex);
	var expectedKeyHexA = '0c60c80f961f0e71f3a9b524af6012062fe037a6';
	
	// P = "password" (8 octets), S = "salt" (4 octets), c = 2, dkLen = 20
	var passphrase = 'password';
	var salt = CryptoJS.enc.Latin1.parse('salt');
	var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 160/32, hasher: CryptoJS.algo.SHA1, iterations: 2 });
	var keyHexB = key.toString(CryptoJS.enc.Hex);
	var expectedKeyHexB = 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957';
	
	// P = "password" (8 octets), S = "salt" (4 octets), c = 4096, dkLen = 20
	var passphrase = 'password';
	var salt = CryptoJS.enc.Latin1.parse('salt');
	var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 160/32, hasher: CryptoJS.algo.SHA1, iterations: 4096 });
	var keyHexC = key.toString(CryptoJS.enc.Hex);
	var expectedKeyHexC = '4b007901b765489abead49d926f721d065a429c1';
	
	// Long running test:
	// P = "password" (8 octets), S = "salt" (4 octets), c = 16777216, dkLen = 20
	// var passphrase = 'password';
	// var salt = CryptoJS.enc.Latin1.parse('salt');
	// var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 160/32, hasher: CryptoJS.algo.SHA1, iterations: 16777216 });
	// var keyHexD = key.toString(CryptoJS.enc.Hex);
	// var expectedKeyHexD = 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984';
	
	// P = "passwordPASSWORDpassword" (24 octets), S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets), c = 4096, dkLen = 25
	var passphrase = 'passwordPASSWORDpassword';
	var salt = CryptoJS.enc.Latin1.parse('saltSALTsaltSALTsaltSALTsaltSALTsalt');
	var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 200/32, hasher: CryptoJS.algo.SHA1, iterations: 4096 });
	var keyHexE = key.toString(CryptoJS.enc.Hex);
	var expectedKeyHexE = '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038';
	
	// P = "pass\0word" (9 octets), S = "sa\0lt" (5 octets), c = 4096, dkLen = 16
	var passphrase = 'pass\0word';
	var salt = CryptoJS.enc.Latin1.parse('sa\0lt');
	var key = CryptoJS.PBKDF2(passphrase, salt, { keySize: 128/32, hasher: CryptoJS.algo.SHA1, iterations: 4096 });
	var keyHexF = key.toString(CryptoJS.enc.Hex);
	var expectedKeyHexF = '56fa6aa75548099dcc37d7f03425e0c3';
	
	test("Test PBKDF-SHA1 against test vectors from RFC 6070 to prove CryptoJS library works", function()
	{
		ok(keyHexA === expectedKeyHexA, keyHexA + ' should equal ' + expectedKeyHexA);
		ok(keyHexB === expectedKeyHexB, keyHexB + ' should equal ' + expectedKeyHexB);
		ok(keyHexC === expectedKeyHexC, keyHexC + ' should equal ' + expectedKeyHexC);
		// ok(keyHexD === expectedKeyHexD, keyHexD + ' should equal ' + expectedKeyHexD);
		ok(keyHexE === expectedKeyHexE, keyHexE + ' should equal ' + expectedKeyHexE);
		ok(keyHexF === expectedKeyHexF, keyHexF + ' should equal ' + expectedKeyHexF);
	});
	*/
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test Keccak PBKDF with 100 iterations
	 * ------------------------------------------------------------------
	 */	
	
	var keccakStartTime = new Date();
	var keccakPassword = 'password';
	var keccakPasswordBytes = Salsa20.core.util.utf8StringToBytes(keccakPassword);
	var keccakPasswordHex = Salsa20.core.util.bytesToHex(keccakPasswordBytes);
	var keccakSalt = '598627c78963db1ccfd0f9807630fcd8231b9233d7b621233a6ce798d8cc536766a701d9b4e5ac9d30f835de094e79cb61688fe2a5ff5dda0fe14a716836f6b7b4004eeb5c01d4b64abf251066f067a6263f7f68560ad1d156aa64f88fe6b411';
	var keccakIterations = 100;
	var keccakDerivedKey = dbCrypto.keccakPasswordDerivation(keccakPasswordHex, keccakSalt, keccakIterations);
	var keccakDerivedKeyLength = keccakDerivedKey.length;
	var keccakEndTime = new Date();
	var keccakMillisecondsTaken = keccakEndTime - keccakStartTime;
	var keccakExpectedDerivedKey = '7a36996a34510d7702c21d3249854d300da872ba6c01b1ea4f495d772f650610e33ad36f00b1b489784d5760410ad3429801839dfbdc5ffb1c428529d4cde6aa';
	var kecccakExpectedDerivedKeyLength = 512 / 4;		// Hash output length in hex symbols
	
	test("Test Keccak PBKDF with 100 iterations", function()
	{
		ok(keccakDerivedKeyLength === kecccakExpectedDerivedKeyLength, 'Digest length ' + keccakDerivedKeyLength + ' should equal ' + kecccakExpectedDerivedKeyLength);
		ok(keccakDerivedKey === keccakExpectedDerivedKey, 'Derived key ' + keccakDerivedKey + ' should equal ' + keccakExpectedDerivedKey + '. Time taken: ' + keccakMillisecondsTaken + 'ms.');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test Skein PBKDF with 100 iterations
	 * ------------------------------------------------------------------
	 */	
	
	var skeinStartTime = new Date();
	var skeinPassword = 'password';
	var skeinPasswordHex = common.convertBinaryToHexadecimal(common.convertTextToBinary(skeinPassword));
	var skeinSalt = '598627c78963db1ccfd0f9807630fcd8231b9233d7b621233a6ce798d8cc536766a701d9b4e5ac9d30f835de094e79cb61688fe2a5ff5dda0fe14a716836f6b7b4004eeb5c01d4b64abf251066f067a6263f7f68560ad1d156aa64f88fe6b411';
	var skeinIterations = 100;
	var skeinDerivedKey = dbCrypto.skeinPasswordDerivation(skeinPasswordHex, skeinSalt, skeinIterations);
	var skeinDerivedKeyLength = skeinDerivedKey.length;
	var skeinEndTime = new Date();
	var skeinMillisecondsTaken = skeinEndTime - skeinStartTime;
	var skeinExpectedDerivedKey = '0f9ebdfc83bfe6e23b3567920be87232216d5bdbf224af9265e285601dde08975d4ef11ee77551114f676e398f91f71726e453552caffce34c6fd9fdcd6cff9e';
	var skeinExpectedDerivedKeyLength = 512 / 4;		// Hash output length in hex symbols
	
	test("Test Skein PBKDF with 100 iterations", function()
	{
		ok(skeinDerivedKeyLength === skeinExpectedDerivedKeyLength, 'Digest length ' + skeinDerivedKeyLength + ' should equal ' + skeinExpectedDerivedKeyLength);
		ok(skeinDerivedKey === skeinExpectedDerivedKey, 'Derived key ' + skeinDerivedKey + ' should equal ' + skeinExpectedDerivedKey + '. Time taken: ' + skeinMillisecondsTaken + 'ms.');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test Cascade PBKDF with PBKDF2-Keccak and Skein PBKDF with 100 iterations each
	 * ------------------------------------------------------------------
	 */	
	
	// Use a 1536 bit salt (256 bit AES key + 256 bit Salsa20 key + 512 bit Keccak key + 512 bit Skein key)
	var cascadePassword = 'password';
	var cascadeSaltHex = '3da69b5ba280cafd1a8053f595881991eef40fe1adcfa4485849b8fc26f412d85fa2257bacd4831537caa5daf3a23b7d69cc6141f4426524631e8248e74f0a33b104c1f1ae5394ffdf0c1b9562ad27fce03925cd892fdde763b7433aede8cbe4dcb55c42f2d53e58942e6293b1cfb4e5c57b629cfa098b292b5e760a0ba18226f776cb0cb867b4acf8e63934c728bb121efcea31250ba70cc082e9ed645e3879a1dd62d9bb7ebf62eb627dc8d8d0ce8bc19c62337099853a6c0360d9595b724f';
	var cascadeKeccakNumOfIterations = 100;
	var cascadeSkeinNumOfIterations = 100;
	
	var cascadeStartTime = new Date();
	var cascadeDerivedKey = dbCrypto.cascadePasswordDerivation(cascadePassword, cascadeSaltHex, cascadeKeccakNumOfIterations, cascadeSkeinNumOfIterations);
	var cascadeEndTime = new Date();
	var cascadeMillisecondsTaken = cascadeEndTime - cascadeStartTime;
	
	var cascadeDerivedKeyLength = cascadeDerivedKey.length;
	var cascadeExpectedDerivedKey = 'bbdaa9bea38a62d0ac5f9ecd612a187ea6def2021a61d92f861875df7687bf9d1a034f751dbe7731f83e057765d3bee6fbeb9e546d6f525ca23df8de219d79f0';
		
	test("Test Cascade PBKDF with PBKDF2-Keccak and Skein PBKDF with 100 iterations each", function()
	{
		ok(cascadeDerivedKeyLength === 128, 'Derived key length ' + cascadeDerivedKeyLength + ' should equal 128');
		ok(cascadeDerivedKey === cascadeExpectedDerivedKey, 'Derived key ' + cascadeDerivedKey + ' should equal ' + cascadeExpectedDerivedKey + '. Time taken: ' + cascadeMillisecondsTaken + 'ms.');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Derive keys from master key
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Derive keys from master key", function()
	{
		var masterKey = '68ff9faddbf1e1d97f18d3eb6fdeb660f796d1aaca4385c35735097415cba8950e8ad1424a3b65248e017a651ef75b7651393c996a0b943f21697e51060e171c';
		var derivedKeys = dbCrypto.deriveKeysFromMasterKey(masterKey);
		var expectedDerivedAesKey = '1c28a9f6efb7b613d6566ce153bfe017b8d2e8d5772fb7fc865a3449715fca13';
		var expectedDerivedSalsaKey = '34d73fabb9618e60fe66f6d34dc16dec17230c5615ee2a91af4eb24678cd0753';
		var expectedDerivedKeccakKey = '79e9729102c04ea8b94663f813b436b9cb051060b3be1ccbe93a3d602cc3ec2e6efe0a038eb841a7fb966c060eb270f6d25667836f764416ca9e72d950ba0acd';
		var expectedDerivedSkeinKey = 'b074f6a12b090c9773acdc82e413d6454463411724d875ea5f898ba5155e8574538810ffcff380d13f099582d8ace715aee1bcac93dd7325b097aca0f281e3d2';
		
		ok(derivedKeys.aesKey.length === 64, 'Derived AES-CTR key length ' + derivedKeys.aesKey.length + ' should equal 64 (256 bits)');
		ok(derivedKeys.salsaKey.length === 64, 'Derived Salsa20 key length ' + derivedKeys.salsaKey.length + ' should equal 64 (256 bits)');
		ok(derivedKeys.keccakMacKey.length === 128, 'Derived Keccak key length ' + derivedKeys.keccakMacKey.length + ' should equal 128 (512 bits)');
		ok(derivedKeys.skeinMacKey.length === 128, 'Derived Skein key length ' + derivedKeys.skeinMacKey.length + ' should equal 128 (512 bits)');
		
		ok(derivedKeys.aesKey === expectedDerivedAesKey, 'Derived AES-CTR key ' + derivedKeys.aesKey + ' should equal ' + expectedDerivedAesKey);
		ok(derivedKeys.salsaKey === expectedDerivedSalsaKey, 'Derived Salsa20 key length ' + derivedKeys.salsaKey + ' should equal ' + expectedDerivedSalsaKey);
		ok(derivedKeys.keccakMacKey === expectedDerivedKeccakKey, 'Derived Keccak key length ' + derivedKeys.keccakMacKey + ' should equal ' + expectedDerivedKeccakKey);
		ok(derivedKeys.skeinMacKey === expectedDerivedSkeinKey, 'Derived Skein key length ' + derivedKeys.skeinMacKey + ' should equal ' + expectedDerivedSkeinKey);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Encrypt and MAC the database keys with the derived keys
	 * ------------------------------------------------------------------
	 */
	
	var dbEncAesKey = '0abe3c109e5baafd9fd8eef26ff4dc420971b530dbce5dd054baf5055728fa09';
	var dbEncSalsaKey = '93d00583375358157d6c25c01ad123afe1a69a5274e5ccd1378bf06876437a3f';
	var dbEncKeccakKey = '30d5ec01e43e0884eb843201b47bcf585c397ec20450ee50820f1ca56945c16c9991eaa08b13a0e2475b5dc709b7b892e84450882c40f70df05ccbd6c283aadd';
	var dbEncSkeinKey = '054f4f55a5a6ece495de2789cde143987476d7b6ec7b8564f09df7b730ce5daa456177d50211f1f9c29358c92297aa213361ad9145cd6acfbfc656df8a11f1c0';
	var dbEncMasterKey = '68ff9faddbf1e1d97f18d3eb6fdeb660f796d1aaca4385c35735097415cba8950e8ad1424a3b65248e017a651ef75b7651393c996a0b943f21697e51060e171c';
	
	QUnit.test("Encrypt and MAC the database keys with the derived keys", function()
	{
		var encryptedDatabaseKeys = dbCrypto.encryptAndMacDatabaseKeys(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, dbEncMasterKey);
		var encryptedDatabaseKeysLength = encryptedDatabaseKeys.keysHex.length;
		var encryptedDatabaseKeysExpectedLength = (64 + 64 + 128 + 128);
		
		var macLength = encryptedDatabaseKeys.macHex.length;
		var macExpectedLength = 128;
		var expectedEncryptedDatabaseKeys = '9851a2cf4a7cc681a572178464497143dad7c5b9102967910891e961d1a3d85bd1266870e4ae606339459bc7a345928f068e058e9cb4b8959abb65c7ec459aa8129cf970b3debe0a6d95bef93b091f48d4b2b2c6b45dde5d46fc3476e955a7f4daceff57feb7eca5c9b9653fa618642b088e750c32c28eef90cecb374a36caaabf83caed6f4569aef723449b3f3ec01960f69cf5a35926ee75f74de146842744bb7d4db52159456e0cf656a4e5c514fb5e0544ffd60496a05671330805e9da00';
		var expectedMac = '2f94c8badb76ed5905c99536c23d32a00b901bd8c22d78eff612f79327fcdcd5c125b68e6637cb02ab663e714e1177fb160c56e0f8e7d305ad62ee581b863c3f';

		ok(encryptedDatabaseKeysLength === encryptedDatabaseKeysExpectedLength, 'Expected length of encrypted keys ' + encryptedDatabaseKeysLength + ' should equal ' + encryptedDatabaseKeysExpectedLength);
		ok(macLength === macExpectedLength, 'Expected length of MAC ' + macLength + ' should equal ' + macExpectedLength);		
		
		ok(encryptedDatabaseKeys.keysHex === expectedEncryptedDatabaseKeys, 'Expected encrypted keys ' + encryptedDatabaseKeys.keysHex + ' should equal ' + expectedEncryptedDatabaseKeys);
		ok(encryptedDatabaseKeys.macHex === expectedMac, 'Expected MAC ' + encryptedDatabaseKeys.macHex + ' should equal ' + expectedMac);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Decrypt the database keys with the derived keys
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Decrypt the database keys with the derived keys", function(assert)
	{
		// Use details from the encryption test earlier
		var encryptedDatabaseKeys = '9851a2cf4a7cc681a572178464497143dad7c5b9102967910891e961d1a3d85bd1266870e4ae606339459bc7a345928f068e058e9cb4b8959abb65c7ec459aa8129cf970b3debe0a6d95bef93b091f48d4b2b2c6b45dde5d46fc3476e955a7f4daceff57feb7eca5c9b9653fa618642b088e750c32c28eef90cecb374a36caaabf83caed6f4569aef723449b3f3ec01960f69cf5a35926ee75f74de146842744bb7d4db52159456e0cf656a4e5c514fb5e0544ffd60496a05671330805e9da00';
		var derivedAesKey = '1c28a9f6efb7b613d6566ce153bfe017b8d2e8d5772fb7fc865a3449715fca13';
		var derivedSalsaKey = '34d73fabb9618e60fe66f6d34dc16dec17230c5615ee2a91af4eb24678cd0753';
		var expectedDecryptedKeys = {
			dbAesKey: dbEncAesKey,
			dbSalsaKey: dbEncSalsaKey,
		    dbKeccakMacKey: dbEncKeccakKey,
			dbSkeinMacKey: dbEncSkeinKey
		};
		var decryptedDatabaseKeys = dbCrypto.decryptDatabaseKeys(derivedAesKey, derivedSalsaKey, encryptedDatabaseKeys);
		
		assert.deepEqual(decryptedDatabaseKeys, expectedDecryptedKeys, 'The decrypted database keys ' + JSON.stringify(decryptedDatabaseKeys) + ' should be the same as the original database keys ' + JSON.stringify(expectedDecryptedKeys));
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Verify the MAC of the encrypted database keys
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Verify the MAC of the encrypted database keys", function()
	{
		var keccakMacKey = 'a13b9c7625b9f95f9822b9d9b3c018e9b61ce075e7b3f142e09b90184c58866e1a24c3f3f5114b8d08fb51296bc78ce5f455bccb6ba22f3adc5c508a1dec7a5c';
		var skeinMacKey = '4ac11c5a9ae2d3b14fe8c86cee3e87b78fe330248ad8379f574ea8e14fa8b798b1480226759a74063564aaf40faefef073ef82a31915c3b498444d93478b0b4b';
		var encryptedKeys = '22d4dbee390e37b5ae97ec3a1506f850b2021909eb4ec862fda7de591c10b27b29b440d0fd755c53980361e247052f19ba3b30db22863d77a36b75b685e353a923082337e9e1a5599d53412b5cbff07bb52ab6ec664cf4def583d48917d434340fa9bd3535d72d2e7b2821d1006e1e5ab797b3b2dbc28cc608b7e714afc09668bac92b40a3643cbc1b953bd8c365091f7cdc3677fc68f025465b23c2117af3cc30ccf9dafb97cdccee3965d309e06cc1c3cebf8c85a55c6592372838eb169b33';
		var encryptedKeysMac = '3d25ab94e0f2878a56a4f887a5cbb84757b82e207f61cf5aeaaf84be3bd98c0dcfdaef66f832bbc7ba62d7ad5cef86ed4c166f8575616fbb6b5bde4d5800f2ed';

		// Test valid case
		var valid = dbCrypto.verifyMacOfDatabaseKeys(keccakMacKey, skeinMacKey, encryptedKeys, encryptedKeysMac);
		
		// Test invalid case (use Keccak key twice)
		var invalid = dbCrypto.verifyMacOfDatabaseKeys(keccakMacKey, keccakMacKey, encryptedKeys, encryptedKeysMac);
		
		ok(valid === true, 'Expected verification of database keys ' + valid + ' should equal true');
		ok(invalid === false, 'Expected bad verification of database keys ' + valid + ' should equal false');
	});		
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test creation of database keys and failsafe keys using the random data from the TRNG
	 * ------------------------------------------------------------------
	 */
			
	QUnit.test("Test creation of database keys and failsafe keys using the random data from the TRNG", function()
	{
		var randomDataHexadecimalA = 'cabeff2ffd746aca51fca2ca72865786d3d18fda5c42acd7033d3df3900c4b32fb5d36c5f0999d81bea8590c0146bd87032ff5c49a8db673a2bdb89ea1663558861d0d16121a9621be080e54e27a893e455d81a6e285380ab5609d27b7d351599dcada35aac0cbe8fc471e1f9921a4f738d1edab3077f957412e8905c65677a259651681b04b958e04950a1422feef6f585313a97db878845d763d16cea9a3cd8115e8f002cf781d098aa450106259ae57e1c526847d965a62c614f1317ff8d11be37ed18a2fc3835a77ef3c08da45b683592bb912049c3fd04e7f6d889282b90f2a429260b782f4a64c38437aaa7406074a120599a4a8eb9043392b0168136ff0a54c761043e2658a3da88a3cb46fee5dcdeb02c007a05fd1b0e7cdf5dc829112e1ff6459f616e977c6c4597a1209522a40e98d3c213fbcaec61e727e3a5c926b4e7898bbe3d448304bba06628d119083a6ee34a7126ca6f6d6050676146957129646bbf916d6883a6c183786d2ed59486dc9e7bcf8910ff843f41790cb3e4ec26b83acdc9249de952f3ff7310e3401aa6ea92ee86e8e544472e0b30666e64e0152481ce9edc2d379638bc4329aff673017ea1641b3214b3a2865b1637ed210f2a39021f53c60ce24b9f1e0a8f9db806251eac1f30d0efd53c63c16c13a9a3ce27839aa9a922a500f13d10fce4a5ac063b3f3b14e7f7ae755ce2d5fcf80c01d0f0652b6169550d0dc5e7e371f11dcdcfb76aefa21f4d6008f2aeba578bb8d68412234be22a2e3eb3c097643f1bbeadc37e5315d7ae9a71577175201fecfd98e863112ae8216dea03e0e0a8d961f12925b3d12cd54ad6da5b9a85d7acad695510f5e0ea8d888834416b5197233a9207687b33bc167dc5ea782df712e90e848e8567c6295c30225c3107aec5043afcd1336ad2c32d0d1d0c77e2cb85c7f2ac7b9bb6ea050c516ce31373f558e20df2752e6fdcbef4c191f8b4fa7bc526d1b2ed590e740887e79a0b312e4e65a47f6c219f116638d0184a62bff7ef6de0a6ca5f8611828919e587572ee8df2f8803ad8e6738d5f4df95bf945b39ec2bf9c9310c8a9c52d8d576685787f5f7be7ae29b414d1ec7175a22429f0dd8aebdf48e417914660a2309d8b690402e882ecef33e5106ade951daabe485a4990454a05472a33266e5ea80d4b7c11ae6cbe80d45b22cedf49de2029415496b1d61575be60a0b734683715260d49346c2fc4d1fc8a3df8733165c7f21aab989d5aef4aa2a6e9492ac3ba33b8fd1d3f6d99625951dd221e36da966cc90db7d6b003b9834dd925226d0c87d177fb33bfa100bcf1d1f7f4158e2d3b4d29a047685904de36083e9150b43f8407be4f7fec7b53f88be25ce0bfe5318277227fa8bcdcd073c9da09d26540edd21e3a863604eebde6c0b16db88b214e1b38b39d07993892752bbf4624287151a0a9f7e79c47038437aa4e1a47a730cda84eb2e68718fe1c891d57c7a93c954f4c13d74d8a5163e69ce8d4c3d0592fdb31ab9229fa3ea324f9befbc56760df05e2e1a0e7c1fafdc066b77fff1c6279b8729f17122433fd8f7d2f35914433f8dbaacb2d6ec0aedae167cf08494232ee312ff8b7c1d68ef124faf0b950b2cd8c2e62000af314ef5c1fb55b1786a58068d2487719deff41f832ebb8ffa80221a7834a1bae784c3afb8ace63be85620ec3d5d2d6898739708b9565bb8d29a41787732f2bf41fe535433e60eff0636a564388906279691ef3264367ec91a815f672614056a304c16b1a0059e903e1d838f9876a2a5e20f3da976bb8b5e5e5bfce18bc8c4dfa96040e703287db59d2de28e7b5a04807497b6a673988d851616413720b5905b4b3b2442e7260287b980c608bba46763e02f086f4c77fe813746e12bfd1bd82a2cd7a76db1ff2e6364194daaf7c1bb7c3b2cef741808ae2078f3fb2d902281a04e22a78ca36e575da3f7fe80554e4b9a9845a23f33d27b2f39c4d563519ca1cb15beabb5f444115ed006783d6b7ab5619532dd33ba6a1f59ae7eb2e0e553138316bf4540f7418355fe5959cce9db919a1a64c02e8542228e09b8ea88e00f412cfdecf8cc37096c80acc891dab769d074db3aa2a70e789e036a6a2cd5bd1359329cf1c391dd8bd8767f4341e28623c87709fdc320d8dc0f2d02ac95596ae4f9dd598e5558504477bbefca69f71ba9a8eeed138437382ccaa30e8141cb3c6fe688269368d910d70bb1233cfa7773af2797bcfba7118273c02cd9d60fec9c8877c256cb4575d0c982df900b0afc7298976e1f7fd1d114bf5fe898c0f7a2c94815d85efc40128171a05dcc3e44bba2e00eea828b5e708fd73535f73139ab1e31ebdebdb3d3ac6f12f7b789563701b5d8f903a3f2471b1c74cc55c0f5ee9382423f575c4905adad4118fb66cd4c918cf381ba1e6194d5f602f93a1f7f528ff38143fa9e8b2781d76206b49b3561c1b619aeb93e27339eeac478678464ee8120213cf79856e2eb0ca00cf393adea7265eea617b99cf8e9c23d236c7a72e8f8601632d1cd0c7c7c315d022b77e28af4abfb92e4a5a77b6b8ef25947a4dcb92576d68a719bd2613d15bbe23634049c4cfd322ab347f152c107335e1bf8eb92eeefbffff2320273ba276270b012f62be38ce27e44a90658222c682356876ca81ca13b6b60dc1b691ba2ca9a408db01ed568573b7986d7ef4c2e4adf51826830634b7267a05288552d7fa66dbd9ef59f0e66855ac82f294a873f4af0f4bae18580516b3c05407e9f3878c6c5da3d2a952da037f7358e118ec5c879aa51e9b5beb9f2fed1a8930f1f7791546d279fa1d18518f6c45b9ba64f605c766b1f921b2fb359b7b4b8c9c61985d582ea91aea7d7894962ec6f8a34c03d21864c2033e00d998f6194abfa07e22deaf2db57ca6ff30fdbf6c295fade4a7f799e547a644767d8cca0678af443e805546571fdd75900062723305b18c52e4d9ace5994cb37d192d791a7971ba790785bd794a70f5ab7790d4f5e4712b1a1864ad8833b507b062fe302b164cecdd158140fbc0c62e58089d241d7f166f209252e4d4f5826d1016b34a94df0eefc637319f88a6b759afbd12cb3b0d97cfff7286608147cec472d7775a66d90dadf9755a7a31ef15beb2d213614a2e408daa6abd0eb8e5d247d3722c42819a7bff6a1b680e4541d742a048da7a0a3252670bb6789a80812c51116e4676e13747d2654d4432462d7fe4001b73cfa6eac4a8861643c6f93d45317f7e471cb7a05810c1df47b3fa738a4594d6ed9ac8bfbec4a6c79d5a5930c8760d88fdbd415d917e11e35c105fa8f7d8ba81d9bbbe2ebe3b2dbee2bc4177240096866ae62047bea778e6474e371b3fbafc4312acd5454608374698f6eae6e5b2015507d56c374edd75ed6420bcaa3e73348e470b0326edf8e53010fd3d46365699b1780590bca4815af56345c8c79b22b7b5bbef5eb69bea5a3253810f9a17f18b8a62ffe48fac212ca9d1b78962a792a11b78fd3a2f97cd8bb28e38dc78fe5c5aab758e5aa357a0cbcf4c3dd689efbf9d207fb6d637c6729f5152f27b6fa74bdff5442461afa015a00d85def62e51d958be32ecd92f1bc439074324e012b49f554e48fb7b7e4ecad9c300c70d83452ddd97231ae54c7edc5535e5240cf6b6fa53f3d0a0e30d140ed8d71d8c893f6b904872d38690124619d92fb432b173a792d3e455e3f1eecbcd2036d018db5a8ff1e4e51de0e44ae885160113f6bb72a29e3e889a01bc8ff5551db7554bb056e665100de14017cb3d9fe764bcfb86ff0c46184e4fa286c437160f196fd9dfd68e4961eb53ddfdbfbffe80058b70cecc74121017685b080a7e602dc03446ab183f0b7eae3f5f85c061ecd2a98c1780ddc5ae46519f441e924ba740a681cb1ea9b4df6c5ad29b5354d2fa7eeb80fa56be2c0e6fc6c412816e2203ea36719c12da45a167dd31501cc0f77aed2f8f7e20e9b818e9fbc32e002a1b9d39816585366b312894de315382c67f64ab939b0382fd0dedc811550e8f653f07c06f6682bcd525007507ca0376b6fac5854761ac2582cf29d1b87329059e08609dcc4670ec4d97ee163bc5712fc2790ee81cea250f3eb43a37ea0f7b07d1b98a9d3ca27c5b21a349abdd77a73a818eb085475b10deab87b31b314f333912606074583a863631095030a842255df2ece3cae98b7a80faa869073b0d5ac12e3eab464bb10e0d92cda8c0431b8bb48e18170b38b2558f3e5d5f344011eacd95f98facc1060d0714dbe3a6dde1f1a4f4908ece45fe31c71e40b57bb74d2c44cd800a080ccf5516297ccd12d89b6d1e8ccba8c552846766aad66a6cbb7f9da427482e677d38c96abe2e7a173fe9c0c1f91d87ee87d2f3bc287004b3cbb12bf81859b0ac933221dd6d33515c79feb021ae9227ca8fb70c4a8af6b75a152760b2a0b19ce2407e554dc5b146504f83d6998a6f056d702d5cc15db3cd7a39c360b76bd55051e1c7140ce5c990ad25f93541616579fd19472c0c995f2f33e6d4440dd62245cec043bc30ea9d38b33cefdfad39e2a7c4e027f851ce667c632fc88eb9a53a24724ecedb145a6798ccf58e75cf2c0253dfd12eb4e5f5164b7977e71ec158ff4dbef3bac081845d8571cfee9928238ad549828d57c1f58cd31962cfffd521c0e501a57f12fe4992c403a100bcc48b891dd10e8a390000297108a6c8d2f4aac7f7f5800f5df14a2cde3e8a64731772dfff11911a8b2c9ee7ca6206e2232b744c0894303565ff995104c1aa1c7f46d10b435f8ca725b8c909581076be6b4ee838b220d3b75821284404ff1e459ddfe01b95de46034bb3323384eb435222f730c12ab3eb8daa7ba3bc46c0a322e326a667e9928c583c28fd146762d1719a62abf25e86e538ed209b1e2a52fc647d5dafa2215df0a55074d81a1ede826d9d66a0c0e6469d1e77c8b5ceee08bbd36ac45b2c4c61ca70025ed7891b2484babc968af8c8c1eaa61e3b8f9e70ff786443006a0bb74faa1916b4da5f0a6122e2ab5b911d4ba8c903fa8c4042d18ce211fdb42e64576a28fc5ce6d5ab29c796'; // Generated from a small photo using the TRNG
		var numOfUsersA = 3;
		var keysA = exportPads.getCryptoKeysFromExtractedRandomData(numOfUsersA, randomDataHexadecimalA);
				
		var expectedSalt = 'cabeff2ffd746aca51fca2ca72865786d3d18fda5c42acd7033d3df3900c4b32fb5d36c5f0999d81bea8590c0146bd87032ff5c49a8db673a2bdb89ea1663558861d0d16121a9621be080e54e27a893e455d81a6e285380ab5609d27b7d351599dcada35aac0cbe8fc471e1f9921a4f738d1edab3077f957412e8905c65677a259651681b04b958e04950a1422feef6f585313a97db878845d763d16cea9a3cd8115e8f002cf781d098aa450106259ae57e1c526847d965a62c614f1317ff8d1';
		var expectedAesKey = '1be37ed18a2fc3835a77ef3c08da45b683592bb912049c3fd04e7f6d889282b9';
		var expectedSalsaKey = '0f2a429260b782f4a64c38437aaa7406074a120599a4a8eb9043392b0168136f';
		var expectedKeccakMacKey = 'f0a54c761043e2658a3da88a3cb46fee5dcdeb02c007a05fd1b0e7cdf5dc829112e1ff6459f616e977c6c4597a1209522a40e98d3c213fbcaec61e727e3a5c92';
		var expectedSkeinMacKey = '6b4e7898bbe3d448304bba06628d119083a6ee34a7126ca6f6d6050676146957129646bbf916d6883a6c183786d2ed59486dc9e7bcf8910ff843f41790cb3e4e';
		var expectedUserFailsafeRngKeyUserAlpha = 'c26b83acdc9249de952f3ff7310e3401aa6ea92ee86e8e544472e0b30666e64e';
		var expectedUserFailsafeRngKeyUserBravo = '0152481ce9edc2d379638bc4329aff673017ea1641b3214b3a2865b1637ed210';
		var expectedUserFailsafeRngKeyUserCharlie = 'f2a39021f53c60ce24b9f1e0a8f9db806251eac1f30d0efd53c63c16c13a9a3c';
		var expectedRemainingRandomData = 'e27839aa9a922a500f13d10fce4a5ac063b3f3b14e7f7ae755ce2d5fcf80c01d0f0652b6169550d0dc5e7e371f11dcdcfb76aefa21f4d6008f2aeba578bb8d68412234be22a2e3eb3c097643f1bbeadc37e5315d7ae9a71577175201fecfd98e863112ae8216dea03e0e0a8d961f12925b3d12cd54ad6da5b9a85d7acad695510f5e0ea8d888834416b5197233a9207687b33bc167dc5ea782df712e90e848e8567c6295c30225c3107aec5043afcd1336ad2c32d0d1d0c77e2cb85c7f2ac7b9bb6ea050c516ce31373f558e20df2752e6fdcbef4c191f8b4fa7bc526d1b2ed590e740887e79a0b312e4e65a47f6c219f116638d0184a62bff7ef6de0a6ca5f8611828919e587572ee8df2f8803ad8e6738d5f4df95bf945b39ec2bf9c9310c8a9c52d8d576685787f5f7be7ae29b414d1ec7175a22429f0dd8aebdf48e417914660a2309d8b690402e882ecef33e5106ade951daabe485a4990454a05472a33266e5ea80d4b7c11ae6cbe80d45b22cedf49de2029415496b1d61575be60a0b734683715260d49346c2fc4d1fc8a3df8733165c7f21aab989d5aef4aa2a6e9492ac3ba33b8fd1d3f6d99625951dd221e36da966cc90db7d6b003b9834dd925226d0c87d177fb33bfa100bcf1d1f7f4158e2d3b4d29a047685904de36083e9150b43f8407be4f7fec7b53f88be25ce0bfe5318277227fa8bcdcd073c9da09d26540edd21e3a863604eebde6c0b16db88b214e1b38b39d07993892752bbf4624287151a0a9f7e79c47038437aa4e1a47a730cda84eb2e68718fe1c891d57c7a93c954f4c13d74d8a5163e69ce8d4c3d0592fdb31ab9229fa3ea324f9befbc56760df05e2e1a0e7c1fafdc066b77fff1c6279b8729f17122433fd8f7d2f35914433f8dbaacb2d6ec0aedae167cf08494232ee312ff8b7c1d68ef124faf0b950b2cd8c2e62000af314ef5c1fb55b1786a58068d2487719deff41f832ebb8ffa80221a7834a1bae784c3afb8ace63be85620ec3d5d2d6898739708b9565bb8d29a41787732f2bf41fe535433e60eff0636a564388906279691ef3264367ec91a815f672614056a304c16b1a0059e903e1d838f9876a2a5e20f3da976bb8b5e5e5bfce18bc8c4dfa96040e703287db59d2de28e7b5a04807497b6a673988d851616413720b5905b4b3b2442e7260287b980c608bba46763e02f086f4c77fe813746e12bfd1bd82a2cd7a76db1ff2e6364194daaf7c1bb7c3b2cef741808ae2078f3fb2d902281a04e22a78ca36e575da3f7fe80554e4b9a9845a23f33d27b2f39c4d563519ca1cb15beabb5f444115ed006783d6b7ab5619532dd33ba6a1f59ae7eb2e0e553138316bf4540f7418355fe5959cce9db919a1a64c02e8542228e09b8ea88e00f412cfdecf8cc37096c80acc891dab769d074db3aa2a70e789e036a6a2cd5bd1359329cf1c391dd8bd8767f4341e28623c87709fdc320d8dc0f2d02ac95596ae4f9dd598e5558504477bbefca69f71ba9a8eeed138437382ccaa30e8141cb3c6fe688269368d910d70bb1233cfa7773af2797bcfba7118273c02cd9d60fec9c8877c256cb4575d0c982df900b0afc7298976e1f7fd1d114bf5fe898c0f7a2c94815d85efc40128171a05dcc3e44bba2e00eea828b5e708fd73535f73139ab1e31ebdebdb3d3ac6f12f7b789563701b5d8f903a3f2471b1c74cc55c0f5ee9382423f575c4905adad4118fb66cd4c918cf381ba1e6194d5f602f93a1f7f528ff38143fa9e8b2781d76206b49b3561c1b619aeb93e27339eeac478678464ee8120213cf79856e2eb0ca00cf393adea7265eea617b99cf8e9c23d236c7a72e8f8601632d1cd0c7c7c315d022b77e28af4abfb92e4a5a77b6b8ef25947a4dcb92576d68a719bd2613d15bbe23634049c4cfd322ab347f152c107335e1bf8eb92eeefbffff2320273ba276270b012f62be38ce27e44a90658222c682356876ca81ca13b6b60dc1b691ba2ca9a408db01ed568573b7986d7ef4c2e4adf51826830634b7267a05288552d7fa66dbd9ef59f0e66855ac82f294a873f4af0f4bae18580516b3c05407e9f3878c6c5da3d2a952da037f7358e118ec5c879aa51e9b5beb9f2fed1a8930f1f7791546d279fa1d18518f6c45b9ba64f605c766b1f921b2fb359b7b4b8c9c61985d582ea91aea7d7894962ec6f8a34c03d21864c2033e00d998f6194abfa07e22deaf2db57ca6ff30fdbf6c295fade4a7f799e547a644767d8cca0678af443e805546571fdd75900062723305b18c52e4d9ace5994cb37d192d791a7971ba790785bd794a70f5ab7790d4f5e4712b1a1864ad8833b507b062fe302b164cecdd158140fbc0c62e58089d241d7f166f209252e4d4f5826d1016b34a94df0eefc637319f88a6b759afbd12cb3b0d97cfff7286608147cec472d7775a66d90dadf9755a7a31ef15beb2d213614a2e408daa6abd0eb8e5d247d3722c42819a7bff6a1b680e4541d742a048da7a0a3252670bb6789a80812c51116e4676e13747d2654d4432462d7fe4001b73cfa6eac4a8861643c6f93d45317f7e471cb7a05810c1df47b3fa738a4594d6ed9ac8bfbec4a6c79d5a5930c8760d88fdbd415d917e11e35c105fa8f7d8ba81d9bbbe2ebe3b2dbee2bc4177240096866ae62047bea778e6474e371b3fbafc4312acd5454608374698f6eae6e5b2015507d56c374edd75ed6420bcaa3e73348e470b0326edf8e53010fd3d46365699b1780590bca4815af56345c8c79b22b7b5bbef5eb69bea5a3253810f9a17f18b8a62ffe48fac212ca9d1b78962a792a11b78fd3a2f97cd8bb28e38dc78fe5c5aab758e5aa357a0cbcf4c3dd689efbf9d207fb6d637c6729f5152f27b6fa74bdff5442461afa015a00d85def62e51d958be32ecd92f1bc439074324e012b49f554e48fb7b7e4ecad9c300c70d83452ddd97231ae54c7edc5535e5240cf6b6fa53f3d0a0e30d140ed8d71d8c893f6b904872d38690124619d92fb432b173a792d3e455e3f1eecbcd2036d018db5a8ff1e4e51de0e44ae885160113f6bb72a29e3e889a01bc8ff5551db7554bb056e665100de14017cb3d9fe764bcfb86ff0c46184e4fa286c437160f196fd9dfd68e4961eb53ddfdbfbffe80058b70cecc74121017685b080a7e602dc03446ab183f0b7eae3f5f85c061ecd2a98c1780ddc5ae46519f441e924ba740a681cb1ea9b4df6c5ad29b5354d2fa7eeb80fa56be2c0e6fc6c412816e2203ea36719c12da45a167dd31501cc0f77aed2f8f7e20e9b818e9fbc32e002a1b9d39816585366b312894de315382c67f64ab939b0382fd0dedc811550e8f653f07c06f6682bcd525007507ca0376b6fac5854761ac2582cf29d1b87329059e08609dcc4670ec4d97ee163bc5712fc2790ee81cea250f3eb43a37ea0f7b07d1b98a9d3ca27c5b21a349abdd77a73a818eb085475b10deab87b31b314f333912606074583a863631095030a842255df2ece3cae98b7a80faa869073b0d5ac12e3eab464bb10e0d92cda8c0431b8bb48e18170b38b2558f3e5d5f344011eacd95f98facc1060d0714dbe3a6dde1f1a4f4908ece45fe31c71e40b57bb74d2c44cd800a080ccf5516297ccd12d89b6d1e8ccba8c552846766aad66a6cbb7f9da427482e677d38c96abe2e7a173fe9c0c1f91d87ee87d2f3bc287004b3cbb12bf81859b0ac933221dd6d33515c79feb021ae9227ca8fb70c4a8af6b75a152760b2a0b19ce2407e554dc5b146504f83d6998a6f056d702d5cc15db3cd7a39c360b76bd55051e1c7140ce5c990ad25f93541616579fd19472c0c995f2f33e6d4440dd62245cec043bc30ea9d38b33cefdfad39e2a7c4e027f851ce667c632fc88eb9a53a24724ecedb145a6798ccf58e75cf2c0253dfd12eb4e5f5164b7977e71ec158ff4dbef3bac081845d8571cfee9928238ad549828d57c1f58cd31962cfffd521c0e501a57f12fe4992c403a100bcc48b891dd10e8a390000297108a6c8d2f4aac7f7f5800f5df14a2cde3e8a64731772dfff11911a8b2c9ee7ca6206e2232b744c0894303565ff995104c1aa1c7f46d10b435f8ca725b8c909581076be6b4ee838b220d3b75821284404ff1e459ddfe01b95de46034bb3323384eb435222f730c12ab3eb8daa7ba3bc46c0a322e326a667e9928c583c28fd146762d1719a62abf25e86e538ed209b1e2a52fc647d5dafa2215df0a55074d81a1ede826d9d66a0c0e6469d1e77c8b5ceee08bbd36ac45b2c4c61ca70025ed7891b2484babc968af8c8c1eaa61e3b8f9e70ff786443006a0bb74faa1916b4da5f0a6122e2ab5b911d4ba8c903fa8c4042d18ce211fdb42e64576a28fc5ce6d5ab29c796';
	
		var randomDataHexadecimalB = 'e27839aa9a922a500f13d10fce4a5ac063b3f3b14e7f7ae755ce2d';
		var numOfUsersB = 4;
		var keysB = exportPads.getCryptoKeysFromExtractedRandomData(numOfUsersB, randomDataHexadecimalB);
		
		ok(keysA.salt === expectedSalt, 'salt ' + keysA.salt + ' should equal ' + expectedSalt);
		ok(keysA.aesKey === expectedAesKey, 'aesKey ' + keysA.aesKey + ' should equal ' + expectedAesKey);
		ok(keysA.salsaKey === expectedSalsaKey, 'salsaKey ' + keysA.salsaKey + ' should equal ' + expectedSalsaKey);
		ok(keysA.keccakMacKey === expectedKeccakMacKey, 'keccakMacKey ' + keysA.keccakMacKey + ' should equal ' + expectedKeccakMacKey);
		ok(keysA.skeinMacKey === expectedSkeinMacKey, 'skeinMacKey ' + keysA.skeinMacKey + ' should equal ' + expectedSkeinMacKey);
		ok(keysA.userFailsafeRngKeys.alpha === expectedUserFailsafeRngKeyUserAlpha, 'userFailsafeRngKeyUserAlpha ' + keysA.userFailsafeRngKeys.alpha + ' should equal ' + expectedUserFailsafeRngKeyUserAlpha);
		ok(keysA.userFailsafeRngKeys.bravo === expectedUserFailsafeRngKeyUserBravo, 'userFailsafeRngKeyUserBravo ' + keysA.userFailsafeRngKeys.bravo + ' should equal ' + expectedUserFailsafeRngKeyUserBravo);
		ok(keysA.userFailsafeRngKeys.charlie === expectedUserFailsafeRngKeyUserCharlie, 'userFailsafeRngKeyUserCharlie ' + keysA.userFailsafeRngKeys.charlie + ' should equal ' + expectedUserFailsafeRngKeyUserCharlie);
		ok(keysA.extractedRandomDataHex === expectedRemainingRandomData, 'remainingRandomData ' + keysA.extractedRandomDataHex + ' should equal ' + expectedRemainingRandomData);
		
		ok(keysB === false, 'Second fetch of keys: ' + keysB.toString() + ' should equal false because there is not enough key material');
	});
	
	
	
	/*
	 * ------------------------------------------------------------------
	 * Create pads and test correct allocation between users
	 * ------------------------------------------------------------------
	 */
	
	var randomDataHexadecimal = 'cabeff2ffd746aca51fca2ca72865786d3d18fda5c42acd7033d3df3900c4b32fb5d36c5f0999d81bea8590c0146bd87032ff5c49a8db673a2bdb89ea1663558861d0d16121a9621be080e54e27a893e455d81a6e285380ab5609d27b7d351599dcada35aac0cbe8fc471e1f9921a4f738d1edab3077f957412e8905c65677a259651681b04b958e04950a1422feef6f585313a97db878845d763d16cea9a3cd8115e8f002cf781d098aa450106259ae57e1c526847d965a62c614f1317ff8d11be37ed18a2fc3835a77ef3c08da45b683592bb912049c3fd04e7f6d889282b90f2a429260b782f4a64c38437aaa7406074a120599a4a8eb9043392b0168136ff0a54c761043e2658a3da88a3cb46fee5dcdeb02c007a05fd1b0e7cdf5dc829112e1ff6459f616e977c6c4597a1209522a40e98d3c213fbcaec61e727e3a5c926b4e7898bbe3d448304bba06628d119083a6ee34a7126ca6f6d6050676146957129646bbf916d6883a6c183786d2ed59486dc9e7bcf8910ff843f41790cb3e4ec26b83acdc9249de952f3ff7310e3401aa6ea92ee86e8e544472e0b30666e64e0152481ce9edc2d379638bc4329aff673017ea1641b3214b3a2865b1637ed210f2a39021f53c60ce24b9f1e0a8f9db806251eac1f30d0efd53c63c16c13a9a3ce27839aa9a922a500f13d10fce4a5ac063b3f3b14e7f7ae755ce2d5fcf80c01d0f0652b6169550d0dc5e7e371f11dcdcfb76aefa21f4d6008f2aeba578bb8d68412234be22a2e3eb3c097643f1bbeadc37e5315d7ae9a71577175201fecfd98e863112ae8216dea03e0e0a8d961f12925b3d12cd54ad6da5b9a85d7acad695510f5e0ea8d888834416b5197233a9207687b33bc167dc5ea782df712e90e848e8567c6295c30225c3107aec5043afcd1336ad2c32d0d1d0c77e2cb85c7f2ac7b9bb6ea050c516ce31373f558e20df2752e6fdcbef4c191f8b4fa7bc526d1b2ed590e740887e79a0b312e4e65a47f6c219f116638d0184a62bff7ef6de0a6ca5f8611828919e587572ee8df2f8803ad8e6738d5f4df95bf945b39ec2bf9c9310c8a9c52d8d576685787f5f7be7ae29b414d1ec7175a22429f0dd8aebdf48e417914660a2309d8b690402e882ecef33e5106ade951daabe485a4990454a05472a33266e5ea80d4b7c11ae6cbe80d45b22cedf49de2029415496b1d61575be60a0b734683715260d49346c2fc4d1fc8a3df8733165c7f21aab989d5aef4aa2a6e9492ac3ba33b8fd1d3f6d99625951dd221e36da966cc90db7d6b003b9834dd925226d0c87d177fb33bfa100bcf1d1f7f4158e2d3b4d29a047685904de36083e9150b43f8407be4f7fec7b53f88be25ce0bfe5318277227fa8bcdcd073c9da09d26540edd21e3a863604eebde6c0b16db88b214e1b38b39d07993892752bbf4624287151a0a9f7e79c47038437aa4e1a47a730cda84eb2e68718fe1c891d57c7a93c954f4c13d74d8a5163e69ce8d4c3d0592fdb31ab9229fa3ea324f9befbc56760df05e2e1a0e7c1fafdc066b77fff1c6279b8729f17122433fd8f7d2f35914433f8dbaacb2d6ec0aedae167cf08494232ee312ff8b7c1d68ef124faf0b950b2cd8c2e62000af314ef5c1fb55b1786a58068d2487719deff41f832ebb8ffa80221a7834a1bae784c3afb8ace63be85620ec3d5d2d6898739708b9565bb8d29a41787732f2bf41fe535433e60eff0636a564388906279691ef3264367ec91a815f672614056a304c16b1a0059e903e1d838f9876a2a5e20f3da976bb8b5e5e5bfce18bc8c4dfa96040e703287db59d2de28e7b5a04807497b6a673988d851616413720b5905b4b3b2442e7260287b980c608bba46763e02f086f4c77fe813746e12bfd1bd82a2cd7a76db1ff2e6364194daaf7c1bb7c3b2cef741808ae2078f3fb2d902281a04e22a78ca36e575da3f7fe80554e4b9a9845a23f33d27b2f39c4d563519ca1cb15beabb5f444115ed006783d6b7ab5619532dd33ba6a1f59ae7eb2e0e553138316bf4540f7418355fe5959cce9db919a1a64c02e8542228e09b8ea88e00f412cfdecf8cc37096c80acc891dab769d074db3aa2a70e789e036a6a2cd5bd1359329cf1c391dd8bd8767f4341e28623c87709fdc320d8dc0f2d02ac95596ae4f9dd598e5558504477bbefca69f71ba9a8eeed138437382ccaa30e8141cb3c6fe688269368d910d70bb1233cfa7773af2797bcfba7118273c02cd9d60fec9c8877c256cb4575d0c982df900b0afc7298976e1f7fd1d114bf5fe898c0f7a2c94815d85efc40128171a05dcc3e44bba2e00eea828b5e708fd73535f73139ab1e31ebdebdb3d3ac6f12f7b789563701b5d8f903a3f2471b1c74cc55c0f5ee9382423f575c4905adad4118fb66cd4c918cf381ba1e6194d5f602f93a1f7f528ff38143fa9e8b2781d76206b49b3561c1b619aeb93e27339eeac478678464ee8120213cf79856e2eb0ca00cf393adea7265eea617b99cf8e9c23d236c7a72e8f8601632d1cd0c7c7c315d022b77e28af4abfb92e4a5a77b6b8ef25947a4dcb92576d68a719bd2613d15bbe23634049c4cfd322ab347f152c107335e1bf8eb92eeefbffff2320273ba276270b012f62be38ce27e44a90658222c682356876ca81ca13b6b60dc1b691ba2ca9a408db01ed568573b7986d7ef4c2e4adf51826830634b7267a05288552d7fa66dbd9ef59f0e66855ac82f294a873f4af0f4bae18580516b3c05407e9f3878c6c5da3d2a952da037f7358e118ec5c879aa51e9b5beb9f2fed1a8930f1f7791546d279fa1d18518f6c45b9ba64f605c766b1f921b2fb359b7b4b8c9c61985d582ea91aea7d7894962ec6f8a34c03d21864c2033e00d998f6194abfa07e22deaf2db57ca6ff30fdbf6c295fade4a7f799e547a644767d8cca0678af443e805546571fdd75900062723305b18c52e4d9ace5994cb37d192d791a7971ba790785bd794a70f5ab7790d4f5e4712b1a1864ad8833b507b062fe302b164cecdd158140fbc0c62e58089d241d7f166f209252e4d4f5826d1016b34a94df0eefc637319f88a6b759afbd12cb3b0d97cfff7286608147cec472d7775a66d90dadf9755a7a31ef15beb2d213614a2e408daa6abd0eb8e5d247d3722c42819a7bff6a1b680e4541d742a048da7a0a3252670bb6789a80812c51116e4676e13747d2654d4432462d7fe4001b73cfa6eac4a8861643c6f93d45317f7e471cb7a05810c1df47b3fa738a4594d6ed9ac8bfbec4a6c79d5a5930c8760d88fdbd415d917e11e35c105fa8f7d8ba81d9bbbe2ebe3b2dbee2bc4177240096866ae62047bea778e6474e371b3fbafc4312acd5454608374698f6eae6e5b2015507d56c374edd75ed6420bcaa3e73348e470b0326edf8e53010fd3d46365699b1780590bca4815af56345c8c79b22b7b5bbef5eb69bea5a3253810f9a17f18b8a62ffe48fac212ca9d1b78962a792a11b78fd3a2f97cd8bb28e38dc78fe5c5aab758e5aa357a0cbcf4c3dd689efbf9d207fb6d637c6729f5152f27b6fa74bdff5442461afa015a00d85def62e51d958be32ecd92f1bc439074324e012b49f554e48fb7b7e4ecad9c300c70d83452ddd97231ae54c7edc5535e5240cf6b6fa53f3d0a0e30d140ed8d71d8c893f6b904872d38690124619d92fb432b173a792d3e455e3f1eecbcd2036d018db5a8ff1e4e51de0e44ae885160113f6bb72a29e3e889a01bc8ff5551db7554bb056e665100de14017cb3d9fe764bcfb86ff0c46184e4fa286c437160f196fd9dfd68e4961eb53ddfdbfbffe80058b70cecc74121017685b080a7e602dc03446ab183f0b7eae3f5f85c061ecd2a98c1780ddc5ae46519f441e924ba740a681cb1ea9b4df6c5ad29b5354d2fa7eeb80fa56be2c0e6fc6c412816e2203ea36719c12da45a167dd31501cc0f77aed2f8f7e20e9b818e9fbc32e002a1b9d39816585366b312894de315382c67f64ab939b0382fd0dedc811550e8f653f07c06f6682bcd525007507ca0376b6fac5854761ac2582cf29d1b87329059e08609dcc4670ec4d97ee163bc5712fc2790ee81cea250f3eb43a37ea0f7b07d1b98a9d3ca27c5b21a349abdd77a73a818eb085475b10deab87b31b314f333912606074583a863631095030a842255df2ece3cae98b7a80faa869073b0d5ac12e3eab464bb10e0d92cda8c0431b8bb48e18170b38b2558f3e5d5f344011eacd95f98facc1060d0714dbe3a6dde1f1a4f4908ece45fe31c71e40b57bb74d2c44cd800a080ccf5516297ccd12d89b6d1e8ccba8c552846766aad66a6cbb7f9da427482e677d38c96abe2e7a173fe9c0c1f91d87ee87d2f3bc287004b3cbb12bf81859b0ac933221dd6d33515c79feb021ae9227ca8fb70c4a8af6b75a152760b2a0b19ce2407e554dc5b146504f83d6998a6f056d702d5cc15db3cd7a39c360b76bd55051e1c7140ce5c990ad25f93541616579fd19472c0c995f2f33e6d4440dd62245cec043bc30ea9d38b33cefdfad39e2a7c4e027f851ce667c632fc88eb9a53a24724ecedb145a6798ccf58e75cf2c0253dfd12eb4e5f5164b7977e71ec158ff4dbef3bac081845d8571cfee9928238ad549828d57c1f58cd31962cfffd521c0e501a57f12fe4992c403a100bcc48b891dd10e8a390000297108a6c8d2f4aac7f7f5800f5df14a2cde3e8a64731772dfff11911a8b2c9ee7ca6206e2232b744c0894303565ff995104c1aa1c7f46d10b435f8ca725b8c909581076be6b4ee838b220d3b75821284404ff1e459ddfe01b95de46034bb3323384eb435222f730c12ab3eb8daa7ba3bc46c0a322e326a667e9928c583c28fd146762d1719a62abf25e86e538ed209b1e2a52fc647d5dafa2215df0a55074d81a1ede826d9d66a0c0e6469d1e77c8b5ceee08bbd36ac45b2c4c61ca70025ed7891b2484babc968af8c8c1eaa61e3b8f9e70ff786443006a0bb74faa1916b4da5f0a6122e2ab5b911d4ba8c903fa8c4042d18ce211fdb42e64576a28fc5ce6d5ab29c796'; // Generated from a small photo using the TRNG
	var padsTwoUsers = exportPads.createPads(2, randomDataHexadecimal);
	
	QUnit.test("Create pads and test correct allocation between users", function()
	{
		var totalNumOfPads = Math.floor(randomDataHexadecimal.length / common.totalPadSizeHex);		// 18 pads		
		var padsThreeUsers = exportPads.createPads(3, randomDataHexadecimal);
		var padsFourUsers = exportPads.createPads(4, randomDataHexadecimal);
		var padsFiveUsers = exportPads.createPads(5, randomDataHexadecimal);
		var padsSixUsers = exportPads.createPads(6, randomDataHexadecimal);
		var padsSevenUsers = exportPads.createPads(7, randomDataHexadecimal);
		
		ok(padsTwoUsers.alpha[0].padIdentifier.length === common.padIdentifierSizeHex, 'Pad identifier size ' + padsTwoUsers.alpha[0].padIdentifier.length + ' should be ' + common.padIdentifierSizeHex);
		ok(padsTwoUsers.alpha[0].pad.length === common.totalPadSizeHex, 'Full pad including pad id ' + padsTwoUsers.alpha[0].pad.length + ' should be ' + common.totalPadSizeHex);
		
		ok(padsTwoUsers.alpha.length === 9, 'Two users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsTwoUsers.alpha.length + ' should be 9 pads');
		ok(padsTwoUsers.bravo.length === 9, 'Two users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsTwoUsers.bravo.length + ' should be 9 pads');
		
		ok(padsThreeUsers.alpha.length === 6, 'Three users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsThreeUsers.alpha.length + ' should be 6 pads');
		ok(padsThreeUsers.bravo.length === 6, 'Three users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsThreeUsers.bravo.length + ' should be 6 pads');
		ok(padsThreeUsers.charlie.length === 6, 'Three users with total ' + totalNumOfPads + ' pads, charlie result = ' + padsThreeUsers.charlie.length + ' should be 6 pads');
		
		ok(padsFourUsers.alpha.length === 4, 'Four users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsFourUsers.alpha.length + ' should be 4 pads');
		ok(padsFourUsers.bravo.length === 4, 'Four users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsFourUsers.bravo.length + ' should be 4 pads');
		ok(padsFourUsers.charlie.length === 4, 'Four users with total ' + totalNumOfPads + ' pads, charlie result = ' + padsFourUsers.charlie.length + ' should be 4 pads');
		ok(padsFourUsers.delta.length === 6, 'Four users with total ' + totalNumOfPads + ' pads, delta result = ' + padsFourUsers.delta.length + ' should be 4 pads plus the 2 remaining pads');
		
		ok(padsFiveUsers.alpha.length === 3, 'Five users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsFiveUsers.alpha.length + ' should be 3 pads');
		ok(padsFiveUsers.bravo.length === 3, 'Five users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsFiveUsers.bravo.length + ' should be 3 pads');
		ok(padsFiveUsers.charlie.length === 3, 'Five users with total ' + totalNumOfPads + ' pads, charlie result = ' + padsFiveUsers.charlie.length + ' should be 3 pads');
		ok(padsFiveUsers.delta.length === 3, 'Five users with total ' + totalNumOfPads + ' pads, delta result = ' + padsFiveUsers.delta.length + ' should be 3 pads');
		ok(padsFiveUsers.echo.length === 6, 'Five users with total ' + totalNumOfPads + ' pads, echo result = ' + padsFiveUsers.echo.length + ' should be 3 pads plus the 3 remaining pads');
		
		ok(padsSixUsers.alpha.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsSixUsers.alpha.length + ' should be 3 pads');
		ok(padsSixUsers.bravo.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsSixUsers.bravo.length + ' should be 3 pads');
		ok(padsSixUsers.charlie.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, charlie result = ' + padsSixUsers.charlie.length + ' should be 3 pads');
		ok(padsSixUsers.delta.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, delta result = ' + padsSixUsers.delta.length + ' should be 3 pads');
		ok(padsSixUsers.echo.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, echo result = ' + padsSixUsers.echo.length + ' should be 3 pads');
		ok(padsSixUsers.foxtrot.length === 3, 'Six users with total ' + totalNumOfPads + ' pads, foxtrot result = ' + padsSixUsers.foxtrot.length + ' should be 3 pads');
		
		ok(padsSevenUsers.alpha.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, alpha result = ' + padsSevenUsers.alpha.length + ' should be 2 pads');
		ok(padsSevenUsers.bravo.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, bravo result = ' + padsSevenUsers.bravo.length + ' should be 2 pads');
		ok(padsSevenUsers.charlie.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, charlie result = ' + padsSevenUsers.charlie.length + ' should be 2 pads');
		ok(padsSevenUsers.delta.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, delta result = ' + padsSevenUsers.delta.length + ' should be 2 pads');
		ok(padsSevenUsers.echo.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, echo result = ' + padsSevenUsers.echo.length + ' should be 2 pads');
		ok(padsSevenUsers.foxtrot.length === 2, 'Seven users with total ' + totalNumOfPads + ' pads, foxtrot result = ' + padsSevenUsers.foxtrot.length + ' should be 2 pads');
		ok(padsSevenUsers.golf.length === 6, 'Seven users with total ' + totalNumOfPads + ' pads, golf result = ' + padsSevenUsers.golf.length + ' should be 2 pads plus the remaining 4 pads');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test encryption and authentication of one-time pads
	 * ------------------------------------------------------------------
	 */
	
	var encryptedPadsTwoUsers = dbCrypto.encryptAndAuthenticatePads(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, padsTwoUsers);
	
	QUnit.test("Test encryption and authentication of one-time pads", function()
	{				
		ok(encryptedPadsTwoUsers.alpha[0].padNum === 0, 'Pad number ' + encryptedPadsTwoUsers.alpha[0].padNum + ' should be ' + 0);
		ok(encryptedPadsTwoUsers.alpha[0].padIdentifier.length === common.padIdentifierSizeHex, 'Pad identifier ' + encryptedPadsTwoUsers.alpha[0].padIdentifier + ' size ' + encryptedPadsTwoUsers.alpha[0].padIdentifier.length + ' should be ' + common.padIdentifierSizeHex);
		ok(encryptedPadsTwoUsers.alpha[0].pad.length === (common.totalPadSizeHex - common.padIdentifierSizeHex), 'Pad without pad id size should be ' + encryptedPadsTwoUsers.alpha[0].pad.length + ' should be ' + (common.totalPadSizeHex - common.padIdentifierSizeHex));
		ok(encryptedPadsTwoUsers.alpha[0].mac.length === 128, 'MAC size should be ' + encryptedPadsTwoUsers.alpha[0].mac.length + ' should be ' + 128);		
		ok(encryptedPadsTwoUsers.alpha[0].pad !== padsTwoUsers.alpha[0].pad.substr(common.padIdentifierSizeHex), 'Encrypted pad ' + encryptedPadsTwoUsers.alpha[0].pad + ' should not be the same as the plaintext pad ' + padsTwoUsers.alpha[0].pad.substr(common.padIdentifierSizeHex));
		
		ok(encryptedPadsTwoUsers.alpha[8].padNum === 8, 'Pad number ' + encryptedPadsTwoUsers.alpha[8].padNum + ' should be ' + 8);
		ok(encryptedPadsTwoUsers.alpha[8].padIdentifier.length === common.padIdentifierSizeHex, 'Pad identifier ' + encryptedPadsTwoUsers.alpha[8].padIdentifier + ' size ' + encryptedPadsTwoUsers.alpha[8].padIdentifier.length + ' should be ' + common.padIdentifierSizeHex);
		ok(encryptedPadsTwoUsers.alpha[8].pad.length === (common.totalPadSizeHex - common.padIdentifierSizeHex), 'Pad without pad id size should be ' + encryptedPadsTwoUsers.alpha[8].pad.length + ' should be ' + (common.totalPadSizeHex - common.padIdentifierSizeHex));
		ok(encryptedPadsTwoUsers.alpha[8].mac.length === 128, 'MAC size should be ' + encryptedPadsTwoUsers.alpha[8].mac.length + ' should be ' + 128);
		ok(encryptedPadsTwoUsers.alpha[8].pad !== padsTwoUsers.alpha[8].pad.substr(common.padIdentifierSizeHex), 'Encrypted pad ' + encryptedPadsTwoUsers.alpha[8].pad + ' should not be the same as the plaintext pad ' + padsTwoUsers.alpha[8].pad.substr(common.padIdentifierSizeHex));
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test verification and decryption of one-time pads
	 * ------------------------------------------------------------------
	 */
	
	// Test success case
	var decryptedPads = dbCrypto.verifyAndDecryptPads(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, encryptedPadsTwoUsers);
		
	// Test failure case by adding an invalid pad
	var badEncryptedPadsA = db.clone(decryptedPads);
	    badEncryptedPadsA.alpha.push({
			padIdentifier: 'cabeff2ffd746a',
			padNum: 9,
			pad: '12a155fd70bafdca2f0817c99097952b0f976df42ba20531afba220c54d313f2296d39f98dc081bd1b69d66261dbcd13a61f0fb4b41026b46efa8843965d208c692991dcf4d51c088da72ed1824b864467d5f00317da6c06908bf48e06dfa863edfe9e3a4bbb2abbe8f3964652386401a7d04727a6ff4b6c05d1821d75c8409559438f70702fbdde50387784307f858ce33605ce90a04a589f24169e79a7435fbd639247c29ce4b33f3ebf1cb097be34f435bc00c17ac803a0',
			mac: '77c51474d19722ea7ed4402f97229027ee85922d80ad372c6da182556cbdd9d9b88e26bc38d03adb491b45c90adba5243875858cdd55d098a0c0bc44e1d57c62'
	});
	var badDecryptedPadsA = dbCrypto.verifyAndDecryptPads(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, badEncryptedPadsA);
		
	QUnit.test("Test verification and decryption of one-time pads", function(assert)
	{
		assert.deepEqual(padsTwoUsers, decryptedPads, 'The decrypted pads ' + JSON.stringify(decryptedPads) + ' should be the same as the original pads ' + JSON.stringify(padsTwoUsers));
		ok(badDecryptedPadsA === false, 'Invalid pad ' + badDecryptedPadsA + ' should be false');
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Test encryption and MAC of the pad data info then verification and decryption
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Test encryption and MAC of the pad data info then verification and decryption", function(assert)
	{
		// Test encryption and MAC
		var dbEncAesKey = '0abe3c109e5baafd9fd8eef26ff4dc420971b530dbce5dd054baf5055728fa09';
		var dbEncSalsaKey = '93d00583375358157d6c25c01ad123afe1a69a5274e5ccd1378bf06876437a3f';
		var dbEncKeccakKey = '30d5ec01e43e0884eb843201b47bcf585c397ec20450ee50820f1ca56945c16c9991eaa08b13a0e2475b5dc709b7b892e84450882c40f70df05ccbd6c283aadd';
		var dbEncSkeinKey = '054f4f55a5a6ece495de2789cde143987476d7b6ec7b8564f09df7b730ce5daa456177d50211f1f9c29358c92297aa213361ad9145cd6acfbfc656df8a11f1c0';
		
		// Mock pad info to encrypt
		var padData = {
			info: {
				custom: {
					enableSounds: true,
					enableVibration: true,
					enableWebNotifications: true
				},
				programVersion: '1.5',
				serverAddressAndPort: 'http://testjericho.net',
				serverKey: '89975057bac787e526aba890440dd89f95f2ea14a1779dcd3ff4bac215418a7566dafb5bf19417ec6d152f636ba8eb3ac4bb823086da8541798f67c3a1055d2e',
				user: 'alpha',
				userNicknames: {
					alpha: 'Alice',
					bravo: 'Bob'
				}
			}
		};
		var padDataJson = JSON.stringify(padData.info);
		var padDataBinary = common.convertTextToBinary(padDataJson);
		var padDataHex = common.convertBinaryToHexadecimal(padDataBinary);
		
		var padDataInfoEncrypted = dbCrypto.encryptAndMacPadInfo(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, padData.info);
		var info = padDataInfoEncrypted.info;
		var mac = padDataInfoEncrypted.mac;
				
		ok(padDataHex.length === info.length, 'The plaintext length ' + padDataHex.length + ' should be the same as the ciphertext length ' + info.length);
		ok(mac.length === 128, 'The MAC length ' + mac.length + ' should be the same as the output digest size 128 hex symbols');
		
		
		// Test verification of MAC and decryption
		var decryptedPadData = dbCrypto.verifyAndDecryptPadInfo(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncSkeinKey, padDataInfoEncrypted);
		var invalidPadData = dbCrypto.verifyAndDecryptPadInfo(dbEncAesKey, dbEncSalsaKey, dbEncKeccakKey, dbEncKeccakKey, padDataInfoEncrypted); // use Keccak key twice
		
		assert.deepEqual(padData.info, decryptedPadData, 'The decrypted pad data ' + JSON.stringify(decryptedPadData) + ' should be the same as the original pad data ' + padDataJson);
		ok(invalidPadData === false, 'An invalid authentication ' + invalidPadData + ' should be false');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test MAC creation and verification of a user's pad database index
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Test MAC creation and verification of a user's pad database index", function()
	{
		// Create the MAC
		var keccakMacKey = 'e4096eaeadb01cb4a0f274d59da537a66ff4907b7db7b3e0a235581f64b2560eeb129b0f2870a08fe7953e354962a579a5634668e4caae98335fe3379d4bb791';
		var skeinMacKey = 'd6dff9b318515ff04134389ec3da7460f6927e321092c49e3a54d761d57b3d38eae1c0cc2af8aacb8169c9d682bb01a2c8788a5a489baaefd7f7841c80295c9c';
		var userCallSign = 'test';
		var userPads = db.padData.pads[userCallSign];	
		var macOfDatabaseIndex = dbCrypto.createMacOfDatabaseIndex(keccakMacKey, skeinMacKey, userCallSign, userPads);

		// Verify the MAC
		var macVerification = dbCrypto.verifyDatabaseIndex(keccakMacKey, skeinMacKey, userCallSign, userPads, macOfDatabaseIndex);

		ok(macOfDatabaseIndex === '0d9c3ea63ad06394e6b7d3dee4cb08490620c7e57e706a97c383a165f0fa55295fa8c97a9f568bf84af9e5b1bc219b7b2396cb345e318d574a265ba122d0b16a', macOfDatabaseIndex);
		ok(macOfDatabaseIndex.length === common.macSizeHex, 'Hash length: ' + macOfDatabaseIndex.length);
		ok(macVerification === true, 'MAC verified = ' + macVerification);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test creation of a MAC of the database indexes for all users
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Test creation of a MAC of the database indexes for all users", function()
	{
		var keccakMacKey = 'e4096eaeadb01cb4a0f274d59da537a66ff4907b7db7b3e0a235581f64b2560eeb129b0f2870a08fe7953e354962a579a5634668e4caae98335fe3379d4bb791';
		var skeinMacKey = 'd6dff9b318515ff04134389ec3da7460f6927e321092c49e3a54d761d57b3d38eae1c0cc2af8aacb8169c9d682bb01a2c8788a5a489baaefd7f7841c80295c9c';
		var macOfPadIndexes = dbCrypto.createMacOfAllDatabaseIndexes(keccakMacKey, skeinMacKey, encryptedPadsTwoUsers);
				
		ok(macOfPadIndexes.alpha.length === 128, 'MAC length should be 128 hex chars (512 bits)');
		ok(macOfPadIndexes.bravo.length === 128, 'MAC length should be 128 hex chars (512 bits)');
		ok(macOfPadIndexes.alpha === 'cd4f840e3482fc533b18ef2161b1bd5c94373b5e0f1c501df39fb11f40f689651afd4e81b47d67243318fc0c31659dd4d41990f14917bad7ac599be4a1c94c72');
		ok(macOfPadIndexes.bravo === '96beeb13468cd131b65bd40582b089986ad39471273ab0524f642164897649e3115343d4c0ab9fde19918ad55b6eac584cf95fa683a15be4271b69cc3dec8f0b');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Verify MAC of all user's pad database indexes
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Verify MAC of all user's pad database indexes", function()
	{
		// Test data for success case
		var keccakMacKey = 'e4096eaeadb01cb4a0f274d59da537a66ff4907b7db7b3e0a235581f64b2560eeb129b0f2870a08fe7953e354962a579a5634668e4caae98335fe3379d4bb791';
		var skeinMacKey = 'd6dff9b318515ff04134389ec3da7460f6927e321092c49e3a54d761d57b3d38eae1c0cc2af8aacb8169c9d682bb01a2c8788a5a489baaefd7f7841c80295c9c';
		var userPads = JSON.parse(
		           '{"alpha":['
		         +      '{"padNum":0,"padIdentifier":"cabeff2ffd746a","pad":"69ba77f22986ad250a9a30555d4234d34649cb540063bbaa205e0e03c3c77dc50aa3cca8d15e53d63095da5292c5a8d8fdfd1f26edaf9eaafaeba1dcecffe5efa4d6b645ecf48190209e1b0f1ba017d0f7bd25a8e54ba2002e951aa2ffa3d9ad96b831c4c5593e49d0affa9b86ad0b3850f91e8c8a925cd28369aba80f2bd058e0e019c1c52e6608f603c7c4eeff5c28df30b96367249efc082c9f219446dda96797fb82b6b6f42ce3d2c7f47fb9ac915d77f66868e288a29e","mac":"2223c18b198d9a949d94497f5dc7a69fe12dcf53766de3e5515e58e70d0318de6c365beca8fb0a5ccd579a02a3e920f43072b6b56ff3c0fd60db0fb713419e9b"},'
		         +      '{"padNum":1,"padIdentifier":"1be37ed18a2fc3","pad":"223633c169312b271a736c11a04e2558be733aad32db7db7af3ee3ef2327496edff89932d83dce1407f91a47af94a3acb1ac32a63da73f945871e885da49dff63f11fd27188f9aa98aec83a87f47f1ba636dceab2dfc8b7d8ffec7f0c58f22f41d849a4f87bb08a43152a56985fcf2a9ec52b5830ba841995f4cb204e2d7cd7a74732871d5b80a47836f2c7d6f2c1612c591d7f82c0f46ae38ec9db2cc95b1df02545d03b493c3223def44c7319c4baee96c4aabe8331e945d","mac":"6396389c1ee1b6485b3f5b82da22f72bcdb385890b92e46c2091c7b9af860323d268f1b3e58deb9cc3bd801507daad6c7c50c431e00cbcdeb8f597c8745923db"}'
		         + '],"bravo":['
		         +      '{"padNum":2,"padIdentifier":"ff38143fa9e8b2","pad":"73150e1f308c1e663c34eed86b24b8320ec3358aa3b7e58da15e6b1743c8ba21f5b7fb21d00ab2b815fbb2a82488987146b0c1b5cfc032a12cc9cef196a0cf26be47d38729c10fae1e9451adea841517d7bac6e109c7503fdb957d86225cacbf1badf312cef431c3622ad198dc7bfeeecb05e951d42a3542055da445d0dd6ac0efbaa739ce53052599a164bd8523ae55ad180585b22469fbe16f7550fbc648566e3314e8dde82de977599ba2602474d0c9b9d90358be0b9ff5","mac":"e6873d9507b5c03db8d4a73c4bea2173d245df7e8b899f6368b4f1790e152963214fc1b551ef54e3c4e5f6157fa1a6b6e0619e886d79ce8a3435e6d58b259381"},'
		         +      '{"padNum":3,"padIdentifier":"34b7267a052885","pad":"83b6fb7551e3aaa6c85e972127162eafd991db3474f0498438117a83e10b9c298215588a03138df5fe999329e8486868d9ed24ff38322c7a28331c46ed67cf76b3f888de390c234102430cd8cac0fe8fdc114e556600dd725a93a9fb023f27834c3aaa3c1d09c93f0289bd836560ed9dcc331be0dc4d3b7091b69db380fd784baa3803309699fff11f84402b49c357f3b6fe66ea205489e1aab1b9fdcff9fac26b6b3e9f6858fa63879d0e408e6453a1a8961f47d457a466bf","mac":"e7b58ba12d261e8370e2f2b903722e8b7d4cd397854ab7ce2918de53321af2b53078578befc7ec51b701650d9aa68092d519de8385e57da151806e5e956fb5ae"}'
	             + ']}');
		var padIndexMacs = dbCrypto.createMacOfAllDatabaseIndexes(keccakMacKey, skeinMacKey, userPads);
		var verifyTestA = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, userPads, padIndexMacs);
		
		// Test empty objects
		var verifyTestB = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, {}, padIndexMacs);
		var verifyTestC = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, userPads, {});
		
		// Test bad MAC key
		var badMacKeyHex = 'd7dff9b318515ff04134389ec3da7460f6927e321092c49e3a54d761d57b3d38eae1c0cc2af8aacb8169c9d682bb01a2c8788a5a489baaefd7f7841c80295c9c';
		var verifyTestD = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, badMacKeyHex, userPads, padIndexMacs);
		
		// Test bad pad index MAC
		var badPadIndexMacs = JSON.parse('{"alpha":"9c1aef5f3b614381b1e208e8927c85ef8d68c2f2e5877f059554d5b3b70be3b1d1db9468645badaec1afa585b9cad535976861b62dcc7864630f5dbfefe55d6e","bravo":"4e29c484d61568330d04bcf6a0acfef6e49547c063017a4e576279f313f69c23d0702aa2658f93bb6d3c7130b54657865bf9d87c20a3c6b8ac6997e1b47940c8"}');
		var verifyTestE = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, userPads, badPadIndexMacs);
		
		// Test re-ordered pads
		var reorderedUserPads = JSON.parse(
		                        '{"alpha":['
			                  +      '{"padNum":1,"padIdentifier":"1be37ed18a2fc3","pad":"223633c169312b271a736c11a04e2558be733aad32db7db7af3ee3ef2327496edff89932d83dce1407f91a47af94a3acb1ac32a63da73f945871e885da49dff63f11fd27188f9aa98aec83a87f47f1ba636dceab2dfc8b7d8ffec7f0c58f22f41d849a4f87bb08a43152a56985fcf2a9ec52b5830ba841995f4cb204e2d7cd7a74732871d5b80a47836f2c7d6f2c1612c591d7f82c0f46ae38ec9db2cc95b1df02545d03b493c3223def44c7319c4baee96c4aabe8331e945d","mac":"6396389c1ee1b6485b3f5b82da22f72bcdb385890b92e46c2091c7b9af860323d268f1b3e58deb9cc3bd801507daad6c7c50c431e00cbcdeb8f597c8745923db"},'
		                      +      '{"padNum":0,"padIdentifier":"cabeff2ffd746a","pad":"69ba77f22986ad250a9a30555d4234d34649cb540063bbaa205e0e03c3c77dc50aa3cca8d15e53d63095da5292c5a8d8fdfd1f26edaf9eaafaeba1dcecffe5efa4d6b645ecf48190209e1b0f1ba017d0f7bd25a8e54ba2002e951aa2ffa3d9ad96b831c4c5593e49d0affa9b86ad0b3850f91e8c8a925cd28369aba80f2bd058e0e019c1c52e6608f603c7c4eeff5c28df30b96367249efc082c9f219446dda96797fb82b6b6f42ce3d2c7f47fb9ac915d77f66868e288a29e","mac":"2223c18b198d9a949d94497f5dc7a69fe12dcf53766de3e5515e58e70d0318de6c365beca8fb0a5ccd579a02a3e920f43072b6b56ff3c0fd60db0fb713419e9b"}'
		                      + '],"bravo":['
		                      +      '{"padNum":2,"padIdentifier":"ff38143fa9e8b2","pad":"73150e1f308c1e663c34eed86b24b8320ec3358aa3b7e58da15e6b1743c8ba21f5b7fb21d00ab2b815fbb2a82488987146b0c1b5cfc032a12cc9cef196a0cf26be47d38729c10fae1e9451adea841517d7bac6e109c7503fdb957d86225cacbf1badf312cef431c3622ad198dc7bfeeecb05e951d42a3542055da445d0dd6ac0efbaa739ce53052599a164bd8523ae55ad180585b22469fbe16f7550fbc648566e3314e8dde82de977599ba2602474d0c9b9d90358be0b9ff5","mac":"e6873d9507b5c03db8d4a73c4bea2173d245df7e8b899f6368b4f1790e152963214fc1b551ef54e3c4e5f6157fa1a6b6e0619e886d79ce8a3435e6d58b259381"},'
		                      +      '{"padNum":3,"padIdentifier":"34b7267a052885","pad":"83b6fb7551e3aaa6c85e972127162eafd991db3474f0498438117a83e10b9c298215588a03138df5fe999329e8486868d9ed24ff38322c7a28331c46ed67cf76b3f888de390c234102430cd8cac0fe8fdc114e556600dd725a93a9fb023f27834c3aaa3c1d09c93f0289bd836560ed9dcc331be0dc4d3b7091b69db380fd784baa3803309699fff11f84402b49c357f3b6fe66ea205489e1aab1b9fdcff9fac26b6b3e9f6858fa63879d0e408e6453a1a8961f47d457a466bf","mac":"e7b58ba12d261e8370e2f2b903722e8b7d4cd397854ab7ce2918de53321af2b53078578befc7ec51b701650d9aa68092d519de8385e57da151806e5e956fb5ae"}'
		                      + ']}');
		var verifyTestF = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, reorderedUserPads, padIndexMacs);
		
		// Test swapped pads between users
		var swappedUserPads = JSON.parse(
		                      '{"alpha":['
		                    +      '{"padNum":2,"padIdentifier":"ff38143fa9e8b2","pad":"73150e1f308c1e663c34eed86b24b8320ec3358aa3b7e58da15e6b1743c8ba21f5b7fb21d00ab2b815fbb2a82488987146b0c1b5cfc032a12cc9cef196a0cf26be47d38729c10fae1e9451adea841517d7bac6e109c7503fdb957d86225cacbf1badf312cef431c3622ad198dc7bfeeecb05e951d42a3542055da445d0dd6ac0efbaa739ce53052599a164bd8523ae55ad180585b22469fbe16f7550fbc648566e3314e8dde82de977599ba2602474d0c9b9d90358be0b9ff5","mac":"e6873d9507b5c03db8d4a73c4bea2173d245df7e8b899f6368b4f1790e152963214fc1b551ef54e3c4e5f6157fa1a6b6e0619e886d79ce8a3435e6d58b259381"},'
		                    +      '{"padNum":3,"padIdentifier":"34b7267a052885","pad":"83b6fb7551e3aaa6c85e972127162eafd991db3474f0498438117a83e10b9c298215588a03138df5fe999329e8486868d9ed24ff38322c7a28331c46ed67cf76b3f888de390c234102430cd8cac0fe8fdc114e556600dd725a93a9fb023f27834c3aaa3c1d09c93f0289bd836560ed9dcc331be0dc4d3b7091b69db380fd784baa3803309699fff11f84402b49c357f3b6fe66ea205489e1aab1b9fdcff9fac26b6b3e9f6858fa63879d0e408e6453a1a8961f47d457a466bf","mac":"e7b58ba12d261e8370e2f2b903722e8b7d4cd397854ab7ce2918de53321af2b53078578befc7ec51b701650d9aa68092d519de8385e57da151806e5e956fb5ae"}'
		                    + '],"bravo":['
		                    +     '{"padNum":0,"padIdentifier":"cabeff2ffd746a","pad":"69ba77f22986ad250a9a30555d4234d34649cb540063bbaa205e0e03c3c77dc50aa3cca8d15e53d63095da5292c5a8d8fdfd1f26edaf9eaafaeba1dcecffe5efa4d6b645ecf48190209e1b0f1ba017d0f7bd25a8e54ba2002e951aa2ffa3d9ad96b831c4c5593e49d0affa9b86ad0b3850f91e8c8a925cd28369aba80f2bd058e0e019c1c52e6608f603c7c4eeff5c28df30b96367249efc082c9f219446dda96797fb82b6b6f42ce3d2c7f47fb9ac915d77f66868e288a29e","mac":"2223c18b198d9a949d94497f5dc7a69fe12dcf53766de3e5515e58e70d0318de6c365beca8fb0a5ccd579a02a3e920f43072b6b56ff3c0fd60db0fb713419e9b"},'
		                    +     '{"padNum":1,"padIdentifier":"1be37ed18a2fc3","pad":"223633c169312b271a736c11a04e2558be733aad32db7db7af3ee3ef2327496edff89932d83dce1407f91a47af94a3acb1ac32a63da73f945871e885da49dff63f11fd27188f9aa98aec83a87f47f1ba636dceab2dfc8b7d8ffec7f0c58f22f41d849a4f87bb08a43152a56985fcf2a9ec52b5830ba841995f4cb204e2d7cd7a74732871d5b80a47836f2c7d6f2c1612c591d7f82c0f46ae38ec9db2cc95b1df02545d03b493c3223def44c7319c4baee96c4aabe8331e945d","mac":"6396389c1ee1b6485b3f5b82da22f72bcdb385890b92e46c2091c7b9af860323d268f1b3e58deb9cc3bd801507daad6c7c50c431e00cbcdeb8f597c8745923db"}'
		                    + ']}');
		var verifyTestG = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, swappedUserPads, padIndexMacs);
		
		// Test pad list being added to with a bad pad
		var addedUserPads = JSON.parse(
		                    '{"alpha":['
		                  +      '{"padNum":0,"padIdentifier":"cabeff2ffd746a","pad":"69ba77f22986ad250a9a30555d4234d34649cb540063bbaa205e0e03c3c77dc50aa3cca8d15e53d63095da5292c5a8d8fdfd1f26edaf9eaafaeba1dcecffe5efa4d6b645ecf48190209e1b0f1ba017d0f7bd25a8e54ba2002e951aa2ffa3d9ad96b831c4c5593e49d0affa9b86ad0b3850f91e8c8a925cd28369aba80f2bd058e0e019c1c52e6608f603c7c4eeff5c28df30b96367249efc082c9f219446dda96797fb82b6b6f42ce3d2c7f47fb9ac915d77f66868e288a29e","mac":"2223c18b198d9a949d94497f5dc7a69fe12dcf53766de3e5515e58e70d0318de6c365beca8fb0a5ccd579a02a3e920f43072b6b56ff3c0fd60db0fb713419e9b"},'
		                  +      '{"padNum":1,"padIdentifier":"1be37ed18a2fc3","pad":"223633c169312b271a736c11a04e2558be733aad32db7db7af3ee3ef2327496edff89932d83dce1407f91a47af94a3acb1ac32a63da73f945871e885da49dff63f11fd27188f9aa98aec83a87f47f1ba636dceab2dfc8b7d8ffec7f0c58f22f41d849a4f87bb08a43152a56985fcf2a9ec52b5830ba841995f4cb204e2d7cd7a74732871d5b80a47836f2c7d6f2c1612c591d7f82c0f46ae38ec9db2cc95b1df02545d03b493c3223def44c7319c4baee96c4aabe8331e945d","mac":"6396389c1ee1b6485b3f5b82da22f72bcdb385890b92e46c2091c7b9af860323d268f1b3e58deb9cc3bd801507daad6c7c50c431e00cbcdeb8f597c8745923db"},'
		                  +      '{"padNum":2,"padIdentifier":"923ca572cd324f","pad":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","mac":"6396389c1ee1b6485b3f5b82da22f72bcdb385890b92e46c2091c7b9af860323d268f1b3e58deb9cc3bd801507daad6c7c50c431e00cbcdeb8f597c8745923db"}'
		                  + '],"bravo":['
		                  +      '{"padNum":2,"padIdentifier":"ff38143fa9e8b2","pad":"73150e1f308c1e663c34eed86b24b8320ec3358aa3b7e58da15e6b1743c8ba21f5b7fb21d00ab2b815fbb2a82488987146b0c1b5cfc032a12cc9cef196a0cf26be47d38729c10fae1e9451adea841517d7bac6e109c7503fdb957d86225cacbf1badf312cef431c3622ad198dc7bfeeecb05e951d42a3542055da445d0dd6ac0efbaa739ce53052599a164bd8523ae55ad180585b22469fbe16f7550fbc648566e3314e8dde82de977599ba2602474d0c9b9d90358be0b9ff5","mac":"e6873d9507b5c03db8d4a73c4bea2173d245df7e8b899f6368b4f1790e152963214fc1b551ef54e3c4e5f6157fa1a6b6e0619e886d79ce8a3435e6d58b259381"},'
		                  +      '{"padNum":3,"padIdentifier":"34b7267a052885","pad":"83b6fb7551e3aaa6c85e972127162eafd991db3474f0498438117a83e10b9c298215588a03138df5fe999329e8486868d9ed24ff38322c7a28331c46ed67cf76b3f888de390c234102430cd8cac0fe8fdc114e556600dd725a93a9fb023f27834c3aaa3c1d09c93f0289bd836560ed9dcc331be0dc4d3b7091b69db380fd784baa3803309699fff11f84402b49c357f3b6fe66ea205489e1aab1b9fdcff9fac26b6b3e9f6858fa63879d0e408e6453a1a8961f47d457a466bf","mac":"e7b58ba12d261e8370e2f2b903722e8b7d4cd397854ab7ce2918de53321af2b53078578befc7ec51b701650d9aa68092d519de8385e57da151806e5e956fb5ae"}'
		                  + ']}');
		var verifyTestH = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, addedUserPads, padIndexMacs);
		
		// Test invalid removal of pads
		var removedUserPads = JSON.parse(
		                     '{"alpha":[],"bravo":['
		                    +      '{"padNum":2,"padIdentifier":"ff38143fa9e8b2","pad":"73150e1f308c1e663c34eed86b24b8320ec3358aa3b7e58da15e6b1743c8ba21f5b7fb21d00ab2b815fbb2a82488987146b0c1b5cfc032a12cc9cef196a0cf26be47d38729c10fae1e9451adea841517d7bac6e109c7503fdb957d86225cacbf1badf312cef431c3622ad198dc7bfeeecb05e951d42a3542055da445d0dd6ac0efbaa739ce53052599a164bd8523ae55ad180585b22469fbe16f7550fbc648566e3314e8dde82de977599ba2602474d0c9b9d90358be0b9ff5","mac":"e6873d9507b5c03db8d4a73c4bea2173d245df7e8b899f6368b4f1790e152963214fc1b551ef54e3c4e5f6157fa1a6b6e0619e886d79ce8a3435e6d58b259381"},'
		                    +      '{"padNum":3,"padIdentifier":"34b7267a052885","pad":"83b6fb7551e3aaa6c85e972127162eafd991db3474f0498438117a83e10b9c298215588a03138df5fe999329e8486868d9ed24ff38322c7a28331c46ed67cf76b3f888de390c234102430cd8cac0fe8fdc114e556600dd725a93a9fb023f27834c3aaa3c1d09c93f0289bd836560ed9dcc331be0dc4d3b7091b69db380fd784baa3803309699fff11f84402b49c357f3b6fe66ea205489e1aab1b9fdcff9fac26b6b3e9f6858fa63879d0e408e6453a1a8961f47d457a466bf","mac":"e7b58ba12d261e8370e2f2b903722e8b7d4cd397854ab7ce2918de53321af2b53078578befc7ec51b701650d9aa68092d519de8385e57da151806e5e956fb5ae"}'
	                        + ']}');
		var verifyTestI = dbCrypto.verifyAllUserDatabaseIndexes(keccakMacKey, skeinMacKey, removedUserPads, padIndexMacs);
		
		ok(verifyTestA === true, 'Valid pad database should validate');
		ok(verifyTestB === false, 'Invalid userPads object should not validate');
		ok(verifyTestC === false, 'Invalid padIndexMacs object should not validate');
		ok(verifyTestD === false, 'Invalid MAC key should should equal not validate');
		ok(verifyTestE === false, 'Invalid pad index MAC for alpha should not validate');
		ok(verifyTestF === false, 'Re-ordered pads for alpha should not validate');
		ok(verifyTestG === false, 'Swapped pads between users should not validate');
		ok(verifyTestH === false, 'Pad database with additional invalid pads should not validate');
		ok(verifyTestI === false, 'Pad database with valid pads removed should not validate');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * Test random numbers between minimum and maximum are in correct range
	 * ------------------------------------------------------------------
	 */
	
	QUnit.test("Test random numbers between minimum and maximum are in correct range", function()
	{
		// Test small maximums
		var smallIntA = common.getRandomIntInRange(0, 1);	// 0 or 1 possible
		var smallIntB = common.getRandomIntInRange(0, 2);	// 0 or 1 or 2 possible

		// Test maximum
		var smallNumber = common.getRandomIntInRange(0, 255);
		var mediumNumber = common.getRandomIntInRange(0, 65535);
		var largeNumber = common.getRandomIntInRange(0, 4294967295);
		// var tooBigNumber = common.getRandomIntInRange(0, 4294967296);	// Throws exception (as it should)

		// Test fixed limit
		var numberBetween0and10 = common.getRandomIntInRange(0, 10);
		var numberBetween0and20k = common.getRandomIntInRange(0, 20000);
		var numberBetween0and300k = common.getRandomIntInRange(0, 300000);

		// Test min and max
		var numberBetween5and10 = common.getRandomIntInRange(5, 10);
		var numberBetween10kAnd20k = common.getRandomIntInRange(10000, 20000);
		var numberBetween150kAnd300k = common.getRandomIntInRange(150000, 300000);
		var numberBetween1kAnd90k = common.getRandomIntInRange(1000, 90000);
		
		
		ok(((smallIntA >= 0) && (smallIntA <= 1)), '0 - 1: ' + smallIntA.toString());
		ok(((smallIntB >= 0) && (smallIntB <= 2)), '0 - 2: ' + smallIntB.toString());
		
		ok(smallNumber <= 255, '0 - 255: ' + smallNumber);
		ok(mediumNumber <= 65535, '0 - 65,535: ' + mediumNumber);
		ok(largeNumber <= 4294967295, '0 - 4,294,967,295: ' + largeNumber);
		
		ok(numberBetween0and10 <= 10, '0 - 10: ' + numberBetween0and10);
		ok(numberBetween0and20k <= 20000, '0 - 20,000: ' + numberBetween0and20k);
		ok(numberBetween0and300k <= 300000, '0 - 300,000: ' + numberBetween0and300k);
		
		ok(numberBetween5and10 >= 5 && numberBetween5and10 <= 10, '5 - 10: ' + numberBetween5and10);
		ok(numberBetween10kAnd20k >= 10000 && numberBetween10kAnd20k <= 20000, '10,000 - 20,000: ' + numberBetween10kAnd20k);
		ok(numberBetween150kAnd300k >= 150000 && numberBetween150kAnd300k <= 300000, '150,000 - 300,000: ' + numberBetween150kAnd300k);
		ok(numberBetween1kAnd90k >= 1000 && numberBetween1kAnd90k <= 90000, '1,000 - 90,000: ' + numberBetween1kAnd90k);
	});
		
	
	/*
	 * ------------------------------------------------------------------
	 * Calculate passphrase strength in bits
	 * ------------------------------------------------------------------
	 */
		
	QUnit.test("Calculate passphrase strength in bits", function()
	{
		var testPassphraseA = 'AcZ0-fK.LvSx80';		// 14 chars
		var testKeccakIterationsA = 0;
		var testSkeinIterationsA = 10000;
		var testResultA = dbCrypto.calculatePassphraseStrengthInBits(testPassphraseA, testKeccakIterationsA, testSkeinIterationsA);
		var testResultExpectedA = 96;		// 96 bits
		
		var testPassphraseB = 'AcZ0-fK.LvSx80Db2jwu~",|sx0gMxQf87rEaz03m';		// 41 chars
		var testKeccakIterationsB = 10000;
		var testSkeinIterationsB = 10000;
		var testResultB = dbCrypto.calculatePassphraseStrengthInBits(testPassphraseB, testKeccakIterationsB, testSkeinIterationsB);
		var testResultExpectedB = 258;		// 256 bits
		
		// Test strings passed for iterations to check still correct calculation
		var testPassphraseC = 'Edward J. Snowden is a hero, not a traitor.';		// 43 chars
		var testKeccakIterationsC = '10000';
		var testSkeinIterationsC = '10000';
		var testResultC = dbCrypto.calculatePassphraseStrengthInBits(testPassphraseC, testKeccakIterationsC, testSkeinIterationsC);
		var testResultExpectedC = 270;		// 270 bits
			
		ok(testResultA === testResultExpectedA, 'Passphrase: ' + testPassphraseA + ' with ' + testKeccakIterationsA + ' + ' + testSkeinIterationsA + ' iterations and ' + testResultA + ' bits strength should be ' + testResultExpectedA + ' bits');
		ok(testResultB === testResultExpectedB, 'Passphrase: ' + testPassphraseB + ' with ' + testKeccakIterationsB + ' + ' + testSkeinIterationsB + ' iterations and ' + testResultB + ' bits strength should be ' + testResultExpectedB + ' bits');
		ok(testResultC === testResultExpectedC, 'Passphrase: ' + testPassphraseC + ' with "' + testKeccakIterationsC + '" + "' + testSkeinIterationsC + '" iterations and ' + testResultC + ' bits strength should be ' + testResultExpectedC + ' bits');
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * TRNG - Test getting the least significant bits of a pixel
	 * ------------------------------------------------------------------
	 */
		
	QUnit.test("TRNG - Test getting the least significant bits from an image", function()
	{
		// Mock RGBA pixel
		var bytesTestA = [0, 1, 2, 3];	// 00000000, 00000001, 00000010, 00000011
		var expectedBitTestA = '1';		// 0 XOR 1 XOR 0   -- ignore the last byte because alpha channel not used
		var randomBitTestA = trngWorker.getLeastSigBitsFromArray(bytesTestA);
		
		// Mock two RGBA pixels (11, 52, 143, 0) and (14, 222, 167, 0)
		var bytesTestB = [11, 52, 143, 0, 14, 222, 167, 0];		// 00001011, 00110100, 10001111, 00000000, 00001110, 11011110, 10100111, 00000000
		var expectedBitsTestB = '01';	// (1 XOR 0 XOR 1) || (0 XOR 0 XOR 1)  -- ignore every 4th byte because alpha channel not used
		var randomBitsTestB = trngWorker.getLeastSigBitsFromArray(bytesTestB);
		
		ok(randomBitTestA === expectedBitTestA, 'Random bit: ' + randomBitTestA + ' should be ' + expectedBitTestA);
		ok(randomBitsTestB === expectedBitsTestB, 'Random bits: ' + randomBitsTestB + ' should be ' + expectedBitsTestB);
	});
	
	
	/*
	 * ------------------------------------------------------------------
	 * TRNG - Test basic Von Nuemann extractor
	 * ------------------------------------------------------------------
	 */
		
	QUnit.test("TRNG - Test basic Von Nuemann extractor", function()
	{
		var inputBits = '10110010001100011111101100000011';		// 178, 49, 251, 3 (10110010 || 00110001 || 11111011 || 00000011)
		var expectedOutputBits = '1101';	// 10 -> 1, 11 -> discard, 00 -> discard, 10 -> 1, 00 -> discard, 11 -> discard, 00 -> discard, 01 -> 0, 11 -> discard, 11 -> discard, 10 -> 1, 11 -> discard, 00 -> discard, 00 -> discard, 11 -> discard
		var outputBits = trngWorker.vonNeumannExtractor(inputBits);
		
		ok(outputBits === expectedOutputBits, 'Input bits ' + inputBits + ' with result ' + outputBits + ' should equal ' + expectedOutputBits);
	});
});