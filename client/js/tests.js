/*!
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Workers are supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webWorkersSupported = common.checkWebWorkerSupported();
	
	test("Test if HTML5 Web Workers are supported in this browser", function()
	{
		ok(webWorkersSupported === true);
	});
	
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Crypto API is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webCryptoApiSupported = common.checkWebCryptoApiSupported();
	
	test("Test if HTML5 Web Crypto API is supported in this browser", function()
	{
		ok(webCryptoApiSupported === true);
	});
	
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Offline Web Application Cache is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var offlineWebApplicationCacheSupported = common.checkOfflineWebApplicationSupported();
	
	test("Test if HTML5 Offline Web Application Cache is supported in this browser", function()
	{
		ok(offlineWebApplicationCacheSupported === true);
	});
	
	
	/**
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
	
	
	/**
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
		
	
	/**
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
		
	/**
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
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Convert the binary timestamp back to an integer then a date
	 * ------------------------------------------------------------------
	 */
	
	var convertedFromBinaryTimestamp = common.convertBinaryToInteger(timestampBinaryB);
		
	test("Convert the binary timestamp back to an integer then a date", function()
	{
		ok(convertedFromBinaryTimestamp == plaintextMessageTimestamp, convertedFromBinaryTimestamp);
	});
	
	
	/**
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
		
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Encrypt the message parts with the pad message parts
	 * ------------------------------------------------------------------
	 */
	
	// Test basic truth table: wikipedia.org/wiki/Xor#Truth_table
	var testPlaintext = '0011';
	var testPad = '0101';
	var testCiphertext = common.encryptOrDecrypt(testPad, testPlaintext);
	
	// Test encrypting the plaintext parts
	var encryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, messagePartsBinaryReversed);
	var encryptedMessagePartsBinaryLength = encryptedMessagePartsBinary.length;
		
	test("Encrypt the message parts with the pad message parts", function()
	{
		ok(testCiphertext === '0110', testCiphertext);
		ok(encryptedMessagePartsBinary === '01011001001010011111110111101000111000111110001010010011101101010010011111000011111001001100111110110111011010001001110111000110101100100111101111000101100010110111001010011111000010000110100000100010010000101011111001111010111111101001110100100110101101010101000101010010001101000001100100000011010100101110010001000011111001010000111111010001001000001011111000111000101101011001000111001001110110101010001000001111100001111010111011111011000100001101000000011111010000101110010000010100101110011010100010110000110001000001000000010001001001000111000010101000000001001111001001000101111100111000010010001111101110011101100101111110010010010110000110110111011010101100111011011110100110000010001100101011011001111011101001010010001111001110011011001000100110010001010110111011010100000001101111001011100110110001110101010100110000001001010100001011000010100001011101111011001000100010011011111001100100110010101000110110101001000000101001011101100001001110101001110111', encryptedMessagePartsBinary);
		ok(encryptedMessagePartsBinaryLength === common.totalMessagePartsSizeBinary, encryptedMessagePartsBinaryLength);
	});
	
	
	/**
	 * ------------------------------------------------------------------
	 * Combine pad identifier and the ciphertext message parts
	 * ------------------------------------------------------------------
	 */
	
	var completeCiphertextBinary = common.combinePadIdentifierAndCiphertext(padIdentifier, encryptedMessagePartsBinary);
		
	test("Combine pad identifier and the ciphertext message parts", function()
	{
		ok(completeCiphertextBinary.length === common.padIdentifierSizeBinary + common.totalMessagePartsSizeBinary);
	});
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Decrypt binary ciphertext message parts to binary plaintext message parts
	 * ------------------------------------------------------------------
	 */
	
	var decryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, ciphertextMessageParts);
	var decryptedMessagePartsBinaryLength = decryptedMessagePartsBinary.length;;
	
	test("Decrypt ciphertext message parts to plaintext message parts binary", function()
	{
		ok(decryptedMessagePartsBinary === messagePartsBinaryReversed, decryptedMessagePartsBinary);
		ok(decryptedMessagePartsBinaryLength === common.totalMessagePartsSizeBinary, decryptedMessagePartsBinaryLength);
	});
	
	
	/**
	 * ------------------------------------------------------------------
	 * Reverse binary plaintext message parts back to original order
	 * ------------------------------------------------------------------
	 */
	
	var decryptedUnreversedMessagePartsBinary = common.reverseMessageParts(pad, decryptedMessagePartsBinary);
		
	test("Reverse binary plaintext message parts back to original order", function()
	{
		ok(decryptedUnreversedMessagePartsBinary === messagePartsBinary, decryptedUnreversedMessagePartsBinary);
	});
	
	
	/**
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
	
	
	/**
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


	/**
	 * ------------------------------------------------------------------
	 * Basic encryption and decryption of all possible ASCII characters
	 * ------------------------------------------------------------------
	 */
	var binaryPad = common.convertTextToBinary(pad);	
	var binaryPlaintext = common.convertTextToBinary(common.allPossibleChars.join(''));	
	var binaryEncryptedMessage = common.encryptOrDecrypt(binaryPad, binaryPlaintext);
	var hexadecimalEncryptedMessage = common.convertBinaryToHexadecimal(binaryEncryptedMessage);
	var binaryDecryptedMessageFromHex = common.convertHexadecimalToBinary(hexadecimalEncryptedMessage);
	var binaryDecryptedMessage = common.encryptOrDecrypt(binaryPad, binaryDecryptedMessageFromHex);
	var asciiPlaintext = common.convertBinaryToText(binaryDecryptedMessage);
	
	test("Basic encryption and decryption of all possible ASCII characters", function()
	{
		ok(asciiPlaintext === common.allPossibleChars.join(''), asciiPlaintext);
	});
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
		console.log('Valid response: ' + validResponse.toString());
		console.log(responseData);
	});	
	//*/
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
		
	
	/**
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
	
	
	/**
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
		
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Test Keccak PBKDF with 100 iterations
	 * ------------------------------------------------------------------
	 */	
	
	var keccakStartTime = new Date();
	var keccakPassword = 'password';
	var keccakSalt = '598627c78963db1ccfd0f9807630fcd8231b9233d7b621233a6ce798d8cc536766a701d9b4e5ac9d30f835de094e79cb61688fe2a5ff5dda0fe14a716836f6b7b4004eeb5c01d4b64abf251066f067a6263f7f68560ad1d156aa64f88fe6b411';
	var keccakIterations = 100;
	var keccakDerivedKey = dbCrypto.keccakPasswordDerivation(keccakPassword, keccakSalt, keccakIterations);
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
	
	
	/**
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
	
	
	/**
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
	var cascadeExpectedDerivedKey = 'c90559e5c616ebcdecd67b8c0121cfd3ea82dc9e2e973dd7a27101bcf590d76a8686fa76cf4b4fe442d8d3cb282d479b2e826628d161b3db140aade1f1183fee';
		
	test("Test Cascade PBKDF with PBKDF2-Keccak and Skein PBKDF with 100 iterations each", function()
	{
		ok(cascadeDerivedKeyLength === 128, 'Derived key length ' + cascadeDerivedKeyLength + ' should equal 128');
		ok(cascadeDerivedKey === cascadeExpectedDerivedKey, 'Derived key ' + cascadeDerivedKey + ' should equal ' + cascadeExpectedDerivedKey + '. Time taken: ' + cascadeMillisecondsTaken + 'ms.');
	});
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
		
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
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
	
	
	/**
	 * ------------------------------------------------------------------
	 * Test TRNG photo randomness extractor
	 * ------------------------------------------------------------------
	 */
		
	QUnit.test("Test TRNG photo randomness extractor", function()
	{
		// Run the Hash Extractor on the entropy
		var hashAlgorithm = 'skein-512';
		var entropyInputEstimatePerPixel = 1;
		var dataset = [21,96,177,22,94,178,22,96,180,23,96,179,24,95,180,25,95,179,23,96,180,24,97,178,23,96,180,24,96,178,26,95,179,24,94,179,26,95,177,25,96,178,24,95,178,23,96,178,24,94,179,24,95,178,25,95,180,23,96,178,26,94,179,24,95,178,23,96,179,25,95,179,25,94,180,26,95,179,24,96,179,24,96,180,23,96,181,24,96,181,25,97,180,23,97,181,22,97,180,23,98,181,22,98,182,25,98,182,24,97,182,24,98,182,26,99,183,24,99,183,24,98,183,24,99,183,25,100,184,26,100,184,24,101,185,26,100,185,24,101,184,26,101,185,26,102,185,25,102,185,27,103,186,27,104,186,27,103,187,26,104,187,28,105,188,26,104,188,28,104,188,26,106,188,28,106,187,28,107,188,30,106,189,29,107,190,29,107,189,30,108,190,29,108,191,28,108,190,28,110,191,27,110,190,29,110,191,29,111,190,30,112,190,34,111,186,23,99,180,26,98,183,28,97,183,26,98,183,28,98,182,27,99,183,28,98,183,26,99,182,29,98,183,30,99,182,29,98,181,30,98,181,29,98,183,30,97,181,29,98,182,28,97,183,27,97,182,28,97,183,27,98,182,29,98,183,28,97,183,29,98,183,29,97,182,28,98,183,29,98,182,29,97,183,27,99,183,28,99,183,30,98,185,28,98,185,27,99,184,27,100,185,29,100,185,29,99,187,27,101,185,29,100,186,28,101,186,28,102,186,29,102,187,28,101,186,30,102,188,30,102,187,28,103,187,29,102,188,28,103,189,29,103,188,30,103,190,28,105,189,30,104,189,29,106,191,33,105,190,31,107,189,30,107,191,29,108,190,32,107,191,30,107,191,30,109,192,32,109,192,33,108,192,33,111,192,34,109,192,32,110,193,34,110,194,34,110,193,32,111,194,33,111,194,34,112,195,34,114,195,35,114,195,42,117,194,40,115,192,38,117,193,42,117,189,25,102,181,29,99,185,29,99,186,30,101,185,31,100,184,30,100,185,31,101,184,29,101,184,31,101,183,30,100,182,32,99,183,30,101,182,30,99,184,32,100,184,31,100,183,31,101,183,32,100,183,29,100,183,30,99,184,30,100,184,28,100,184,29,101,183,32,99,183,29,100,185,30,100,185,29,100,184,30,101,185,29,101,185,31,101,186,29,101,184,30,100,186,29,102,187,29,102,186,29,101,187,29,102,187,31,102,187,30,103,187,28,103,188,30,103,187,31,103,188,31,104,189,32,104,190,31,104,189,31,105,189,30,107,191,32,107,191,30,108,190,33,107,191,31,107,192,32,108,191,32,108,193,32,109,192,34,109,193,34,110,192,33,111,194,34,111,193,33,112,193,35,112,194,36,112,192,35,111,194,35,113,193,37,114,195,35,113,193,34,115,195,36,113,196,38,115,196,38,114,196,37,117,194,43,120,194,49,122,192,41,119,193,46,120,192,39,118,191,29,104,183,32,101,187,30,102,187,31,103,186,32,102,186,30,103,187,32,103,185,34,103,186,32,103,186,32,102,185,33,102,184,33,101,186,31,102,185,33,102,185,32,102,184,33,102,184,32,102,185,33,102,185,33,101,184,31,102,186,31,102,187,32,101,187,32,103,186,31,102,187,30,103,187,29,103,186,32,103,187,32,102,187,31,103,187,32,103,188,31,104,189,31,103,188,32,104,189,31,104,189,31,104,190,31,105,190,33,105,190,31,106,190,32,106,191,33,106,191,33,106,190,31,107,192,33,107,191,32,106,191,32,109,192,33,108,191,33,109,193,34,111,193,34,109,193,33,111,194,35,111,193,33,112,195,35,111,195,36,113,195,34,113,195,37,113,196,36,114,196,39,114,195,38,115,196,37,116,197,39,115,195,36,117,196,39,117,197,38,116,196,39,117,195,39,118,197,42,120,195,43,121,195,45,122,194,45,121,195,45,123,192,45,122,192,30,107,187,33,105,189,34,105,189,32,106,188,35,105,189,33,105,190,34,105,189,34,106,187,34,105,188,33,105,187,32,105,188,34,104,188,33,105,187,34,105,188,33,105,187,32,105,188,31,105,188,34,105,187,34,103,189,32,105,189,32,104,190,34,104,189,33,105,189,33,104,189,34,105,190,33,104,190,32,106,189,33,105,190,31,106,191,33,106,191,34,105,192,32,106,191,32,107,190,34,108,191,32,107,192,33,108,192,34,108,192,32,109,192,33,109,193,34,109,193,34,110,192,33,111,193,35,111,194,36,110,194,35,111,195,37,111,195,35,111,196,35,113,196,38,112,196,36,114,197,36,113,196,36,115,197,37,115,197,37,116,197,38,115,198,39,117,199,38,117,198,40,118,200,40,118,198,40,118,199,41,118,198,41,119,199,40,119,199,42,119,198,39,120,200,39,122,200,41,121,199,43,122,199,44,121,199,43,121,199,42,122,200,44,123,197,44,124,197,31,110,190,34,108,192,35,108,192,35,109,192,36,108,191,38,107,192,36,109,191,34,109,190,34,108,191,36,109,189,33,108,191,36,108,189,35,108,191,33,108,191,35,108,190,34,107,192,37,107,191,33,108,191,34,107,191,33,107,192,36,106,192,34,108,192,35,108,192,33,108,192,34,107,192,35,108,193,36,108,193,32,108,193,35,108,192,33,109,193,35,108,193,35,108,194,34,109,193,35,109,194,36,110,194,35,111,195,34,111,195,36,111,196,35,112,196,38,112,196,36,113,196,35,114,196,37,114,197,39,112,198,36,115,198,35,115,198,38,115,198,39,115,199,39,116,199,39,117,200,38,117,200,40,118,200,39,117,199,41,119,201,42,120,200,40,121,202,41,122,201,42,122,201,43,122,202,46,122,202,44,123,202,44,123,203,43,123,202,44,123,201,44,124,202,45,123,201,43,124,203,46,124,202,43,125,201,43,125,203,46,125,202,44,126,201,47,127,200,49,127,198,34,112,192,34,111,194,37,112,195,36,112,193,39,111,194,36,112,194,37,112,193,36,111,194,36,112,194,37,111,194,37,111,193,37,110,195,35,111,193,36,111,194,36,110,194,35,110,194,36,109,194,35,110,194,36,110,194,36,110,195,34,111,194,37,110,195,36,110,196,36,110,194,37,111,196,37,111,194,37,111,195,36,111,195,35,112,196,37,111,196,37,113,196,36,114,197,38,114,197,36,115,197,37,115,198,38,115,198,39,116,199,36,116,199,38,117,199,37,117,200,40,118,201,38,119,201,39,119,201,40,119,201,41,119,202,39,120,202,42,120,202,41,121,203,41,122,203,44,122,203,43,123,203,43,124,204,45,125,204,44,125,203,46,127,204,48,127,205,47,127,205,48,126,205,47,127,205,48,127,204,47,127,204,47,128,204,49,128,205,46,129,204,47,128,205,46,129,204,48,129,204,48,129,205,49,130,203,50,130,203,53,130,199,37,116,196,38,114,198,37,115,198,39,114,196,38,116,198,38,114,197,38,115,197,39,114,197,40,114,197,39,114,197,39,112,197,39,113,197,37,113,195,38,113,196,38,113,197,39,113,196,38,114,197,40,113,198,39,112,197,38,114,197,39,114,197,39,113,197,37,114,198,38,115,197,37,115,197,39,114,198,38,115,198,40,116,199,39,116,199,39,117,198,37,117,200,39,118,200,40,118,201,39,118,200,38,119,200,40,118,201,39,120,201,39,120,202,40,120,202,40,121,202,42,121,202,41,122,203,42,122,203,40,122,204,43,122,204,41,123,205,44,124,205,43,124,205,43,125,206,44,126,206,46,126,205,47,127,206,46,129,207,52,130,206,51,132,207,53,135,207,57,135,208,56,135,208,54,133,206,60,134,208,60,137,206,61,138,208,61,139,208,64,138,208,62,137,207,54,133,207,59,138,208,58,135,207,55,135,206,65,137,200,74,140,198,74,141,193,39,119,199,39,119,201,38,119,201,40,119,201,39,118,200,40,118,200,41,118,200,41,117,200,40,117,200,40,118,199,39,117,200,41,116,200,40,116,199,39,115,199,40,116,199,40,117,199,41,116,199,40,116,199,40,117,200,40,116,200,40,117,200,41,117,200,40,117,200,41,118,200,41,117,201,40,118,201,41,118,201,40,119,201,41,119,201,39,119,201,41,119,202,41,120,203,41,121,203,42,120,204,42,121,203,41,121,204,42,122,204,41,123,205,41,124,205,42,124,205,45,123,206,42,125,206,44,125,207,44,126,207,44,127,207,47,127,208,46,128,208,47,129,209,49,130,209,49,131,209,51,132,210,61,138,210,81,150,212,108,168,218,127,181,221,131,182,223,120,176,220,94,158,210,103,158,205,105,161,206,109,165,208,113,168,209,112,166,211,102,160,205,93,154,200,92,156,201,98,161,207,93,155,205,77,143,199,74,141,198,65,139,200,40,123,201,42,121,204,41,122,204,43,121,204,41,122,203,41,122,202,44,121,202,42,121,202,43,121,202,44,120,202,43,120,202,45,119,202,41,119,202,43,119,202,42,120,202,42,119,203,41,120,201,43,120,202,42,120,202,44,121,202,42,120,203,42,121,203,42,120,203,43,121,203,40,122,202,43,121,204,43,122,204,42,122,204,43,123,205,43,122,204,44,123,205,44,124,206,43,124,206,45,124,206,45,125,207,45,126,207,45,127,208,44,127,208,46,127,209,46,127,208,46,128,209,45,129,210,47,130,210,48,130,211,49,132,211,48,132,212,50,133,212,52,134,211,54,135,211,87,154,211,126,175,216,139,186,222,146,192,225,145,192,223,151,197,227,144,191,224,127,178,214,112,167,206,110,163,203,109,163,203,110,165,204,109,164,203,113,168,208,99,156,198,91,151,196,98,157,199,96,159,201,92,155,201,93,159,207,58,139,205,42,126,205,43,125,207,44,124,207,45,125,206,45,124,205,43,124,205,46,124,206,47,124,205,46,123,203,47,123,205,46,123,205,46,123,204,44,123,204,44,124,204,45,123,204,43,123,204,46,123,205,43,123,204,45,124,205,46,124,205,44,124,205,43,124,205,44,124,206,46,124,206,44,124,206,43,125,207,45,125,207,44,125,207,46,126,207,45,126,206,45,126,208,44,127,207,46,127,208,45,127,209,47,128,209,46,127,209,46,128,210,47,129,210,48,129,211,48,130,211,49,130,210,53,131,208,50,132,210,49,132,212,50,133,213,50,134,212,49,135,214,49,136,212,54,137,213,60,141,214,68,145,213,78,146,207,108,162,206,123,171,209,130,179,213,123,173,209,111,163,205,113,165,205,109,162,203,113,164,204,112,165,205,108,161,202,110,164,203,113,167,204,111,165,202,108,162,200,101,157,197,91,151,194,87,146,189,87,148,192,88,152,195,87,152,197,69,143,196,44,130,208,47,128,210,47,129,210,49,128,210,47,128,209,49,128,209,47,128,208,47,128,209,49,127,206,50,127,206,48,128,207,49,127,205,46,127,207,47,127,205,46,127,206,45,127,207,47,127,207,49,127,206,47,127,207,48,127,207,48,127,208,47,128,209,48,128,208,46,128,208,47,128,209,48,128,209,47,129,209,46,129,209,47,129,209,48,129,210,48,130,210,49,130,211,49,130,210,48,131,211,49,131,212,50,131,212,51,132,212,50,132,213,51,133,213,52,133,214,51,134,214,52,134,213,55,134,210,63,135,206,56,135,211,55,136,212,54,137,214,54,137,215,54,139,215,70,145,213,95,156,212,123,172,216,128,178,217,102,157,203,107,159,204,105,159,203,102,158,201,107,160,201,115,165,205,123,172,208,120,168,206,119,170,206,120,171,206,116,169,202,110,165,201,106,161,199,98,156,194,88,148,188,80,143,187,78,139,184,82,142,186,80,143,188,76,138,186,69,134,184,46,134,210,51,131,212,48,132,212,49,132,211,50,132,210,52,131,209,50,132,210,51,132,209,51,132,208,49,131,209,51,131,208,50,131,209,49,131,208,49,131,209,50,130,209,48,130,209,47,130,210,49,131,211,49,131,210,50,131,210,49,131,211,48,132,211,51,132,212,51,132,211,52,133,211,52,133,212,51,133,213,52,133,213,51,134,213,51,134,214,51,134,215,52,134,215,54,135,216,53,136,216,53,136,217,53,137,217,56,137,217,53,138,217,57,138,217,57,139,215,56,140,216,58,140,217,59,141,215,59,142,216,60,143,217,71,146,215,89,155,213,123,173,216,114,168,212,100,159,205,102,159,205,112,163,206,108,163,206,110,162,205,111,164,204,125,172,209,124,174,208,120,172,206,121,171,207,116,168,203,111,165,199,104,159,196,93,150,189,85,146,186,78,140,184,74,136,181,72,133,180,71,133,180,71,133,179,68,131,180,62,128,177,52,137,211,52,136,214,54,135,212,53,136,213,52,137,212,53,136,211,54,136,211,54,135,211,51,135,211,53,135,211,52,135,211,53,134,210,54,134,211,53,134,212,51,135,211,53,134,210,53,134,211,52,134,211,51,135,213,52,134,213,53,135,213,53,135,212,53,134,213,53,135,214,52,136,214,55,135,214,54,135,216,54,137,216,55,137,216,56,137,217,56,137,218,56,138,218,55,138,218,57,139,219,57,140,219,58,140,218,62,139,215,68,141,213,78,145,212,79,148,213,66,144,216,74,146,213,94,154,211,92,153,209,97,156,211,106,163,215,98,157,212,99,156,209,95,152,206,91,152,203,101,156,201,109,162,203,109,162,205,105,160,203,108,162,204,116,167,207,105,162,205,89,153,205,86,152,202,87,151,197,86,149,196,80,145,192,77,140,188,71,139,190,68,139,195,65,140,200,64,140,201,65,133,192,65,132,188,61,131,187,59,131,187,55,141,213,56,139,216,56,140,214,55,141,214,56,140,214,56,141,213,55,140,213,57,139,213,55,139,213,57,139,213,56,138,212,55,138,212,58,138,212,53,138,213,55,139,213,54,138,213,56,137,213,55,138,214,56,139,214,56,138,215,57,139,215,57,138,217,58,139,217,57,139,217,57,140,217,57,140,218,58,140,218,59,140,219,59,141,220,60,142,220,58,142,220,60,143,221,60,144,221,63,140,215,74,138,203,85,143,201,91,144,201,96,148,203,92,145,202,98,150,200,103,152,201,108,156,202,126,171,212,125,171,212,101,153,202,98,151,202,96,152,201,101,155,201,115,166,206,121,172,209,124,173,211,106,161,203,111,165,205,122,173,210,117,172,211,97,157,205,79,151,210,68,151,214,68,150,216,66,150,216,64,150,218,64,150,219,61,153,220,61,154,220,63,151,220,62,149,216,61,150,218,63,151,219,62,152,217,57,145,215,59,143,217,59,143,216,61,143,216,60,143,215,58,143,215,60,142,215,59,142,215,58,142,215,58,142,214,59,141,214,58,141,214,59,141,214,57,142,214,59,141,214,61,141,214,57,141,216,59,141,215,60,142,216,59,142,216,59,143,217,59,142,217,58,143,218,60,143,217,59,143,219,61,143,219,60,144,220,61,144,220,62,145,220,63,145,221,63,145,222,63,146,221,62,146,222,62,147,222,62,148,222,64,148,222,66,146,218,68,144,215,70,146,216,76,145,210,93,147,202,85,143,201,83,145,203,94,147,200,96,151,202,96,155,206,98,152,201,90,147,199,83,144,199,87,148,200,99,156,203,111,164,206,121,171,211,120,169,208,108,163,204,104,160,202,100,158,204,97,159,206,91,154,201,79,146,201,69,150,215,67,154,222,67,155,221,66,155,221,68,155,222,66,156,223,64,156,223,67,155,223,65,156,222,65,157,221,65,156,220,60,148,215,62,147,218,64,147,216,65,146,217,64,146,216,62,147,216,62,146,216,64,146,214,64,145,216,64,145,215,61,145,216,63,144,216,62,145,216,63,144,216,63,145,216,64,145,217,64,144,217,62,144,217,63,145,217,63,146,217,63,146,219,63,145,218,63,145,219,64,145,220,64,146,220,65,146,220,64,146,221,65,147,221,64,148,222,65,149,222,64,149,222,65,150,223,67,151,223,67,150,224,67,151,224,68,152,225,69,152,225,71,153,226,71,155,226,71,154,225,75,153,220,73,155,225,73,155,223,76,153,220,74,154,220,76,153,218,75,148,211,79,145,204,77,139,198,74,147,209,76,149,209,78,147,206,78,150,205,78,152,212,73,147,206,75,147,205,74,148,208,71,152,213,73,158,221,73,158,223,70,160,224,70,160,225,69,159,225,70,159,226,68,160,224,66,159,225,67,160,225,66,160,224,67,159,224,68,159,224,68,159,221,63,150,215,66,149,217,66,148,216,67,149,217,65,148,215,66,149,216,67,148,216,66,149,216,66,148,215,65,148,215,66,148,216,67,148,215,66,148,215,65,148,217,67,148,216,65,148,217,66,147,217,65,148,217,66,148,217,66,148,218,67,149,219,67,149,220,66,149,220,66,150,220,66,150,221,66,150,222,68,151,221,67,152,222,68,152,222,69,152,224,70,152,224,71,152,224,72,153,224,72,153,225,72,154,225,72,154,226,74,155,226,73,156,226,76,156,227,75,156,225,75,157,227,75,158,227,76,158,226,79,159,227,77,159,228,78,160,226,77,159,224,75,156,221,77,153,216,74,144,204,73,140,200,74,147,207,72,144,204,72,146,206,76,150,209,83,151,206,83,148,202,85,154,209,78,155,214,75,161,224,75,162,225,74,163,226,71,163,226,72,163,226,71,163,226,72,163,226,70,163,225,70,162,225,72,162,225,71,162,225,73,162,225,73,162,224,73,162,222,67,150,211,68,150,214,69,149,215,68,151,215,68,151,216,72,151,216,69,151,216,71,152,216,70,151,215,69,151,216,72,151,216,68,151,215,70,151,216,67,150,216,70,150,216,69,150,215,70,150,216,69,149,217,72,150,217,70,150,217,69,152,219,70,151,218,69,148,216,69,149,215,69,151,218,70,153,220,72,153,222,72,153,219,75,153,222,75,155,222,75,155,224,74,156,224,75,156,225,76,157,225,78,157,225,78,157,226,78,158,226,77,159,227,81,160,228,80,160,228,79,161,228,81,162,228,82,162,228,85,163,228,84,163,227,83,162,227,84,161,225,82,158,220,84,158,217,91,158,215,97,159,212,95,159,213,92,155,208,90,152,204,85,151,205,84,153,208,82,155,209,85,153,206,85,151,204,86,152,207,76,157,214,77,162,223,76,165,226,76,164,227,77,165,226,76,165,226,76,164,225,80,163,221,97,166,215,97,167,213,97,166,214,94,166,214,96,166,214,69,135,191,74,143,202,71,147,209,72,148,211,72,148,210,73,151,211,73,152,214,71,153,215,74,153,214,73,153,214,74,153,214,73,153,214,72,152,215,72,152,214,74,152,214,72,152,215,74,150,215,72,151,216,73,151,216,72,151,216,73,151,216,72,151,216,73,153,217,74,154,219,76,155,220,76,155,221,77,156,221,77,156,220,78,157,221,79,158,223,78,158,223,80,158,224,80,159,224,81,158,224,80,159,224,82,159,224,83,160,225,83,161,226,84,161,226,85,161,226,90,160,222,87,159,222,97,161,219,101,162,217,104,159,213,103,159,212,105,158,209,97,150,203,94,149,200,100,153,200,101,154,201,98,152,200,96,153,201,95,153,204,87,155,208,84,156,211,84,154,210,81,156,212,83,162,218,82,162,219,81,162,220,79,165,222,80,166,225,79,168,228,79,169,226,79,164,222,78,160,216,81,162,217,86,165,218,98,167,213,101,164,209,103,165,208,99,163,206,100,159,201,81,145,197,79,141,198,76,139,195,74,138,196,74,139,195,72,138,195,76,143,201,75,149,207,75,150,208,76,152,210,76,152,211,76,153,211,75,153,212,77,152,212,73,150,208,70,145,205,70,141,203,72,139,201,71,140,201,73,142,203,71,140,200,70,142,202,74,147,209,75,150,212,77,151,214,79,153,216,79,156,217,81,158,219,80,158,220,83,159,221,84,159,221,84,158,221,83,156,219,81,148,210,83,143,203,85,145,205,85,149,209,94,150,207,95,149,203,94,148,203,102,152,203,97,146,199,97,147,200,99,150,199,102,152,201,96,148,198,98,150,199,101,152,200,99,153,199,98,151,198,94,146,196,91,146,193,91,148,195,88,146,195,83,145,197,84,151,203,86,154,206,92,154,205,98,166,215,91,164,216,97,170,220,90,168,221,84,165,220,84,167,223,82,169,224,83,167,222,84,164,219,88,157,209,109,169,209,107,168,208,103,165,208,101,164,205,92,158,202,84,155,201,85,138,184,82,132,186,80,135,186,88,140,191,80,136,188,76,134,188,76,134,189,80,141,197,76,142,198,78,146,202,78,149,206,78,153,208,79,153,210,78,152,209,78,151,209,78,151,207,77,149,206,74,146,204,76,145,203,77,145,202,77,145,204,76,144,204,78,147,206,80,149,209,82,154,213,85,158,215,84,158,216,85,159,217,85,159,218,86,155,216,86,156,216,83,151,212,84,144,203,97,148,203,92,145,202,92,146,202,90,145,201,99,148,202,112,157,206,106,154,202,99,149,198,99,147,197,92,144,196,93,145,195,92,145,196,96,146,197,101,152,199,107,156,201,111,159,203,101,152,199,94,148,196,102,154,200,106,158,202,101,155,200,96,151,197,95,152,199,92,152,197,109,163,206,119,173,211,109,163,206,116,171,210,112,167,208,94,157,204,87,157,208,82,158,211,86,159,210,87,158,209,86,158,208,87,157,205,85,156,207,85,161,212,87,164,214,86,161,210,85,159,207,66,122,172,71,121,179,70,123,177,69,125,179,71,127,182,72,128,182,70,132,185,72,133,188,75,138,192,77,142,195,77,146,201,79,149,203,80,150,204,81,150,205,80,151,205,80,150,205,82,152,206,80,152,207,80,154,209,82,153,210,83,154,208,83,153,210,84,153,210,82,154,211,86,155,212,91,154,209,86,157,215,87,157,214,89,157,214,85,153,211,84,151,209,86,151,209,85,146,204,89,147,204,89,147,203,92,147,202,93,148,203,105,154,204,100,152,203,95,147,199,94,145,197,93,143,195,94,145,195,93,144,195,93,144,194,94,145,195,101,150,198,103,153,199,101,151,198,99,151,197,97,150,196,92,148,194,87,146,193,88,145,192,86,144,192,86,144,191,84,144,192,86,148,194,87,148,194,84,148,196,84,149,197,84,152,202,84,155,204,84,158,208,84,160,211,84,161,211,84,162,212,84,163,213,86,169,219,85,170,219,86,168,218,83,167,215,60,114,163,64,115,168,66,118,171,67,120,173,67,120,175,70,122,177,68,124,179,68,128,183,69,131,184,70,135,188,75,138,191,75,140,193,78,143,197,78,146,197,78,145,198,78,143,197,79,146,199,81,150,201,81,150,203,83,152,204,85,153,205,83,153,206,85,152,207,86,152,208,87,153,207,92,152,203,87,154,208,87,152,207,88,154,208,91,157,211,91,158,212,94,158,213,95,158,213,93,157,212,95,157,212,95,156,210,97,154,208,99,152,206,96,155,208,96,153,206,98,151,202,101,151,201,102,151,201,100,151,199,98,150,198,102,151,199,103,153,199,101,152,197,99,151,198,100,152,198,101,153,198,101,154,197,103,156,200,104,158,200,94,151,198,89,149,194,89,148,196,82,146,193,87,150,195,83,150,198,82,155,205,88,165,214,88,167,215,88,169,218,88,170,218,89,171,219,88,171,219,88,173,220,89,172,220,89,173,219,87,172,219,89,171,219,87,172,218,56,108,155,57,107,161,58,111,162,59,112,165,61,115,167,65,117,171,64,120,172,62,120,173,65,121,174,66,124,177,67,128,181,70,129,182,70,131,184,73,132,185,73,134,187,75,137,189,76,138,192,78,141,195,80,145,198,84,148,201,85,149,201,85,150,202,87,150,204,86,151,203,87,151,204,86,151,204,96,152,201,89,152,205,89,153,205,91,154,207,91,155,207,91,155,206,91,155,209,93,156,209,94,155,209,94,154,208,95,154,207,97,153,206,103,155,204,103,154,204,98,150,201,97,149,202,98,151,201,106,157,205,102,155,203,102,152,202,97,150,199,102,153,200,103,153,199,99,152,198,96,151,197,93,148,195,88,145,195,90,148,196,98,153,199,98,155,197,92,153,197,86,148,194,84,148,195,80,148,195,81,148,196,83,152,200,84,156,205,87,163,210,86,166,212,88,166,213,87,167,214,87,169,216,89,168,215,87,169,215,89,170,217,88,170,216,88,171,216,90,170,218,87,168,214,39,87,134,43,90,140,47,97,145,50,99,149,51,102,150,54,104,154,56,107,156,57,109,160,57,113,162,58,114,165,58,115,166,59,118,167,62,122,170,64,124,175,65,126,177,68,128,179,68,128,181,70,131,183,72,133,184,76,136,188,77,138,189,77,139,191,79,140,193,80,141,195,80,141,194,85,144,195,88,143,193,83,145,196,85,146,199,93,149,200,84,146,199,87,149,202,89,150,203,90,152,203,92,152,204,94,154,205,95,155,207,94,154,207,103,156,206,109,158,207,104,157,206,100,154,204,90,148,201,91,148,200,88,147,201,89,148,202,89,149,202,88,150,201,90,151,201,89,150,200,87,149,200,86,149,199,87,148,200,86,149,199,86,150,200,84,151,199,83,151,199,82,152,200,83,154,200,83,153,198,81,152,200,83,153,200,80,152,201,80,154,203,80,155,203,81,157,205,82,157,204,81,156,205,81,158,206,82,160,207,83,161,207,84,161,209,83,163,209,84,164,212,89,167,209,14,59,99,15,57,101,15,58,101,16,59,102,17,60,103,18,61,104,19,63,105,19,64,106,20,66,108,23,67,110,23,70,113,25,72,116,26,74,120,28,78,122,30,80,124,31,83,127,34,85,131,36,88,134,40,91,137,41,94,141,43,97,145,45,100,146,48,102,151,52,106,153,62,113,158,67,112,153,57,113,158,60,117,167,63,119,168,65,122,173,69,126,175,71,129,179,75,132,183,77,135,186,79,138,188,83,139,191,85,141,193,86,143,195,86,144,195,84,143,195,84,142,194,82,142,194,81,141,194,81,141,193,80,142,193,82,143,195,84,145,196,83,147,196,83,146,196,84,147,196,84,146,195,82,145,194,80,147,195,83,147,194,81,147,195,80,147,195,77,145,192,77,146,192,75,144,191,74,143,191,74,143,192,73,145,193,74,145,194,74,147,195,77,148,195,76,148,198,77,150,198,77,151,197,75,152,199,76,152,198,78,153,200,75,153,201,76,154,203,79,155,201,15,61,102,18,60,104,17,59,103,17,60,102,17,61,104,17,62,103,17,61,103,16,61,104,16,61,103,17,60,104,18,62,104,16,62,104,16,61,104,16,62,105,15,62,104,16,62,105,16,61,104,15,61,104,15,61,105,16,62,105,16,62,108,16,62,105,16,62,106,27,70,109,49,77,101,75,105,132,26,68,108,16,61,105,15,61,104,15,62,107,16,62,106,14,61,106,17,62,107,16,63,108,17,64,108,19,66,109,23,67,111,23,69,112,26,71,116,26,73,118,29,77,120,30,79,122,33,82,125,35,85,129,37,87,131,38,89,133,36,89,133,38,89,134,45,99,143,48,101,146,45,99,142,48,103,146,52,109,154,53,112,155,55,113,156,47,104,149,47,107,151,50,110,153,51,113,156,53,115,161,54,116,162,54,118,165,57,123,167,58,127,172,60,126,173,61,130,176,61,129,176,66,135,179,64,134,177,67,136,181,67,139,184,70,142,187,68,140,184,20,65,106,22,65,108,21,64,108,22,64,107,21,64,108,20,64,105,21,64,106,19,64,106,20,65,108,20,64,107,21,63,106,20,65,108,21,65,108,18,65,109,21,66,112,20,66,110,21,65,111,21,66,112,20,67,111,21,68,113,21,68,114,21,68,115,19,67,112,22,68,114,22,69,115,22,70,116,22,70,117,22,69,115,22,68,115,22,68,114,21,68,113,21,67,114,22,66,113,22,67,111,21,67,113,21,66,110,22,65,110,21,65,109,21,66,109,22,67,110,21,67,110,23,67,110,20,66,108,21,66,109,23,68,109,24,68,109,23,67,107,22,66,105,23,67,105,24,67,104,24,68,106,25,70,106,26,70,106,26,71,105,25,71,105,25,72,108,25,72,110,26,73,110,25,74,109,24,73,112,29,77,111,25,73,111,24,75,111,24,74,112,26,75,114,25,75,113,26,76,113,28,80,117,29,80,116,29,74,118,29,73,120,28,73,118,28,73,116,29,72,117,29,71,116,28,71,117,30,71,115,28,71,114,27,71,114,26,71,114,27,71,114,25,70,113,27,71,113,25,71,113,25,70,112,26,69,114,26,69,112,25,69,112,27,70,113,25,70,112,25,70,113,24,70,114,25,70,113,25,69,112,24,69,112,24,68,111,23,68,110,23,67,110,25,68,111,23,68,112,25,69,111,25,69,112,26,70,114,28,71,117,27,72,115,26,71,113,28,72,114,28,71,113,27,72,114,26,70,112,26,70,111,28,72,112,27,70,111,27,70,108,27,71,109,28,71,108,28,73,110,30,74,108,30,74,109,31,75,110,34,78,113,33,78,112,31,77,113,32,77,113,31,77,114,30,77,114,29,76,113,29,77,114,28,75,115,27,76,115,26,76,112,27,75,114,28,74,113,26,74,112,24,73,111,25,72,107,31,72,113,35,74,118,34,74,116,33,73,115,33,72,114,33,71,113,33,71,110,32,70,110,32,71,111,32,74,115,36,77,119,36,79,122,37,80,124,36,78,124,36,79,122,36,80,124,38,83,127,38,81,126,36,82,125,35,80,125,37,81,128,36,81,127,35,80,125,36,81,127,37,82,128,35,83,127,38,82,128,36,81,127,35,80,124,35,80,125,34,78,124,35,78,123,35,76,122,34,78,121,34,77,122,35,78,124,34,78,122,34,77,121,36,78,123,35,78,122,34,78,122,35,77,121,34,78,120,35,78,119,33,76,118,34,76,117,34,77,116,33,77,118,34,76,113,34,75,112,36,76,112,34,77,113,36,79,114,38,81,114,37,80,115,39,83,116,39,83,117,39,84,117,41,84,119,40,84,119,38,83,117,37,84,120,37,83,120,36,80,117,34,82,118,34,81,117,33,80,118,32,79,117,32,80,117,29,79,115,31,79,115,30,79,116,32,79,117,32,79,113,52,82,107,51,77,103,52,76,103,50,75,103,51,78,106,53,82,113,52,83,113,48,80,111,50,80,110,47,79,111,51,83,115,46,78,109,47,80,112,42,76,107,45,74,102,43,74,104,45,79,110,44,78,114,43,77,110,44,79,113,45,84,122,45,84,126,43,79,117,43,82,122,45,85,128,46,86,128,45,85,127,44,84,125,45,84,128,44,84,127,44,83,126,43,82,124,44,83,125,45,82,126,46,84,127,46,85,128,46,84,126,46,83,126,46,83,123,44,82,124,46,85,126,46,86,128,45,82,122,44,82,121,42,80,119,41,80,118,41,77,113,39,77,110,39,74,109,39,73,105,38,73,105,40,74,104,41,77,109,43,81,115,44,82,115,44,83,116,43,83,114,43,82,116,42,83,114,41,84,116,41,84,118,40,84,117,38,81,115,37,82,117,38,82,117,36,80,114,35,78,112,33,78,113,35,78,112,35,79,113,35,79,112,34,79,112,68,80,83,69,79,85,74,82,88,72,82,85,72,84,87,71,82,83,74,84,85,75,84,84,77,85,86,76,86,87,77,85,86,75,84,87,74,84,86,74,83,88,75,83,87,75,84,92,77,86,91,77,87,94,76,85,91,77,87,97,74,84,91,76,86,98,73,85,97,75,87,98,74,84,94,71,82,93,71,84,95,71,83,99,70,86,105,68,83,104,67,81,101,60,75,94,56,73,93,59,77,100,61,82,107,60,83,109,61,78,101,60,79,104,55,75,100,52,73,98,54,81,110,53,84,118,51,79,111,49,78,109,48,78,110,50,78,109,48,77,109,51,80,108,50,82,112,46,75,102,46,74,100,49,76,99,53,82,110,55,88,118,55,88,117,50,82,110,52,84,113,52,87,114,54,88,118,52,86,115,48,84,112,49,89,117,51,90,119,46,86,116,42,81,111,41,79,104,50,88,116,52,91,120,43,80,109,43,83,111,42,85,113,42,84,114,42,82,110,51,76,95,50,77,103,51,78,106,50,77,102,51,79,103,52,78,101,51,78,104,55,79,102,51,76,96,54,77,98,54,74,92,57,76,94,62,80,94,62,79,93,60,79,93,63,79,92,64,77,88,62,81,95,63,81,95,64,84,101,68,82,93,68,86,102,66,83,100,66,82,98,66,83,101,67,86,105,67,83,97,72,86,99,69,85,98,73,85,101,73,88,104,71,86,105,71,87,107,69,87,107,67,89,111,69,88,114,70,82,103,74,90,112,77,90,107,82,94,112,79,94,114,78,92,110,79,94,115,77,99,124,78,103,129,77,103,129,78,104,133,75,105,133,77,107,134,78,106,133,74,104,130,73,103,129,71,102,127,71,102,125,71,99,123,68,95,116,65,89,108,62,87,103,65,86,98,67,89,100,64,85,96,63,82,93,65,88,97,66,88,100,61,86,98,57,87,106,55,84,100,53,81,94,55,82,97,59,83,97,57,82,93,56,84,96,61,89,103,59,91,110,57,87,105,71,77,71,70,76,75,73,78,77,73,78,75,77,81,78,73,78,77,76,81,81,75,82,81,74,81,81,77,84,83,73,80,80,76,82,82,77,85,87,76,85,89,76,84,86,81,87,88,72,79,80,77,87,90,80,88,88,78,92,97,84,93,96,82,94,99,82,93,98,85,93,98,83,94,99,87,96,101,88,98,105,87,96,105,87,97,106,83,97,109,91,101,111,89,100,109,88,100,112,85,100,114,87,100,114,86,99,112,89,103,118,88,100,117,87,102,117,89,103,122,89,104,122,85,101,118,84,102,119,86,103,122,87,104,124,85,104,123,85,104,120,83,106,126,83,107,127,79,104,124,82,103,121,77,104,122,78,105,126,74,102,123,76,107,129,75,106,127,74,106,129,73,104,126,74,104,125,72,102,121,71,105,125,70,102,123,69,100,122,67,103,123,71,103,123,70,105,127,70,108,130,69,106,126,69,104,123,69,104,121,68,104,120,68,101,116,72,101,114,71,100,109,72,99,106,76,81,73,78,80,75,75,79,72,76,79,73,80,82,73,83,85,76,82,85,75,84,85,76,81,83,73,85,87,75,84,84,73,86,84,72,84,85,71,83,83,71,86,86,74,86,85,74,88,88,74,90,88,74,94,92,79,96,93,80,97,92,80,95,91,78,99,92,77,100,94,79,99,92,76,104,96,83,104,95,80,97,89,75,114,102,88,113,102,84,107,98,82,107,96,80,106,94,78,109,98,82,106,95,79,106,94,80,108,95,81,107,95,81,105,92,78,107,97,82,106,94,78,112,102,84,111,100,84,113,101,85,110,100,83,116,104,86,109,102,84,109,101,84,104,100,82,106,100,83,102,98,84,106,103,87,101,99,82,101,99,83,96,97,83,100,102,90,97,99,86,98,101,90,91,99,88,90,98,89,87,96,88,89,98,90,86,100,94,84,95,90,85,100,95,83,100,97,83,101,97,86,104,101,83,104,101,85,105,103,83,103,103,82,104,104,79,103,104,79,105,105,62,68,58,67,69,61,57,62,56,61,66,59,60,64,57,63,66,58,62,66,57,68,70,60,59,65,55,64,67,57,74,75,64,75,77,65,72,72,62,74,76,64,73,75,63,81,81,70,81,81,71,89,88,76,89,87,75,90,89,76,91,90,77,97,94,80,97,92,79,91,89,76,104,98,87,102,98,84,105,97,82,108,101,87,103,98,84,116,106,91,109,102,88,104,98,85,111,101,87,111,101,86,113,104,88,118,109,93,118,107,91,114,104,89,116,105,90,120,107,91,123,112,95,123,114,94,115,106,92,124,113,95,118,109,93,126,116,97,129,120,100,123,115,96,120,115,96,124,119,100,117,115,96,119,113,94,117,114,93,117,115,95,111,112,94,111,110,91,109,111,90,109,109,90,103,104,85,107,109,90,101,104,85,105,106,88,99,103,86,97,102,84,101,105,88,96,103,85,98,105,86,97,103,85,91,101,81,99,105,85,94,102,83,94,101,83,93,101,84,95,105,85,54,59,52,63,69,61,59,64,58,59,64,56,68,71,62,60,66,58,52,58,50,50,54,45,64,68,57,61,66,56,67,70,58,65,69,58,64,67,55,68,71,59,76,77,64,60,63,53,81,80,68,77,78,66,82,83,70,80,81,69,82,81,69,82,82,71,88,86,75,94,91,78,79,78,67,93,91,78,98,93,79,99,92,79,97,94,78,82,82,69,107,101,85,100,94,80,99,93,80,107,99,84,105,99,85,109,101,86,107,98,82,110,102,86,112,106,89,106,98,82,110,102,86,106,100,87,113,105,89,114,105,90,115,108,92,116,109,93,110,107,88,110,104,87,118,114,94,115,112,95,117,112,94,112,111,92,111,109,91,110,110,91,110,112,92,109,111,91,110,111,91,101,105,87,108,110,90,106,109,90,107,110,89,106,109,89,107,112,94,105,109,91,104,109,88,96,102,84,101,109,88,102,110,90,100,107,86,97,104,84,99,109,88,92,103,84,95,104,86,94,104,86,90,101,81,48,54,48,58,64,55,60,64,55,63,68,56,64,68,59,60,64,57,69,73,59,51,56,46,52,58,50,65,69,56,61,64,55,65,67,56,64,68,54,68,70,57,87,88,72,86,86,71,90,88,72,70,71,60,79,80,68,80,80,65,79,77,64,72,73,62,82,82,70,85,84,72,83,83,70,82,80,68,78,76,65,80,78,64,91,85,69,72,70,61,74,71,59,91,86,72,85,83,70,93,87,73,92,86,72,93,89,75,99,94,81,103,97,83,101,94,78,96,90,72,97,90,75,99,95,80,105,98,84,103,97,79,107,101,82,99,95,78,110,105,87,105,101,84,112,109,90,110,107,90,111,107,87,108,106,88,103,103,85,110,109,89,112,113,93,106,106,88,103,102,84,91,96,77,99,102,84,101,104,85,88,93,75,93,98,80,94,99,83,88,94,76,91,98,79,91,97,79,86,94,76,89,97,81,80,90,72,86,96,77,85,94,75,81,93,76,81,91,75,79,90,73,83,93,75,58,61,52,60,62,54,63,68,59,67,71,60,64,68,59,75,76,64,59,64,53,62,66,54,66,68,58,71,75,62,71,74,61,70,73,59,73,75,62,74,74,60,65,69,56,83,83,68,58,60,49,48,51,45,78,81,65,93,90,74,75,75,61,74,75,62,73,74,61,91,89,75,89,88,74,89,85,70,87,83,70,93,89,73,80,75,63,88,84,70,99,92,77,94,89,74,100,94,79,100,95,78,99,93,79,104,97,82,101,94,79,111,103,87,113,105,89,112,105,87,114,106,87,124,114,96,120,112,94,120,113,95,115,107,89,115,107,88,115,111,91,119,113,93,117,112,91,117,112,90,120,114,96,113,112,92,115,113,92,110,109,88,109,108,88,111,112,90,112,112,92,109,112,91,103,106,89,99,103,84,98,101,80,93,99,82,97,100,82,93,98,78,88,95,77,89,97,77,88,96,78,85,93,74,84,95,77,83,94,76,84,92,76,80,91,75,80,91,74,78,90,76,64,67,53,51,57,48,63,70,59,65,68,57,72,75,63,72,73,61,60,65,54,75,76,62,63,67,57,68,69,58,68,72,58,78,78,63,70,67,53,51,53,42,42,50,42,70,71,55,70,71,56,69,71,60,81,81,67,79,80,65,80,80,66,85,83,68,71,72,59,86,84,70,80,80,66,89,86,72,89,85,68,89,84,70,93,88,72,92,89,73,88,83,70,97,92,76,106,98,80,106,99,81,107,100,81,103,95,78,99,92,74,112,104,84,105,97,79,121,110,89,112,102,81,128,115,92,121,109,87,116,108,88,104,99,80,122,113,93,115,108,89,117,111,90,123,116,93,110,104,84,121,115,91,108,104,85,117,114,92,111,108,90,101,100,76,108,108,86,107,108,87,106,110,86,107,108,88,97,98,77,84,89,72,95,98,79,94,97,80,88,93,76,83,89,72,84,92,76,88,95,77,82,88,72,80,90,72,78,87,68,75,85,71,81,90,74,79,91,74,82,92,74,80,91,74,63,70,57,61,67,58,58,66,55,52,57,49,59,64,55,70,74,62,69,74,63,67,71,58,58,62,51,58,62,50,47,52,39,66,67,55,65,67,53,65,66,53,69,71,58,55,59,50,78,77,65,70,72,59,65,65,55,79,79,65,73,73,61,74,75,59,69,70,55,60,62,51,81,81,67,81,79,63,99,93,76,74,73,60,83,80,65,78,75,58,88,84,67,84,78,61,87,83,67,109,101,80,93,88,71,87,80,64,107,99,79,86,82,66,112,98,76,101,92,72,101,92,71,98,92,73,101,95,74,102,93,74,102,95,75,106,99,80,92,87,69,99,95,75,102,98,76,93,89,71,103,100,80,86,86,68,96,95,76,91,91,74,94,92,71,86,85,64,83,84,66,93,94,74,89,92,74,91,93,78,88,91,76,88,91,73,85,88,73,75,79,65,83,87,68,81,89,72,79,89,72,79,88,72,78,87,71,76,87,69,76,86,68,78,88,73,74,84,66,71,84,67,75,86,70,69,73,60,50,58,50,67,71,62,61,65,55,48,54,45,55,61,50,58,64,54,63,66,54,54,60,49,53,59,49,68,71,57,63,67,57,72,75,65,64,67,55,64,68,58,75,77,66,77,78,66,71,74,64,74,77,64,67,69,57,75,75,63,68,69,56,67,68,56,66,66,53,63,63,53,71,69,57,71,71,58,79,78,64,78,76,63,63,64,50,76,70,53,63,60,47,67,63,49,96,89,71,71,69,55,92,86,69,85,80,62,84,78,62,81,75,58,84,78,64,87,82,63,79,75,61,97,92,75,99,91,72,91,83,66,95,91,70,85,84,66,88,86,68,88,86,66,88,84,65,97,94,76,90,90,72,93,93,74,91,91,74,83,84,68,97,97,75,87,87,70,91,93,76,86,90,71,88,90,71,83,86,69,87,91,76,84,87,72,78,84,69,91,94,74,84,90,71,83,89,70,80,87,65,79,85,66,81,88,68,80,89,71,82,92,73,81,92,73,80,89,70,88,96,76,64,72,59,62,69,60,70,72,61,61,67,56,55,60,50,68,71,59,59,62,52,61,66,54,62,68,55,59,66,55,68,71,60,56,62,51,64,69,57,67,70,59,74,75,63,71,75,61,76,77,64,72,75,62,71,75,63,72,74,61,67,69,58,72,74,61,72,72,59,63,65,55,71,71,58,77,76,63,83,82,67,79,77,63,74,73,59,64,63,52,67,67,52,82,77,60,85,81,64,77,73,58,92,88,69,84,80,66,92,88,72,90,85,69,93,87,70,84,80,66,96,89,69,82,79,63,93,91,72,99,93,71,94,88,70,96,93,74,90,88,69,93,91,74,92,91,72,92,89,68,91,91,73,80,80,63,94,95,76,91,91,72,90,89,69,84,84,66,92,94,74,88,90,74,87,89,71,87,90,71,80,84,67,83,88,70,84,88,71,83,87,70,86,90,73,82,86,69,83,89,70,78,86,67,76,84,66,75,82,64,81,90,70,83,93,73,80,90,70,87,96,76,79,89,70,51,58,47,44,52,45,55,61,51,47,54,44,56,63,52,57,63,51,66,69,58,58,63,53,56,61,49,63,67,54,56,61,50,51,58,47,59,63,52,58,64,53,60,65,54,63,68,57,65,70,59,58,65,54,59,64,53,66,70,59,66,70,56,72,74,61,66,67,56,68,70,56,69,71,58,69,69,59,81,79,65,84,84,69,77,75,61,78,75,61,78,76,61,76,73,58,80,77,62,69,68,53,94,91,72,82,78,63,86,83,67,83,81,66,94,89,74,92,88,73,93,87,68,99,91,73,88,85,67,81,78,60,95,90,71,99,95,77,95,92,74,94,93,75,90,89,71,93,92,73,88,89,70,88,88,68,95,94,73,84,85,67,91,92,69,83,86,69,87,90,72,89,91,73,86,90,71,85,88,69,85,88,71,70,76,60,93,96,77,74,80,61,89,93,70,85,89,70,75,82,65,82,91,73,75,85,68,80,89,72,81,90,72,86,93,72,83,92,72,86,93,71,82,92,69,57,65,55,57,63,55,59,65,56,63,69,58,64,69,59,58,66,54,60,66,55,56,64,54,66,72,59,64,69,60,63,68,59,66,71,60,56,61,51,62,66,54,61,65,53,60,65,56,63,67,55,56,61,48,67,71,59,67,70,58,64,67,54,75,77,64,77,78,65,67,69,57,66,67,56,60,60,49,72,72,60,78,78,64,64,65,53,87,85,70,86,84,69,79,78,64,85,82,68,85,83,68,86,86,70,85,83,68,80,77,61,92,88,71,88,86,69,86,81,64,85,82,65,93,88,69,92,89,71,83,82,65,86,85,68,73,74,60,73,73,59,83,82,67,76,74,57,84,85,65,86,85,66,85,85,66,87,87,70,87,89,72,85,87,67,85,87,70,82,84,67,82,82,65,89,93,74,86,90,70,89,91,71,81,85,67,82,86,69,80,86,68,78,85,66,77,86,68,77,85,68,82,93,74,80,89,72,81,88,70,80,89,72,81,92,73,79,88,71,77,88,69,78,87,67,58,66,55,53,61,52,56,62,51,59,65,55,59,68,57,63,70,60,59,65,53,60,66,54,58,66,54,60,66,54,64,69,57,56,61,51,60,63,54,63,68,54,65,69,59,55,59,49,66,70,56,60,65,52,63,66,53,62,65,52,68,70,56,67,70,57,71,72,58,72,74,60,80,79,63,63,65,52,82,78,65,75,75,62,75,75,61,77,78,63,71,71,57,70,69,56,78,76,62,84,83,66,82,82,65,87,84,69,88,83,67,78,75,60,89,87,69,89,86,71,92,90,73,87,86,70,81,80,64,88,87,68,70,71,56,74,74,59,67,69,54,97,93,72,85,83,66,84,84,67,84,83,65,81,82,65,80,81,63,72,75,60,84,85,66,78,82,64,81,85,68,78,81,64,87,91,70,92,97,76,88,91,73,84,88,69,83,87,69,79,86,69,76,84,67,83,90,71,79,87,71,71,81,65,69,80,63,74,83,63,76,84,63,79,89,69,74,84,64,76,87,67,82,91,70,47,56,46,46,54,45,55,60,50,51,57,47,52,60,50,59,65,53,47,53,42,39,47,39,47,53,44,49,56,44,62,68,56,59,65,54,65,69,57,67,71,57,59,64,51,50,56,46,65,68,54,72,73,59,60,65,53,65,66,55,69,70,57,72,73,57,62,65,52,68,69,57,70,71,56,58,61,47,59,61,48,59,62,49,69,70,55,76,76,61,70,69,54,71,72,58,76,75,61,77,77,60,75,75,59,76,75,58,73,72,55,71,69,53,75,73,58,82,81,64,78,78,63,77,77,62,82,81,65,75,77,61,79,79,64,78,78,61,84,83,64,81,81,64,73,75,57,69,69,53,52,57,47,57,61,49,43,49,41,37,44,35,43,50,40,49,55,45,56,64,50,54,62,48,69,75,59,74,78,60,71,75,56,73,77,59,69,77,60,77,82,63,76,83,63,78,85,67,76,81,64,79,86,66,75,83,64,72,81,64,83,89,68,82,90,70,80,88,66,79,88,69,94,103,77,54,63,51,58,63,52,51,57,48,54,58,45,41,46,36,51,56,43,65,71,57,57,63,50,50,55,45,61,66,53,55,62,51,65,71,57,65,71,58,60,65,54,57,63,53,72,75,63,65,70,58,73,77,64,72,74,63,73,77,64,66,71,58,71,73,61,70,73,59,69,71,59,64,66,51,59,61,49,79,80,65,74,75,60,76,77,64,67,66,52,58,60,49,51,52,42,71,72,57,61,63,50,71,72,55,79,81,63,66,67,52,69,69,54,80,78,61,81,79,64,76,74,58,83,81,64,81,80,62,81,82,64,71,71,55,74,73,57,78,80,63,77,77,59,80,80,63,66,69,53,48,52,41,48,52,40,69,69,50,46,46,33,33,38,27,48,52,40,53,59,49,44,50,39,47,54,42,52,57,46,52,59,45,65,72,55,73,78,60,67,74,56,72,81,62,61,69,54,70,79,59,76,82,66,69,79,61,84,92,72,79,92,70,78,88,66,75,86,68,82,92,68,47,55,44,47,52,44,55,61,51,50,57,47,50,53,41,58,63,49,60,67,53,64,69,53,37,46,38,59,65,54,49,57,46,56,60,50,60,66,52,62,67,56,70,73,58,67,71,59,65,67,55,64,67,54,54,56,45,53,57,46,62,65,52,57,61,47,59,62,50,66,69,56,55,59,48,58,61,49,69,71,57,76,78,62,61,65,52,75,75,60,54,54,40,49,51,41,55,55,44,58,59,45,49,50,37,55,56,44,65,69,56,59,63,54,64,67,56,76,73,60,78,77,61,76,75,60,78,78,60,80,80,61,81,82,64,73,73,58,75,75,57,81,80,61,78,78,60,75,74,58,70,70,54,84,83,64,72,76,58,63,62,45,40,40,26,35,38,27,41,39,28,38,42,31,30,36,26,28,35,24,25,32,24,16,24,18,30,33,24,29,36,28,34,42,32,42,53,40,40,50,40,60,68,51,66,73,57,67,77,60,78,85,67,75,84,65,77,89,70,78,87,68,74,85,64,38,45,35,51,57,45,54,61,47,46,51,41,57,64,51,63,69,55,58,66,51,64,71,58,58,64,52,62,67,54,48,55,44,63,68,56,63,68,53,58,63,51,60,65,50,56,60,49,51,56,45,41,46,38,45,48,39,40,45,37,44,49,39,42,47,36,39,45,36,37,42,34,60,63,52,73,74,60,73,74,61,67,70,55,66,67,53,75,74,58,48,50,39,64,65,51,72,73,56,72,72,56,78,77,60,73,72,54,62,63,48,62,64,51,77,76,61,80,80,64,75,76,62,74,77,60,68,69,53,60,63,46,70,71,55,67,67,50,69,70,51,70,72,57,85,87,66,75,77,59,73,75,59,76,77,60,77,80,61,70,73,57,42,47,36,46,48,37,67,67,49,77,80,59,51,57,42,46,51,36,52,57,39,53,59,43,68,71,53,66,73,54,51,58,45,64,70,53,64,69,51,72,77,61,73,81,62,73,82,64,70,80,60,76,86,65,73,85,65,71,81,63,74,83,62,49,54,42,49,55,43,37,44,34,47,52,43,55,62,48,46,53,41,43,51,41,59,65,50,65,71,55,55,61,47,64,69,57,54,61,50,65,70,56,65,68,55,63,69,55,49,55,43,47,51,41,48,53,43,66,68,53,62,65,52,72,74,60,69,74,60,51,55,44,70,72,57,76,77,62,64,68,54,74,73,59,69,70,56,66,68,54,71,73,58,61,62,49,65,67,52,74,73,58,82,82,64,54,56,44,77,76,59,81,82,64,62,64,50,76,75,59,71,74,57,68,69,54,64,66,50,50,51,38,33,36,28,32,37,28,50,53,41,50,54,40,55,59,46,59,62,50,45,51,40,46,50,37,63,66,51,62,66,51,56,58,44,63,65,49,49,54,38,70,71,54,57,60,45,44,51,38,44,52,36,78,83,65,76,83,62,81,86,66,78,85,63,72,77,55,82,85,62,82,88,68,64,71,56,63,72,56,69,79,61,66,76,59,69,76,58,74,82,61,70,78,60,74,83,61,52,59,45,54,59,47,55,62,49,37,43,34,48,55,44,54,60,46,52,60,48,52,58,45,64,71,57,57,64,51,51,58,47,57,61,49,53,59,46,53,58,48,61,66,52,27,36,27,44,49,39,37,43,35,63,67,52,43,48,37,57,64,50,50,56,44,66,67,53,61,67,52,70,74,58,63,66,52,67,68,52,77,78,64,69,72,58,75,78,63,75,75,61,70,75,59,63,66,54,64,68,53,57,62,48,67,69,55,76,77,62,71,72,58,52,55,43,44,49,39,35,41,31,52,56,44,55,59,47,43,49,40,39,44,34,32,37,28,37,44,34,34,39,29,30,38,27,27,33,24,67,67,49,53,54,39,24,29,20,19,25,19,22,29,21,45,47,37,22,28,20,26,32,23,62,65,50,63,69,54,79,86,66,78,84,66,66,73,53,52,60,43,76,82,60,78,87,65,60,66,51,60,69,54,54,67,53,63,69,54,60,68,53,70,78,61,66,77,60,78,87,66,57,64,52,53,60,50,48,53,40,40,47,36,46,53,42,42,51,39,39,49,38,27,37,29,58,66,56,45,54,42,32,38,29,45,49,42,50,56,46,51,56,44,40,47,38,23,30,22,27,34,26,35,44,34,62,66,53,37,44,34,41,48,39,54,57,43,63,68,54,76,80,64,71,74,59,52,59,49,67,69,54,78,80,64,53,57,44,69,70,55,76,75,59,44,49,39,49,52,38,51,55,42,31,37,28,39,44,35,41,45,37,56,59,48,28,33,25,27,34,26,8,15,8,6,13,9,1,9,6,9,17,12,6,16,11,13,20,15,18,25,19,14,22,16,13,22,15,23,30,22,43,49,37,60,66,52,53,58,42,54,55,41,37,41,31,18,24,16,25,29,20,15,21,14,17,24,15,11,21,14,22,33,26,43,53,44,52,60,45,61,67,45,76,81,58,88,94,71,88,95,73,68,73,56,66,77,60,77,88,69,65,73,57,65,74,56,55,66,51,67,76,60,65,76,59,59,65,51,50,57,45,40,48,38,54,60,47,40,47,35,43,50,37,43,52,40,30,38,28,14,23,18,19,27,19,33,39,29,15,23,17,9,18,15,34,40,30,46,49,36,41,46,34,42,47,37,67,71,54,62,67,52,64,67,50,57,63,47,56,62,51,67,72,57,70,74,60,63,68,52,67,70,55,73,75,60,63,67,54,51,59,46,47,51,41,60,62,47,26,32,24,95,91,71,98,96,76,24,30,23,36,40,32,26,31,23,29,36,27,73,73,56,38,43,31,23,29,21,17,23,16,25,31,24,26,34,24,23,30,22,24,31,22,18,25,18,23,29,20,21,27,19,28,35,26,39,45,34,71,75,59,36,42,29,30,37,28,32,37,26,32,39,28,35,39,28,17,22,14,20,26,18,25,32,22,21,28,20,23,31,23,58,66,52,82,88,64,87,94,72,54,65,49,59,68,51,74,80,61,64,72,55,66,76,58,43,52,40,36,44,34,36,48,38,34,44,34,40,51,38,48,52,39,32,40,28,14,24,17,58,60,43,44,51,36,42,49,35,47,53,36,54,59,44,49,54,40,37,43,32,40,46,34,57,59,43,27,34,26,50,54,42,63,61,42,23,23,14,16,22,17,36,43,32,56,60,45,50,55,40,60,63,47,27,35,27,65,68,53,63,66,51,48,53,39,87,87,68,52,58,45,76,80,64,72,76,60,34,41,32,32,38,29,83,82,62,85,85,66,54,57,46,15,21,15,18,24,19,34,39,29,55,56,43,87,86,65,71,72,53,46,50,36,77,78,58,87,93,80,75,80,65,91,90,72,72,77,62,20,30,23,87,85,61,61,66,49,52,57,43,69,71,48,86,87,64,69,70,49,62,68,51,44,52,38,50,53,38,21,26,18,38,41,26,35,39,27,29,35,24,33,37,25,30,36,26,28,34,24,39,48,33,42,50,37,59,69,50,63,71,54,61,69,53,46,55,42,33,42,31,23,30,22,28,35,27,28,38,28,25,37,26,38,50,39];
		var randomData = trngImgWorker.init(hashAlgorithm, entropyInputEstimatePerPixel, dataset);
		var randomDataHex = randomData.extractedRandomDataHexadecimal;
		var expectedRandomData = 'f6af567e5782d3126e2d1a560f1cd070f3be402951e3e2a43e72f1c98db6d1316eeab14871636baba20192e69d0994c9f59d3294fc8c264931cd136264f35afc09100ca279dc8aaca101b9c436c364567ff29ad286168fc256c17b899c0c09e2db83df771eb66d080db1765eb0f0b06b2e1a8451f7d20409455c3031fc6e1390c9836dfdc15877d4f192a5cf75de075abd97bd8ae865958e4d9bc5825f155e4f61552310ed8b24d05f279e15c88a5c9e85ee5245803e93111bbc2fd5f4b04c7e736579aea4483ea0cd3fa2ab27d58d31632ff84b238519b7e63ee10ecf11c4cc';
				
		ok(randomDataHex === expectedRandomData, 'Extracted random data ' + randomDataHex + ' should be ' + expectedRandomData);		
	});
	
	
	/**
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
});