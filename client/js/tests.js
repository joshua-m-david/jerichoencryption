/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
*/

// On page load run QUnit tests
$(document).ready(function()
{
	// Test data
	var pad = '7aadfc0a83b1edce072b624ae07fd5fea1c509ad46d73d63c4824b8208427f38497cfc4dc5f4cab33dfc8d4d853ff797866662bc75b6cfd27756a9d0d7d6512b09f7f5576823df4f0bf3ee5640a0964a2b9227f8e8838d24515f615e0efa81633757fb90f3740d1f90bf249b1dd440e4a37e5b4bf421d4030fc57855a70f212de9f7225ccd94f7c49e880db656bb0185f88bc8796bd2140def04ac2f7da6e8d2a2f7810fdadc1ddc7df5ab955ec34e08f7046525da940774b1';
	var plaintextMessage = 'The quick brown fox jumps over the lazy dog';	
	var plaintextMessageMax = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick ';
	var plaintextMessageMaxExceeded = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown';
	var plaintextMessageLength = common.messageSize;
	var plaintextMessageTimestamp = 1374237870;
	var plaintextMessageMacAlgorithmIndex = 1;
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Local Storage is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var localStorageSupported = common.checkLocalStorageSupported();
	
	test("Test if HTML5 Local Storage is supported in this browser", function()
	{
		ok(localStorageSupported == true);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Workers are supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webWorkersSupported = common.checkWebWorkerSupported();
	
	test("Test if HTML5 Web Workers are supported in this browser", function()
	{
		ok(webWorkersSupported == true);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Web Crypto API is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var webCryptoApiSupported = common.checkWebCryptoApiSupported();
	
	test("Test if HTML5 Web Crypto API is supported in this browser", function()
	{
		ok(webCryptoApiSupported == true);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Offline Web Application Cache is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var OfflineWebApplicationCacheSupported = common.checkOfflineWebApplicationSupported();
	
	test("Test if HTML5 Offline Web Application Cache is supported in this browser", function()
	{
		ok(OfflineWebApplicationCacheSupported == true);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test random numbers from Web Crypto API are in correct range
	 * ------------------------------------------------------------------
	 */
	
	// Test small maximums
	var smallIntA = common.getRandomIntInRange(0, 1);	// 0 or 1 possible
	var smallIntB = common.getRandomIntInRange(0, 2);	// 0 or 1 or 2 possible
	
	// Test maximum
	var smallNumber = common.getRandomIntInRange(0, 255);
	var mediumNumber = common.getRandomIntInRange(0, 65535);
	var largeNumber = common.getRandomIntInRange(0, 4294967295);
	
	// Test fixed limit
	var numberBetween0and10 = common.getRandomIntInRange(0, 10);
	var numberBetween0and20k = common.getRandomIntInRange(0, 20000);
	var numberBetween0and300k = common.getRandomIntInRange(0, 300000);
	
	// Test min and max
	var numberBetween5and10 = common.getRandomIntInRange(5, 10);
	var numberBetween10kAnd20k = common.getRandomIntInRange(10000, 20000);
	var numberBetween150kAnd300k = common.getRandomIntInRange(150000, 300000);
	
	test("Test random numbers from Web Crypto API are in correct range", function()
	{
		ok(((smallIntA >=0) && (smallIntA <= 1)), smallIntA.toString());
		ok(((smallIntB >=0) && (smallIntB <= 2)), smallIntB.toString());
		
		ok(smallNumber <= 255, smallNumber);
		ok(mediumNumber <= 65535, mediumNumber);
		ok(largeNumber <= 4294967295, largeNumber);
		
		ok(numberBetween0and10 <= 10, numberBetween0and10);
		ok(numberBetween0and20k <= 20000, numberBetween0and20k);
		ok(numberBetween0and300k <= 300000, numberBetween0and300k);
		
		ok(numberBetween5and10 >= 5 && numberBetween5and10 <= 10, numberBetween5and10);
		ok(numberBetween10kAnd20k >= 10000 && numberBetween10kAnd20k <= 20000, numberBetween10kAnd20k);
		ok(numberBetween150kAnd300k >= 150000 && numberBetween150kAnd300k <= 300000, numberBetween150kAnd300k);
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
		ok(testBinaryFrom7to8bit == '01100001', testBinaryFrom7to8bit);
		ok(testNumeric == '043', testNumeric);
		ok(testNumericLengthExtensionNotNeeded == '130', testNumericLengthExtensionNotNeeded);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Get the original plaintext length formatted to 3 digits
	 * ------------------------------------------------------------------
	 */
	
	var originalPlaintextLength = common.getOriginalPlaintextLength(plaintextMessage);
	
	test("Get the original plaintext length formatted to 3 digits", function()
	{
		ok(originalPlaintextLength == '043');
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test plaintext which exceeds maximum and should return the max message size
	 * ------------------------------------------------------------------
	 */
	
	// Test 133 char long string
	var maxPlaintextLength = common.getOriginalPlaintextLength(plaintextMessageMaxExceeded);
	
	test("Test plaintext which exceeds maximum and should return the max message size", function()
	{
		ok(maxPlaintextLength == common.messageSize);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Pad the message with random numbers up to the maximum message size
	 * ------------------------------------------------------------------
	 */
	var plaintextPadded = common.padMessage(plaintextMessage);
		
	test("Pad the message with random numbers up to the maximum message size", function()
	{
		ok(plaintextPadded.length == common.messageSize);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test padding function on max length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxPadded = common.padMessage(plaintextMessageMax);
		
	test("Test padding function on max length plaintext", function()
	{
		// Message should be same, ie no padding added
		ok(plaintextMessageMax == plaintextMessageMaxPadded);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test padding function on oversize length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxExceededPadded = common.padMessage(plaintextMessageMaxExceeded);
			
	test("Test padding function on oversize length plaintext", function()
	{
		// Message should be truncated, ie no padding added
		ok(plaintextMessageMaxExceededPadded == plaintextMessageMax);
		ok(plaintextMessageMaxExceededPadded.length == common.messageSize);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Get the current timestamp in UTC and make sure it is 10 digits
	 * ------------------------------------------------------------------
	 */
	
	var currentTimestamp = common.getCurrentUtcTimestamp();
	var currentTimestampLength = currentTimestamp.toString().length;
	
	// 10 digit timestamp is good up to 20 Nov 2286
	test("Get the current timestamp in UTC and make sure it is 10 digits", function()
	{
		ok(currentTimestampLength == common.messageTimestampSize);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Convert the max length plaintext to binary
	 * ------------------------------------------------------------------
	 */
	
	// Use the maximum length one for the remainder of tests for easier testing
	var plaintextMessageBinary = common.convertTextToBinary(plaintextMessageMax);
		
	test("Convert the max length plaintext to binary", function()
	{
		ok(plaintextMessageBinary == '01010100011010000110010100100000011100010111010101101001011000110110101100100000011000100111001001101111011101110110111000100000011001100110111101111000001000000110101001110101011011010111000001110011001000000110111101110110011001010111001000100000011101000110100001100101001000000110110001100001011110100111100100100000011001000110111101100111001011100010000001010100011010000110010100100000011100010111010101101001011000110110101100100000011000100111001001101111011101110110111000100000011001100110111101111000001000000110101001110101011011010111000001110011001000000110111101110110011001010111001000100000011101000110100001100101001000000110110001100001011110100111100100100000011001000110111101100111001011100010000001010100011010000110010100100000011100010111010101101001011000110110101100100000');
		ok(plaintextMessageBinary.length == common.messageSizeBinary);
	});
				
	/**
	 * ------------------------------------------------------------------
	 * Get a random MAC algorithm index from the list of MAC algorithms
	 * ------------------------------------------------------------------
	 */
		
	var randomMacIndex = common.getRandomMacAlgorithmIndex();
	var randomMacAlgorithm = common.macAlgorithms[randomMacIndex];
	
	// Test in range
	var macIndexMaximum = common.macAlgorithms.length - 1;
	var testMacIndex = ((randomMacIndex >=0) && (randomMacIndex <= macIndexMaximum));	
		
	test("Get a random MAC algorithm index from the list of MAC algorithms", function()
	{
		ok(testMacIndex == true, randomMacIndex.toString() + ' ' + randomMacAlgorithm);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Prepare message for encryption
	 * ------------------------------------------------------------------
	 */
		
	var messagePartsBinary = common.prepareMessageForEncryption(plaintextMessageMax, plaintextMessageLength, plaintextMessageTimestamp, plaintextMessageMacAlgorithmIndex);
		
	test("Prepare message for encryption", function()
	{
		ok(messagePartsBinary == '010101000110100001100101001000000111000101110101011010010110001101101011001000000110001001110010011011110111011101101110001000000110011001101111011110000010000001101010011101010110110101110000011100110010000001101111011101100110010101110010001000000111010001101000011001010010000001101100011000010111101001111001001000000110010001101111011001110010111000100000010101000110100001100101001000000111000101110101011010010110001101101011001000000110001001110010011011110111011101101110001000000110011001101111011110000010000001101010011101010110110101110000011100110010000001101111011101100110010101110010001000000111010001101000011001010010000001101100011000010111101001111001001000000110010001101111011001110010111000100000010101000110100001100101001000000111000101110101011010010110001101101011001000000011000100110000001100000011000100110011001101110011010000110010001100110011011100111000001101110011000000110001');
		ok(messagePartsBinary.length == common.messageSizeBinary + common.messageLengthSizeBinary + common.messageTimestampSizeBinary + common.macAlgorithmSizeBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Convert the one-time pad from hexadecimal to binary
	 * ------------------------------------------------------------------
	 */
	
	var padBinary = common.convertHexadecimalToBinary(pad);
	
	test("Convert one-time pad from hexadecimal to binary", function()
	{
		ok(padBinary == '0111101010101101111111000000101010000011101100011110110111001110000001110010101101100010010010101110000001111111110101011111111010100001110001010000100110101101010001101101011100111101011000111100010010000010010010111000001000001000010000100111111100111000010010010111110011111100010011011100010111110100110010101011001100111101111111001000110101001101100001010011111111110111100101111000011001100110011000101011110001110101101101101100111111010010011101110101011010101001110100001101011111010110010100010010101100001001111101111111010101010111011010000010001111011111010011110000101111110011111011100101011001000000101000001001011001001010001010111001001000100111111110001110100010000011100011010010010001010001010111110110000101011110000011101111101010000001011000110011011101010111111110111001000011110011011101000000110100011111100100001011111100100100100110110001110111010100010000001110010010100011011111100101101101001011111101000010000111010100000000110000111111000101011110000101010110100111000011110010000100101101111010011111011100100010010111001100110110010100111101111100010010011110100010000000110110110110010101101011101100000001100001011111100010001011110010000111100101101011110100100001010000001101111011110000010010101100001011110111110110100110111010001101001010100010111101111000000100001111110110101101110000011101110111000111110111110101101010111001010101011110110000110100111000001000111101110000010001100101001001011101101010010100000001110111010010110001');
		ok(padBinary.length == common.totalPadSizeBinary);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Get the pad identifier from pad in binary
	 * ------------------------------------------------------------------
	 */
	
	var padIdentifier = common.getPadIdentifier(padBinary);
	
	test("Get the pad identifier from pad in binary", function()
	{
		ok(padIdentifier == '01111010101011011111110000001010100000111011000111101101');
		ok(padIdentifier.length == common.padIdentifierSizeBinary);
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
		ok(padMessagePartsBinary == '110011100000011100101011011000100100101011100000011111111101010111111110101000011100010100001001101011010100011011010111001111010110001111000100100000100100101110000010000010000100001001111111001110000100100101111100111111000100110111000101111101001100101010110011001111011111110010001101010011011000010100111111111101111001011110000110011001100110001010111100011101011011011011001111110100100111011101010110101010011101000011010111110101100101000100101011000010011111011111110101010101110110100000100011110111110100111100001011111100111110111001010110010000001010000010010110010010100010101110010010001001111111100011101000100000111000110100100100010100010101111101100001010111100000111011111010100000010110001100110111010101111111101110010000111100110111010000001101000111111001000010111111001001001001101100011101110101000100000011100100101000110111111001011011010010111111010000100001110101000000001100001111');
		ok(padMessagePartsBinaryLength == common.messageSizeBinary + common.messageLengthSizeBinary + common.messageTimestampSizeBinary + common.macAlgorithmSizeBinary);
		ok(padMessagePartsBinaryLength == common.totalMessagePartsSizeBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Encrypt the message parts with the pad message parts
	 * ------------------------------------------------------------------
	 */
	var encryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, messagePartsBinary);
		
	test("Encrypt the message parts with the pad message parts", function()
	{
		ok(encryptedMessagePartsBinary == '100110100110111101001110010000100011101110010101000101101011011010010101100000011010011101111011110000100011000110111001000111010000010110101011111110100110101111101000011111010010111100001111010010110110100100010011100010100010100010110111110101001011111011011011010110001101110011100001001011001111111101000110110101111111001111101001000000010100110010011100001000011101111010101010111100100000011000100011110000001011001110111100111101100011001101011001011001101000000010011011011101110000111001001100101001110110111101100001100001101000001100100110001100111000000011111001001111000100111011100000000001111000110010000000111001101010110101001000001100000010010100011000011111100110101010010101111001100100110100010111000000111001001111110101110100110000010101111000011101101111001111010100000001001010101000101101111001000111000111010111100101000100101001101001011110001100001100011001111000110011001100111110');
		ok(encryptedMessagePartsBinary.length == common.totalMessagePartsSizeBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Combine pad identifier and the ciphertext message parts
	 * ------------------------------------------------------------------
	 */
	
	var completeCiphertextBinary = common.combinePadIdentifierAndCiphertext(padIdentifier, encryptedMessagePartsBinary);
		
	test("Combine pad identifier and the ciphertext message parts", function()
	{
		ok(completeCiphertextBinary == '01111010101011011111110000001010100000111011000111101101100110100110111101001110010000100011101110010101000101101011011010010101100000011010011101111011110000100011000110111001000111010000010110101011111110100110101111101000011111010010111100001111010010110110100100010011100010100010100010110111110101001011111011011011010110001101110011100001001011001111111101000110110101111111001111101001000000010100110010011100001000011101111010101010111100100000011000100011110000001011001110111100111101100011001101011001011001101000000010011011011101110000111001001100101001110110111101100001100001101000001100100110001100111000000011111001001111000100111011100000000001111000110010000000111001101010110101001000001100000010010100011000011111100110101010010101111001100100110100010111000000111001001111110101110100110000010101111000011101101111001111010100000001001010101000101101111001000111000111010111100101000100101001101001011110001100001100011001111000110011001100111110');
		ok(completeCiphertextBinary.length == common.padIdentifierSizeBinary + common.totalMessagePartsSizeBinary);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Convert the complete ciphertext binary to hexadecimal
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextHex = common.convertBinaryToHexadecimal(completeCiphertextBinary);
		
	test("Convert the complete ciphertext binary to hexadecimal", function()
	{
		ok(ciphertextHex == '7aadfc0a83b1ed9a6f4e423b9516b69581a77bc231b91d05abfa6be87d2f0f4b69138a28b7d4bedb58dce12cff46d7f3e9014c9c21deaaf20623c0b3bcf6335966809b770e4ca76f618683263380f93c4ee0078c80e6ad483025187e6a95e64d170393f5d3057876f3d404aa2de471d7944a6978c319e3333e');
		ok(ciphertextHex.length == common.padIdentifierSizeHex + common.totalMessagePartsSizeHex);
	});
			
	/**
	 * ------------------------------------------------------------------
	 * Test hashing with SHA-3 Keccak 512 bit
	 * ------------------------------------------------------------------
	 */
	
	// The quick brown fox jumps over the lazy dog.
	var plaintextMessageComplete = plaintextMessage + '.';
	
	test("Test 512 bit hash using SHA-3 Keccak", function()
	{
		ok(common.secureHash('sha3-512', '') == '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e', 'empty string');
		ok(common.secureHash('sha3-512', plaintextMessage) == 'd135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609', plaintextMessage);
		ok(common.secureHash('sha3-512', plaintextMessageComplete) == 'ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760', plaintextMessageComplete);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test hashing with Whirlpool 512 bit
	 * ------------------------------------------------------------------
	 */
		
	test("Test 512 bit hash using Whirlpool", function()
	{
		ok(common.secureHash('whirlpool-512', '') == '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3', 'empty string');
		ok(common.secureHash('whirlpool-512', plaintextMessage) == 'b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35', plaintextMessage);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test SHA2 512 bit HMAC algorithm
	 * ------------------------------------------------------------------
	 */
	
	var sha2hmac = common.secureMac('hmac-sha2-512', pad, plaintextMessage)
		
	// CryptoJS:  9e2e95b1725a6dea1890d8be24dd395746bddaa2ab7c5e524fe274fc3424c105582a4c51f58b2cddac1ea99f3c84da66d980a99f0131c294a2515772f75c3cce
	// JS SHA:    9e2e95b1725a6dea1890d8be24dd395746bddaa2ab7c5e524fe274fc3424c105582a4c51f58b2cddac1ea99f3c84da66d980a99f0131c294a2515772f75c3cce
	// JS Digest: 9e2e95b1725a6dea1890d8be24dd395746bddaa2ab7c5e524fe274fc3424c105582a4c51f58b2cddac1ea99f3c84da66d980a99f0131c294a2515772f75c3cce	
	test("Test SHA2 512 bit HMAC algorithm", function()
	{
		ok(sha2hmac == '9e2e95b1725a6dea1890d8be24dd395746bddaa2ab7c5e524fe274fc3424c105582a4c51f58b2cddac1ea99f3c84da66d980a99f0131c294a2515772f75c3cce', sha2hmac);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test SHA3 512 bit HMAC algorithm
	 * ------------------------------------------------------------------
	 */
	
	var sha3hmac = common.secureMac('hmac-sha3-512', pad, plaintextMessage)
		
	test("Test SHA3 512 bit HMAC algorithm", function()
	{
		ok(sha3hmac == '0371ff42e77ed45949d7adc3749953d3112495e3e013f3424c380bc2fbecf35884d69bceeb577798181cc50d13f10879214b60cae47475026628b760e603a89b', sha3hmac);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test Skein 512 bit HMAC algorithm
	 * ------------------------------------------------------------------
	 */
	
	var skeinHmac = common.secureMac('hmac-skein-512', pad, plaintextMessage);
		
	test("Test Skein 512 bit HMAC algorithm", function()
	{
		ok(skeinHmac == '40ca93092bcb18734c7b230c1222267dc9e9ebc2621f62dc642cded7df75c9ab98f020afe8a139a13b52e51e1abaf17cbc100c7868a69ca7959be3f1d7e34a62', skeinHmac);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test creation of MAC for chat program
	 * ------------------------------------------------------------------
	 */
	
	var mac = common.createMac(plaintextMessageMacAlgorithmIndex, pad, ciphertextHex);
	
	test("Test creation of MAC for chat program", function()
	{
		ok(mac == '1853dcc02ec4854c9ab4685c30932b87e098e960a2fe9ba7cc3782500a6dcdc095fdbd7f6803d753f3ac69f7a7288085a9f08fc05fb33ab8ef69e6ac836dd30f', mac);
	});

	/**
	 * ------------------------------------------------------------------
	 * Get MAC part of the one-time pad to use for encrypting the MAC
	 * ------------------------------------------------------------------
	 */

	var padForMac = common.getPadPartForMac(pad);

	test("Get MAC part of the one-time pad to use for encrypting the MAC", function()
	{
		ok(padForMac == 'c57855a70f212de9f7225ccd94f7c49e880db656bb0185f88bc8796bd2140def04ac2f7da6e8d2a2f7810fdadc1ddc7df5ab955ec34e08f7046525da940774b1', padForMac);
		ok(padForMac.length == common.macSizeHex, padForMac.length);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Encrypt the MAC with one-time pad
	 * ------------------------------------------------------------------
	 */
	
	var encryptedMac = common.encryptOrDecryptMac(padForMac, mac);
	
	test("Encrypt the MAC with one-time pad", function()
	{
		ok(encryptedMac == 'dd2b896721e5a8a56d963491a464ef1968955f3619ff1e5f47fffb3bd879c02f91519202ceeb05f1042d662d7b355cf85c5b1a9e9cfd324feb0cc376176aa7be', encryptedMac);
		ok(encryptedMac.length == common.macSizeHex, encryptedMac.length);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Convert the ciphertext hexadecimal back to binary
	 * ------------------------------------------------------------------
	 */
		
	var ciphertextBinaryConvertedFromHex = common.convertHexadecimalToBinary(ciphertextHex);
	
	test("Convert the ciphertext hexadecimal back to binary", function()
	{
		ok(ciphertextBinaryConvertedFromHex == completeCiphertextBinary);
		ok(ciphertextBinaryConvertedFromHex.length == common.padIdentifierSizeBinary + common.totalMessagePartsSizeBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Get message ciphertext parts from ciphertext
	 * ------------------------------------------------------------------
	 */
	
	var ciphertextMessageParts = common.getPadMessageParts(ciphertextBinaryConvertedFromHex);
	
	test("Get message ciphertext parts from ciphertext", function()
	{
		ok(ciphertextMessageParts == encryptedMessagePartsBinary);
		ok(ciphertextMessageParts.length == common.totalMessagePartsSizeBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Decrypt binary ciphertext message parts to binary plaintext message parts
	 * ------------------------------------------------------------------
	 */
	
	var decryptedMessagePartsBinary = common.encryptOrDecrypt(padMessagePartsBinary, ciphertextMessageParts);
	
	test("Decrypt ciphertext message parts to plaintext message parts binary", function()
	{
		ok(decryptedMessagePartsBinary == messagePartsBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Convert decrypted binary message parts back to ASCII plaintext message parts
	 * ------------------------------------------------------------------
	 */		
	var decryptedPlaintextMessageParts = common.convertBinaryToText(decryptedMessagePartsBinary);
	
	test("Convert decrypted binary message parts back to ASCII plaintext message parts", function()
	{
		ok(decryptedPlaintextMessageParts == plaintextMessageMax + plaintextMessageLength + plaintextMessageTimestamp + plaintextMessageMacAlgorithmIndex, decryptedPlaintextMessageParts);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Split up ASCII plaintext message parts
	 * ------------------------------------------------------------------
	 */		
	
	var messageParts = common.getSeparateMessageParts(decryptedPlaintextMessageParts);	
	var messagePlaintextWithPadding = messageParts.messagePlaintextWithPadding;
	var actualMessageLength = messageParts.messageLength;
	var messageTimestamp = messageParts.messageTimestamp;
	var macAlgorithmIndex = messageParts.macAlgorithmIndex;
	
	test("Split up ASCII plaintext message parts", function()
	{
		ok(messagePlaintextWithPadding == plaintextMessageMax, messagePlaintextWithPadding);
		ok(actualMessageLength == plaintextMessageLength, actualMessageLength);
		ok(messageTimestamp == plaintextMessageTimestamp, messageTimestamp);
		ok(macAlgorithmIndex == plaintextMessageMacAlgorithmIndex, macAlgorithmIndex);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Get plaintext message without padding
	 * ------------------------------------------------------------------
	 */	
	
	var messageWithPadding = 'The quick brown fox jumps over the lazy dog952389192387465102748921721097841547812937419547217419572';
	var lengthOfMessage = '043';
	var messageWithoutPadding = common.removePaddingFromMessage(messageWithPadding, lengthOfMessage);
	
	// Extra tests to make sure only digits allowed
	var lengthOfMessageTestA = '1';		// min
	var lengthOfMessageTestB = 'abc';	// non digit
	var lengthOfMessageTestC = '-99';	// negative
	var lengthOfMessageTestD = '999';	// max int
	var lengthOfMessageTestE = '100';	// max message size
	var lengthOfMessageTestF = '101';	// exceed max message size
	var lengthOfMessageTestG = '0';		// below min
	
	// Test removing the padding (the last 3 should fail the checks and return the full message with padding)
	var messageWithoutPaddingA = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestA);
	var messageWithoutPaddingB = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestB);
	var messageWithoutPaddingC = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestC);
	var messageWithoutPaddingD = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestD);
	var messageWithoutPaddingE = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestE);
	var messageWithoutPaddingF = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestF);
	var messageWithoutPaddingG = common.removePaddingFromMessage(messageWithPadding, lengthOfMessageTestG);
		
	test("Get plaintext message without padding", function()
	{
		ok(messageWithoutPadding == plaintextMessage, messageWithoutPadding);
		ok(messageWithoutPadding.length == parseInt(lengthOfMessage), lengthOfMessage);
		ok(messageWithoutPaddingA == 'T', messageWithoutPaddingA);
		ok(messageWithoutPaddingB == messageWithPadding, messageWithoutPaddingB);
		ok(messageWithoutPaddingC == messageWithPadding, messageWithoutPaddingC);
		ok(messageWithoutPaddingD == messageWithPadding, messageWithoutPaddingD);
		ok(messageWithoutPaddingE == messageWithPadding, messageWithoutPaddingE);
		ok(messageWithoutPaddingF == messageWithPadding, messageWithoutPaddingF);
		ok(messageWithoutPaddingG == messageWithPadding, messageWithoutPaddingG);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Encrypt and decrypt all possible ASCII characters
	 * ------------------------------------------------------------------
	 */
	var binaryPad = common.convertTextToBinary(pad);	
	var binaryPlaintext = common.convertTextToBinary(common.allPossibleChars.join(''));	
	var binaryEncryptedMessage = common.encryptOrDecrypt(binaryPad, binaryPlaintext);
	var hexadecimalEncryptedMessage = common.convertBinaryToHexadecimal(binaryEncryptedMessage);
	var binaryDecryptedMessageFromHex = common.convertHexadecimalToBinary(hexadecimalEncryptedMessage);
	var binaryDecryptedMessage = common.encryptOrDecrypt(binaryPad, binaryDecryptedMessageFromHex);
	var asciiPlaintext = common.convertBinaryToText(binaryDecryptedMessage);
	
	test("Encrypt and decrypt all possible ASCII characters", function()
	{
		ok(asciiPlaintext == common.allPossibleChars.join(''), asciiPlaintext);
	});
			
	/**
	 * ------------------------------------------------------------------
	 * Encrypt full length message to be ready for transport with wrapper function
	 * ------------------------------------------------------------------
	 */
	
	var output = common.encryptAndAuthenticateMessage(plaintextMessageMax, pad, plaintextMessageMax, plaintextMessageTimestamp, plaintextMessageMacAlgorithmIndex);
		
	test("Encrypt full length message to be ready for transport with wrapper function", function()
	{
		ok(output.ciphertext == '7aadfc0a83b1ed9a6f4e423b9516b69581a77bc231b91d05abfa6be87d2f0f4b69138a28b7d4bedb58dce12cff46d7f3e9014c9c21deaaf20623c0b3bcf6335966809b770e4ca76f618683263380f93c4ee0078c80e6ad483025187e6a95e64d170393f5d3057876f3d404aa2de471d7944a6978c319e3333e', 'ciphertext: ' + output.ciphertext);
		ok(output.mac == 'dd2b896721e5a8a56d963491a464ef1968955f3619ff1e5f47fffb3bd879c02f91519202ceeb05f1042d662d7b355cf85c5b1a9e9cfd324feb0cc376176aa7be', 'mac: ' + output.mac);
		ok(output.ciphertext.length == common.padIdentifierSizeHex + common.totalMessagePartsSizeHex, 'ciphertext length: ' + output.ciphertext.length);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Encrypt message to be ready for transport using test padding
	 * ------------------------------------------------------------------
	 */
	
	var testMessageWithPadding = 'The quick brown fox jumps over the lazy dog021384709235646758274219036756034157892374021968483915798';
	var result = common.encryptAndAuthenticateMessage(plaintextMessage, pad, testMessageWithPadding, plaintextMessageTimestamp, plaintextMessageMacAlgorithmIndex);

	test("Encrypt message to be ready for transport using test padding", function()
	{
		ok(result.ciphertext == '7aadfc0a83b1ed9a6f4e423b9516b69581a77bc231b91d05abfa6be87d2f0f4b69138a28b7d4bedb58dce12cff46d7f3e901528e4485f7e6406690e2e4e3671f3fc0c06f5a14eb7d3acade657697a37c1ba113c9ddb4b51d636c566a3ec8b05a016fcfa8c04d3c2aa7861cab29e771d7944a6978c319e3333e', 'ciphertext: ' + result.ciphertext);
		ok(result.mac == 'dc40b5de0ac2566c82827b23334dbc3894d2e178fa20406d6cd764192bbda43316b4124107142612fa1398b757da636364677f78d95cb12e6716ac8cca21eed6', 'mac: ' + result.mac);
		ok(result.ciphertext.length == common.padIdentifierSizeHex + common.totalMessagePartsSizeHex, 'ciphertext length: ' + result.ciphertext.length);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Encrypt message to be ready for transport using random padding and random MAC
	 * ------------------------------------------------------------------
	 */
	
	var results = common.encryptAndAuthenticateMessage(plaintextMessage, pad);

	test("Encrypt message to be ready for transport using random padding and random MAC", function()
	{
		// No point comparing the ciphertext or MAC to a fixed value because it will be different each time when the 
		// ciphertext is created with random padding and random MAC algorithm
		ok(results.ciphertext.length == common.padIdentifierSizeHex + common.totalMessagePartsSizeHex, 'ciphertext length: ' + results.ciphertext.length);
		ok(results.mac.length == common.macSizeHex, 'MAC length: ' + results.mac.length);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Decrypt the MAC
	 * ------------------------------------------------------------------
	 */
		
	var decryptedMac = common.encryptOrDecryptMac(padForMac, output.mac);
	
	test("Decrypt the MAC", function()
	{
		ok(decryptedMac == mac);
		ok(decryptedMac.length == common.macSizeHex, 'MAC length: ' + decryptedMac.length);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Test verification of MAC
	 * ------------------------------------------------------------------
	 */
	
	var validation = common.validateMac(messageParts.macAlgorithmIndex, pad, output.ciphertext, decryptedMac);
	
	test("Test verification of MAC", function()
	{
		ok(validation == true, decryptedMac);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Get the pad identifier from the ciphertext
	 * ------------------------------------------------------------------
	 */
	
	var padIdFromCiphertext = common.getPadIdentifierFromCiphertext(results.ciphertext);
		
	test("Get the pad identifier from the ciphertext", function()
	{
		ok(padIdFromCiphertext == '7aadfc0a83b1ed');
		ok(padIdFromCiphertext.length == common.padIdentifierSizeHex);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Decrypt and verify message with wrapper method
	 * ------------------------------------------------------------------
	 */
		
	var decryptionOutput = common.decryptAndVerifyMessage(results.ciphertext, pad, results.mac);
	
	test("Decrypt and verify message with wrapper method", function()
	{
		ok(decryptionOutput.plaintext == plaintextMessage, decryptionOutput.plaintext);
		ok(decryptionOutput.valid == true, 'message valid and authentic: ' + decryptionOutput.valid);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Decrypt and verify message with set padding and timestamp
	 * ------------------------------------------------------------------
	 */
	
	var decryptedOutput = common.decryptAndVerifyMessage(result.ciphertext, pad, result.mac);
	
	test("Decrypt and verify message with set padding and timestamp", function()
	{
		ok(decryptedOutput.plaintext == plaintextMessage, decryptionOutput.plaintext);
		ok(decryptedOutput.timestamp == plaintextMessageTimestamp, 'message sent: ' + new Date(decryptedOutput.timestamp * 1000));
		ok(decryptedOutput.valid == true, 'message valid and authentic: ' + decryptionOutput.valid);
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
		ok(allAsciiChars == common.allPossibleChars.join(''), allAsciiChars);
		ok(miscNonAllowedChars == 'abc  xyz', miscNonAllowedChars);
		ok(oversizePlaintext.length == common.messageSize, oversizePlaintext.length);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Fix the server URL for excess forward slashes
	 * ------------------------------------------------------------------
	 */
	
	test("Fix the server URL for excess forward slashes", function()
	{
		ok(common.standardiseUrl('http://localhost', 'send-message.php') == 'http://localhost/send-message.php');
		ok(common.standardiseUrl('http://localhost/', 'send-message.php') == 'http://localhost/send-message.php');
		ok(common.standardiseUrl('http://localhost/chatserver', 'send-message.php') == 'http://localhost/chatserver/send-message.php');
		ok(common.standardiseUrl('http://localhost/chatserver/', 'send-message.php') == 'http://localhost/chatserver/send-message.php');
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
		ok(encodedStringA == '&lt;script&gt;alert(&quot;xss&quot;);&lt;&#x2F;script&gt;', encodedStringA);
		ok(encodedStringB == '&lt;script&gt;alert(&#x27;xss&#x27;);&lt;&#x2F;script&gt;', encodedStringB);
		ok(encodedStringC == '&amp;&lt;&gt;&quot;&#x27;&#x2F;', encodedStringC);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test escaping of message for XSS and linkifying
	 * ------------------------------------------------------------------
	 */
	
	var linkedTextA = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/wiki/One-time_pad is a type of encryption that is impossible to crack if used correctly.');
	var linkedTextB = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/wiki/One-time_pad?test=<script>alert("xss);</script>');
	var linkedTextC = chat.convertLinksAndEscapeForXSS('The one-time pad http://en.wikipedia.org/<script>alert("xss);</script>/wiki/One-time_pad is a type of encryption');
	
	console.log(linkedTextC);
	
	test("Test escaping of message for XSS and linkifying", function()
	{
		ok(linkedTextA == 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/wiki/One-time_pad">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;wiki&#x2F;O...</a> is a type of encryption that is impossible to crack if used correctly.', linkedTextA);
		ok(linkedTextB == 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/wiki/One-time_pad?test=">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;wiki&#x2F;O...</a>&lt;script&gt;alert(&quot;xss);&lt;&#x2F;script&gt;', linkedTextB);
		ok(linkedTextC == 'The one-time pad <a target="_blank" href="http://en.wikipedia.org/">http:&#x2F;&#x2F;en.wikipedia.org&#x2F;</a>&lt;script&gt;alert(&quot;xss);&lt;&#x2F;script&gt;&#x2F;wiki&#x2F;One-time_pad is a type of encryption', linkedTextC);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test shuffle of array
	 * ------------------------------------------------------------------
	 */
	
	// Clone the array to avoid shuffling the actual array by reference (other tests rely on the order)
	var clonedHashAlgorithms = db.clone(common.hashAlgorithms);
	var shuffledHashAlgorithms = common.shuffleArray(clonedHashAlgorithms);
	
	var clonedPossibleAsciiChars = db.clone(common.allPossibleChars);
	var shuffledPossibleAsciiChars = common.shuffleArray(clonedPossibleAsciiChars);
	
	test("Test shuffle of arrays", function()
	{
		ok(shuffledHashAlgorithms.length == common.hashAlgorithms.length, shuffledHashAlgorithms.join(', '));
		ok(shuffledPossibleAsciiChars.length == common.allPossibleChars.length, shuffledPossibleAsciiChars.join(''));
	});
});