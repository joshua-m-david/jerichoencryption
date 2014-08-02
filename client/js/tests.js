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

// On page load run QUnit tests
$(document).ready(function()
{
	// Test data
	var pad = '72fa270d9148a82c056a62e32c5dbb916db2cba99efbc2c49533c5349bdeaeb4ec307e588b0cb125b4c23f07ccbac5d30b7736903cfb37a72ca6c189185546d401b48210cf46468a5615f2b63eaa7c415592a5bdad98bf47b3f49058ae278d7194567240a66f11755ead65cd194a36f30f7cf98d6c60fd45eca00a845922fc5d411f70a8b3d9c0dfaf69df60c42f6aec429ef479f3caa312ded2944546b93b49e09a53e679c999c99900a6bd93f93d2c2fcd387cb28625ab6c6bbd24baf9251c';
	var plaintextMessage = 'The quick brown fox jumps over the lazy dog';	
	var plaintextMessageMax = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps';
	var plaintextMessageMaxExceeded = 'The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.';
	var plaintextMessageLength = common.messageSize;
	var plaintextMessageTimestamp = 1374237870;
	var plaintextMessageMacAlgorithmIndex = 0;		// skein-512 - see common.macAlgorithms[1]
	
	/**
	 * ------------------------------------------------------------------
	 * Test if HTML5 Local Storage is supported in this browser
	 * ------------------------------------------------------------------
	 */
	
	var localStorageSupported = common.checkLocalStorageSupported();
	
	test("Test if HTML5 Local Storage is supported in this browser", function()
	{
		ok(localStorageSupported === true);
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
	 * Get the original plaintext length
	 * ------------------------------------------------------------------
	 */
	
	var originalPlaintextLength = common.getOriginalPlaintextLength(plaintextMessage);
	
	test("Get the original plaintext length", function()
	{
		ok(originalPlaintextLength === 43, originalPlaintextLength);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test plaintext which exceeds maximum and should return the max message size
	 * ------------------------------------------------------------------
	 */
	
	var maxPlaintextLength = common.getOriginalPlaintextLength(plaintextMessageMaxExceeded);
	
	test("Test plaintext which exceeds maximum and should return the max message size", function()
	{
		ok(maxPlaintextLength === common.messageSize, maxPlaintextLength);
	});
		
	/**
	 * ------------------------------------------------------------------
	 * Pad the message with random bits up to the maximum message size
	 * ------------------------------------------------------------------
	 */
	var plaintextMessageBinary = common.convertTextToBinary(plaintextMessage);
	var plaintextPaddedBinary = common.padMessage(plaintextMessageBinary);
		
	test("Pad the message with random numbers up to the maximum message size", function()
	{
		ok(plaintextPaddedBinary.length === common.messageSizeBinary, plaintextPaddedBinary);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test padding function on max length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxBinary = common.convertTextToBinary(plaintextMessageMax);
	var plaintextMessageMaxPadded = common.padMessage(plaintextMessageMaxBinary);
	
	test("Test padding function on max length plaintext", function()
	{
		// Message should be same, ie no padding added
		ok(plaintextMessageMaxBinary === plaintextMessageMaxPadded, plaintextMessageMaxPadded);
	});
	
	/**
	 * ------------------------------------------------------------------
	 * Test padding function on oversize length plaintext
	 * ------------------------------------------------------------------
	 */
	
	var plaintextMessageMaxExceededBinary = common.convertTextToBinary(plaintextMessageMaxExceeded);
	var plaintextMessageMaxExceededPadded = common.padMessage(plaintextMessageMaxExceededBinary);
	var plaintextMessageMaxExceededPaddedLength = plaintextMessageMaxExceededPadded.length;
			
	test("Test padding function on oversize length plaintext", function()
	{
		// Message should be truncated, ie no padding added
		ok(plaintextMessageMaxExceededPadded === plaintextMessageMaxBinary, plaintextMessageMaxExceededPadded);
		ok(plaintextMessageMaxExceededPaddedLength === common.messageSizeBinary, plaintextMessageMaxExceededPaddedLength);
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
		ok(padBinaryLength == common.totalPadSizeBinary, padBinaryLength);
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
		ok(padIdentifierLength == common.padIdentifierSizeBinary, padIdentifierLength);
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
		ok(ciphertextHex == '72fa270d9148a85929fde8e3e293b527c3e4cfb7689dc6b27bc58b729f08682242be7afe9d26b5515234190352e443e50fd120be38b591c9daa20f87aefb10d01f42e414b9a8b0c410112470a804f245f3848fb9d97e4961b76acede98232b67ba523ce6c89915bb501bcb9b1d54c0950b0a177b2226f9932a36a40a5d84ea77');
		ok(ciphertextHex.length == common.padIdentifierSizeHex + common.totalMessagePartsSizeHex);
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
	
	test("asic encryption and decryption of all possible ASCII characters", function()
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
		ok(common.standardiseUrl('http://localhost', 'send-message.php') === 'http://localhost/send-message.php');
		ok(common.standardiseUrl('http://localhost/', 'send-message.php') === 'http://localhost/send-message.php');
		ok(common.standardiseUrl('http://localhost/chatserver', 'send-message.php') === 'http://localhost/chatserver/send-message.php');
		ok(common.standardiseUrl('http://localhost/chatserver/', 'send-message.php') === 'http://localhost/chatserver/send-message.php');
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
	 * Testing of nonce generation
	 * ------------------------------------------------------------------
	 */
	
	var nonceA = common.getRandomNonce();
	var nonceB = common.getRandomNonce();
	var nonceC = common.getRandomNonce();	
	var noRepeat = (nonceA !== nonceB) && (nonceA !== nonceC) && (nonceB !== nonceC);
	
	test("Testing of nonce generation", function()
	{
		// Check lengths equals 128 hexadecimal chars (512 bits)
		ok(nonceA.length === 128, nonceA);
		ok(nonceB.length === 128, nonceB);
		ok(nonceC.length === 128, nonceC);
		
		// Check no repeating nonces
		ok(noRepeat === true, 'No repeat: ' + noRepeat.toString());
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
	var serverAddressAndPort = 'http://127.0.0.1/jericho/server/';
	var serverKey = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';

	// Send a request off to the server to check the connection
	common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseDataJson)
	{
		console.log('Valid response: ' + validResponse.toString());
		console.log(responseDataJson);
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
	
	// Set test ciphertext as just one of the pads, it should find it based on the padId
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
	
	var indexForFindingD = 4;
	var ciphertextForFindingD = db.padData.pads[fromUser][indexForFindingD].pad;
	var padIdentifierForFindingD = db.padData.pads[fromUser][indexForFindingD].padIdentifier;
	var foundPadDataD = common.getPadToDecryptMessage(ciphertextForFindingD, fromUser);
	
	var indexForFindingE = 5;
	var ciphertextForFindingE = db.padData.pads[fromUser][indexForFindingE].pad;
	var padIdentifierForFindingE = db.padData.pads[fromUser][indexForFindingE].padIdentifier;
	var foundPadDataE = common.getPadToDecryptMessage(ciphertextForFindingE, fromUser);
	
	var indexForFindingF = 6;
	var ciphertextForFindingF = db.padData.pads[fromUser][indexForFindingF].pad;
	var padIdentifierForFindingF = db.padData.pads[fromUser][indexForFindingF].padIdentifier;
	var foundPadDataF = common.getPadToDecryptMessage(ciphertextForFindingF, fromUser);
	
	var indexForFindingG = 7;
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
	
});