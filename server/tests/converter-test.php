<?php
/**
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


use Jericho\Converter;
use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the conversion methods
 */
class ConverterTest extends TestCase
{
	/**
	 * @var Converter $converter The common conversion functions
	 */
	private $converter;

	/**
	 * Main setup which is run for each unit test
	 */
	protected function setUp(): void
	{
		// Load the helper functions
		$this->converter = new Converter();
	}

	public function testLoadConfig()
	{
		// Get the absolute path to the test configuration file e.g. /var/www/html/tests/config/config.json
		$configFilePath = realpath(__DIR__ . '/config/config.json');

		// Load the configuration into memory
		$config = $this->converter->loadAndDecodeConfig($configFilePath);

		$this->assertSame('127.0.0.1', $config['databaseConfig']['databaseHostname']);
		$this->assertSame(true, $config['applicationConfig']['testResponseHeaders']);
		$this->assertSame('aabbccddeeff0011', $config['groupConfigs'][0]['groupId']);
	}

	public function testConvertNumOfHexSymbolsToNumOfBits()
	{
		// Test converting the number of hex symbols to the number of bits those symbols represent
		$numOfBitsA = $this->converter->convertNumOfHexSymbolsToNumOfBits(2);
		$numOfBitsB = $this->converter->convertNumOfHexSymbolsToNumOfBits(4);
		$numOfBitsC = $this->converter->convertNumOfHexSymbolsToNumOfBits(64);

		$this->assertSame(8, $numOfBitsA);
		$this->assertSame(16, $numOfBitsB);
		$this->assertSame(256, $numOfBitsC);
	}

	public function testConvertNumOfHexSymbolsToNumOfBytes()
	{
		// Test converting the number of hex symbols to the number of bits those symbols represent
		$numOfBytesA = $this->converter->convertNumOfHexSymbolsToNumOfBytes(2);
		$numOfBytesB = $this->converter->convertNumOfHexSymbolsToNumOfBytes(4);
		$numOfBytesC = $this->converter->convertNumOfHexSymbolsToNumOfBytes(64);

		$this->assertSame(1, $numOfBytesA);
		$this->assertSame(2, $numOfBytesB);
		$this->assertSame(32, $numOfBytesC);
	}

	public function testConvertNumOfBitsToNumOfHexSymbols()
	{
		// Test converting number of bits to number of hex symbols
		$numOfHexSymbolsA = $this->converter->convertNumOfBitsToNumOfHexSymbols(8);
		$numOfHexSymbolsB = $this->converter->convertNumOfBitsToNumOfHexSymbols(16);
		$numOfHexSymbolsC = $this->converter->convertNumOfBitsToNumOfHexSymbols(256);

		$this->assertSame(2, $numOfHexSymbolsA);
		$this->assertSame(4, $numOfHexSymbolsB);
		$this->assertSame(64, $numOfHexSymbolsC);
	}

	public function testConvertNumOfBitsToNumOfBytes()
	{
		// Test converting number of bits to number of hex symbols
		$numOfBytesA = $this->converter->convertNumOfBitsToNumOfBytes(8);
		$numOfBytesB = $this->converter->convertNumOfBitsToNumOfBytes(16);
		$numOfBytesC = $this->converter->convertNumOfBitsToNumOfBytes(256);

		$this->assertSame(1, $numOfBytesA);
		$this->assertSame(2, $numOfBytesB);
		$this->assertSame(32, $numOfBytesC);
	}

	public function testConvertingBinaryToHexadecimalAndBack()
	{
		// Binary (padded to 4 bits) <-> hex mappings
		$binaryStrings = [
			[ 'binary' => '0000', 'hex' => '0' ],
			[ 'binary' => '0001', 'hex' => '1' ],
			[ 'binary' => '0010', 'hex' => '2' ],
			[ 'binary' => '0011', 'hex' => '3' ],
			[ 'binary' => '0100', 'hex' => '4' ],
			[ 'binary' => '0101', 'hex' => '5' ],
			[ 'binary' => '0110', 'hex' => '6' ],
			[ 'binary' => '0111', 'hex' => '7' ],
			[ 'binary' => '1000', 'hex' => '8' ],
			[ 'binary' => '1001', 'hex' => '9' ],
			[ 'binary' => '1010', 'hex' => 'a' ],
			[ 'binary' => '1011', 'hex' => 'b' ],
			[ 'binary' => '1100', 'hex' => 'c' ],
			[ 'binary' => '1101', 'hex' => 'd' ],
			[ 'binary' => '1110', 'hex' => 'e' ],
			[ 'binary' => '1111', 'hex' => 'f' ]
		];

		$binaryString = '';
		$hexString = '';

		// Join the strings together to test conversion altogether
		for ($i = 0; $i < count($binaryStrings); $i++)
		{
			$binaryString .= $binaryStrings[$i]['binary'];
			$hexString .= $binaryStrings[$i]['hex'];
		}

		// Do the conversions
		$conversionFromBinaryToHex = $this->converter->convertBinaryStringToHex($binaryString);
		$conversionFromHexToBinary = $this->converter->convertHexToBinaryString($hexString);

		$this->assertSame($conversionFromBinaryToHex, $hexString);
		$this->assertSame($conversionFromHexToBinary, $binaryString);
	}

	public function testConvertHexadecimalToInteger()
	{
		// Test converting hexadecimal strings to integers
		$hexStringA = '0000';
		$intA = $this->converter->convertHexToInt($hexStringA);
		$expectedIntA = 0;

		$hexStringB = '0001';
		$intB = $this->converter->convertHexToInt($hexStringB);
		$expectedIntB = 1;

		$hexStringC = '0164';
		$intC = $this->converter->convertHexToInt($hexStringC);
		$expectedIntC = 356;

		$hexStringD = '00e2';
		$intD = $this->converter->convertHexToInt($hexStringD);
		$expectedIntD = 226;

		$this->assertSame($expectedIntA, $intA);
		$this->assertSame($expectedIntB, $intB);
		$this->assertSame($expectedIntC, $intC);
		$this->assertSame($expectedIntD, $intD);
	}

	public function testConvertNumOfBytesToNumOfHexSymbols()
	{
		// Convert number of bytes to number of hex symbols
		$numOfHexSymbolsA = $this->converter->convertNumOfBytesToNumOfHexSymbols(1);
		$expectedNumOfHexSymbolsA = 2;

		$numOfHexSymbolsB = $this->converter->convertNumOfBytesToNumOfHexSymbols(2);
		$expectedNumOfHexSymbolsB = 4;

		$numOfHexSymbolsC = $this->converter->convertNumOfBytesToNumOfHexSymbols(32);
		$expectedNumOfHexSymbolsC = 64;

		$this->assertSame($expectedNumOfHexSymbolsA, $numOfHexSymbolsA);
		$this->assertSame($expectedNumOfHexSymbolsB, $numOfHexSymbolsB);
		$this->assertSame($expectedNumOfHexSymbolsC, $numOfHexSymbolsC);
	}

	public function testConvertNumOfBytesToNumOfBase64Chars()
	{
		$bytesTestA = 'AB';
		$bytesLengthTestA = strlen($bytesTestA);
		$expectedBase64TestA = base64_encode($bytesTestA);
		$expectedBase64LengthTestA = strlen($expectedBase64TestA);
		$actualBase64LengthTestA = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestA);

		$bytesTestB = 'ABC';
		$bytesLengthTestB = strlen($bytesTestB);
		$expectedBase64TestB = base64_encode($bytesTestB);
		$expectedBase64LengthTestB = strlen($expectedBase64TestB);
		$actualBase64LengthTestB = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestB);

		$bytesTestC = 'ABCD';
		$bytesLengthTestC = strlen($bytesTestC);
		$expectedBase64TestC = base64_encode($bytesTestC);
		$expectedBase64LengthTestC = strlen($expectedBase64TestC);
		$actualBase64LengthTestC = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestC);

		$bytesTestD = 'ABCDEFG';
		$bytesLengthTestD = strlen($bytesTestD);
		$expectedBase64TestD = base64_encode($bytesTestD);
		$expectedBase64LengthTestD = strlen($expectedBase64TestD);
		$actualBase64LengthTestD = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestD);

		$bytesTestE = 'ABCDEFGabcdefg';
		$bytesLengthTestE = strlen($bytesTestE);
		$expectedBase64TestE = base64_encode($bytesTestE);
		$expectedBase64LengthTestE = strlen($expectedBase64TestE);
		$actualBase64LengthTestE = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestE);

		$bytesTestF = 'ABCDEFGabcdefg1234567';
		$bytesLengthTestF = strlen($bytesTestF);
		$expectedBase64TestF = base64_encode($bytesTestF);
		$expectedBase64LengthTestF = strlen($expectedBase64TestF);
		$actualBase64LengthTestF = $this->converter->convertNumOfBytesToNumOfBase64Chars($bytesLengthTestF);

		$this->assertSame($expectedBase64LengthTestA, $actualBase64LengthTestA);
		$this->assertSame($expectedBase64LengthTestB, $actualBase64LengthTestB);
		$this->assertSame($expectedBase64LengthTestC, $actualBase64LengthTestC);
		$this->assertSame($expectedBase64LengthTestD, $actualBase64LengthTestD);
		$this->assertSame($expectedBase64LengthTestE, $actualBase64LengthTestE);
		$this->assertSame($expectedBase64LengthTestF, $actualBase64LengthTestF);
	}

	public function testConvertTextToHexadecimal()
	{
		$textA = 'qwertyuiopasdfghjklzxcvbnm';
		$expectedLengthA = $this->converter->convertNumOfBytesToNumOfHexSymbols(strlen($textA));
		$conversionA = $this->converter->convertTextToHex('qwertyuiopasdfghjklzxcvbnm', $expectedLengthA);
		$expectedConversionA = '71776572747975696f706173646667686a6b6c7a786376626e6d';

		$textB = 'QWERTYUIOPASDFGHJKLZXCVBNM';
		$expectedLengthB = $this->converter->convertNumOfBytesToNumOfHexSymbols(strlen($textA));
		$conversionB = $this->converter->convertTextToHex($textB, $expectedLengthB);
		$expectedConversionB = '51574552545955494f504153444647484a4b4c5a584356424e4d';

		$textC = '1234567890';
		$expectedLengthC = $this->converter->convertNumOfBytesToNumOfHexSymbols(strlen($textC));
		$conversionC = $this->converter->convertTextToHex($textC, $expectedLengthC);
		$expectedConversionC = '31323334353637383930';

		$this->assertSame($expectedConversionA, $conversionA);
		$this->assertSame($expectedLengthA, strlen($conversionA));

		$this->assertSame($expectedConversionB, $conversionB);
		$this->assertSame($expectedLengthB, strlen($conversionB));

		$this->assertSame($expectedConversionC, $conversionC);
		$this->assertSame($expectedLengthC, strlen($conversionC));
	}

	public function testConvertIntegerToHexadecimal()
	{
		$intA = 0;
		$expectedLengthA = $this->converter->convertNumOfBytesToNumOfHexSymbols(1);
		$conversionA = $this->converter->convertIntToHex($intA, $expectedLengthA);
		$expectedConversionA = '00';

		$intB = 255;
		$expectedLengthB = $this->converter->convertNumOfBytesToNumOfHexSymbols(1);
		$conversionB = $this->converter->convertIntToHex($intB, $expectedLengthB);
		$expectedConversionB = 'ff';

		$intC = 65535;
		$expectedLengthC = $this->converter->convertNumOfBytesToNumOfHexSymbols(2);
		$conversionC = $this->converter->convertIntToHex($intC, $expectedLengthC);
		$expectedConversionC = 'ffff';

		$this->assertSame($expectedConversionA, $conversionA);
		$this->assertSame($expectedLengthA, strlen($conversionA));

		$this->assertSame($expectedConversionB, $conversionB);
		$this->assertSame($expectedLengthB, strlen($conversionB));

		$this->assertSame($expectedConversionC, $conversionC);
		$this->assertSame($expectedLengthC, strlen($conversionC));
	}
}
