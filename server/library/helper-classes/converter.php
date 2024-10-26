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


namespace Jericho;


/**
 * Converter helper methods
 */
class Converter
{
	/**
	 * Loads the configuration from a file e.g. config/config.json and decodes it from JSON into an array
	 * @param string $configFilePath The absolute path to the config file
	 * @return array Returns the configuration decoded from JSON into an associative array
	 */
	public function loadAndDecodeConfig($configFilePath)
	{
		// Load the file
		$configJson = file_get_contents($configFilePath);

		// Decode into an array
		$config = json_decode($configJson, true);

		return $config;
	}

	/**
	 * Converts the number of hex symbols to the number of bits those symbols represent.
	 * E.g. the number of hex symbols in the string '5f0a' is 4 and the number in bits this represents is 16.
	 * @param int $numOfHexSymbols The number of hexadecimal symbols e.g. 4
	 * @return int Returns the number of bits those symbols represent e.g. 16
	 */
	public function convertNumOfHexSymbolsToNumOfBits($numOfHexSymbols)
	{
		return $numOfHexSymbols * 4;
	}

	/**
	 * Converts the number of hex symbols to the number of bytes those symbols represent.
	 * E.g. the number of hex symbols in the string '5f0a' is 4 and the number in bytes this represents is 2.
	 * @param int $numOfHexSymbols The number of hexadecimal symbols e.g. 4
	 * @return int Returns the number of bytes those symbols represent e.g. 2
	 */
	public function convertNumOfHexSymbolsToNumOfBytes($numOfHexSymbols)
	{
		return $numOfHexSymbols / 2;
	}

	/**
	 * Converts the number of bits to the number of hexadecimal symbols those bits represent.
	 * E.g. the number of bits in the string '0101111100001010' is 16 and the number in hex symbols this represents is 4.
	 * NB: The number of bits must be cleanly divisible into full hexadecimal symbols.
	 * @param int $numOfBits The number of bits e.g. 16
	 * @return int Returns the number of hex symbols if it was converted e.g. 4
	 */
	public function convertNumOfBitsToNumOfHexSymbols($numOfBits)
	{
		return $numOfBits / 4;
	}

	/**
	 * Converts the number of bits to the number of bytes those bits represent.
	 * E.g. the number of bits in the string '0101111100001010' is 16 and the number in bytes this represents is 2.
	 * NB: The number of bits must be cleanly divisible into full bytes.
	 * @param int $numOfBits The number of bits e.g. 16
	 * @return int Returns the number of bytes if it was converted e.g. 2
	 */
	public function convertNumOfBitsToNumOfBytes($numOfBits)
	{
		return $numOfBits / 8;
	}

	/**
	 * Converts hexadecimal code to binary code
	 * @param string hexString A string containing single digit hexadecimal numbers e.g. '0f'
	 * @return string A string containing binary numbers e.g. '00001111'
	 */
	public function convertHexToBinaryString($hexString)
	{
		$output = '';

		// For each hexadecimal character
		for ($i = 0; $i < strlen($hexString); $i++)
		{
			// Convert to binary
			$binary = base_convert($hexString[$i], 16, 2);

			// Convert to binary and add 0s onto the left as necessary to make up to 4 bits
			$paddedBinaryString = str_pad($binary, 4, '0', STR_PAD_LEFT);

			// Append to string
			$output .= $paddedBinaryString;
		}

		return $output;
	}

	/**
	 * Converts data from hexadecimal into a binary data format that PHP recognises for Base64 encoding, Skein hashing etc
	 * @param string $dataHex The data as hexadecimal string
	 * @return Returns binary data (raw bytes)
	 */
	public function convertHexToBinaryData($dataHex)
	{
		// Format: Hex string, high nibble first
		return pack('H*', $dataHex);
	}

	/**
	 * Converts binary code to hexadecimal string. All hexadecimal is lowercase for consistency with the hash functions
	 * These are used as the export format and compatibility before sending via JSON or storing in the database
	 * @param string binaryString A string containing binary numbers e.g. '01001101'
	 * @return string A string containing the hexadecimal numbers e.g. '4d'
	 */
	public function convertBinaryStringToHex($binaryString)
	{
		$output = '';

		// For every 4 bits in the binary string
		for ($i = 0; $i < strlen($binaryString); $i += 4)
		{
			// Grab a chunk of 4 bits
			$bits = substr($binaryString, $i, 4);

			// Convert to decimal then hexadecimal
			$hex = base_convert($bits, 2, 16);

			// Append to output
			$output .= $hex;
		}

		return $output;
	}

	/**
	 * Converts a hexadecimal string e.g. '0164' to an integer e.g. 356
	 * @param string $hexadecimalString
	 * @return int An integer representation of the hexadecimal string
	 */
	public function convertHexToInt($hexadecimalString)
	{
		return (int) base_convert($hexadecimalString, 16, 10);
	}

	/**
	 * Converts the number of bytes to the number of hex symbols those bytes represent
	 * @param int $numOfBytes The number of bytes e.g. 2
	 * @return int Returns the number of hex symbols those bytes represent e.g. 4
	 */
	public function convertNumOfBytesToNumOfHexSymbols($numOfBytes)
	{
		return $numOfBytes * 2;
	}

	/**
	 * Converts the number of bytes to the number of Base64 chars (including padding) that those bytes represent
	 * Reference: https://stackoverflow.com/questions/13378815/
	 * @param int $numOfBytes The number of bytes e.g. 2
	 * @return int Returns the number of Base64 chars those bytes represent e.g. 4
	 */
	public function convertNumOfBytesToNumOfBase64Chars($numOfBytes)
	{
		return (int) (4 * ceil($numOfBytes / 3));
	}

	/**
	 * Convert ASCII text like 'a', 'b', 'cde' etc to its hexadecimal representation
	 * @param string $text The ASCII text to be converted
	 * @param int $paddingLengthInHex The padding length in hexadecimal to be left padded to ensure a consistent length
	 *                                (e.g. 2 hex symbols to always be a byte)
	 * @return string The padded hexadecimal string representation of the text
	 */
	public function convertTextToHex($text, $paddingLengthInHex)
	{
		$charsHex = bin2hex($text);
		$charsPaddedHex = str_pad($charsHex, $paddingLengthInHex, '0', STR_PAD_LEFT);

		return $charsPaddedHex;
	}

	/**
	 * Convert an integer e.g. 1, 2, 255 etc to its hexadecimal representation
	 * @param string $integer The integer to be converted
	 * @param int $paddingLengthInHex The padding length in hexadecimal to be left padded to ensure a consistent length
	 *                                (e.g. 2 hex symbols to always be a byte)
	 * @return string The padded hexadecimal string representation of the integer
	 */
	public function convertIntToHex($integer, $paddingLengthInHex)
	{
		$integerHex = dechex($integer);
		$integerPaddedHex = str_pad($integerHex, $paddingLengthInHex, '0', STR_PAD_LEFT);

		return $integerPaddedHex;
	}
}