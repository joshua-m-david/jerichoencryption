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
 * Encryption and decryption functions for working with network packets
 */
class NetworkCipher
{
	/**
	 * @var int How many bits are produced by the Skein-512 hash function
	 */
	const SKEIN_OUTPUT_BITS_LENGTH = 512;

	/**
	 * @var int The length of the encryption counter in bits
	 */
	const COUNTER_BITS_LENGTH = 64;


	/**
	 * @var Converter The common conversion functions
	 */
	private $converter;


	/**
	 * Constructor takes the initialised Converter helper object using dependency injection
	 * @param Converter $converter The common conversion functions
	 */
	public function __construct($converter)
	{
		$this->converter = $converter;
	}


	/**
	 * Encrypts or decrypts the network payload
	 * @param string $keyHex The key to encrypt/decrypt with e.g. 512 random bits as a hexadecimal string
	 * @param string $nonceHex The nonce e.g. 512 random bits as a hexadecimal string
	 * @param string $payloadHex The encrypted payload (or plaintext payload) as a hexadecimal string
	 * @return string Returns the encrypted or decrypted payload as a hexadecimal string
	 */
	public function encryptOrDecryptPayload($keyHex, $nonceHex, $payloadHex)
	{
		// Create the keystream then encrypt/decrypt the payload
		$keystreamHex = $this->generateKeystream($keyHex, $nonceHex, $payloadHex);
		$ciphertextOrPlaintextHex = $this->xorHex($keystreamHex, $payloadHex);

		return $ciphertextOrPlaintextHex;
	}

	/**
	 * Generates a keystream to encrypt a network payload based on the exact payload length
	 * @param string $keyHex The key to encrypt with e.g. 512 random bits as a hexadecimal string
	 * @param string $nonceHex The nonce e.g. 512 random bits as a hexadecimal string
	 * @param string $payloadHex The payload (or message) as a hexadecimal string to be encrypted
	 * @return string Returns the keystream as a hexadecimal string
	 */
	public function generateKeystream($keyHex, $nonceHex, $payloadHex)
	{
		// How many bytes and hash calls are required to encrypt the message
		$numOfHexSymbolsRequired = strlen($payloadHex);
		$numOfBitsRequired = $this->converter->convertNumOfHexSymbolsToNumOfBits($numOfHexSymbolsRequired);
		$numOfHashCallsRequired = ceil($numOfBitsRequired / self::SKEIN_OUTPUT_BITS_LENGTH);

		// Get the counter length in hex e.g. 16
		$counterHexLength = $this->converter->convertNumOfBitsToNumOfHexSymbols(self::COUNTER_BITS_LENGTH);

		// Set to store the keystream as hex
		$keystreamHex = '';

		// Generate the keystream
		for ($i = 0; $i < $numOfHashCallsRequired; $i++)
		{
			// Get the counter in hex e.g. 0000000000000000, 0000000000000001 etc
			$counterHex = str_pad($i, $counterHexLength, '0', STR_PAD_LEFT);

			// Set the data to be hashed
			$dataToHashHex = $keyHex . $nonceHex . $counterHex;

			// Convert to binary
			$dataToHashBinary = $this->converter->convertHexToBinaryData($dataToHashHex);

			// Hash the data and append it to the keystream generated so far
			$keystreamHex .= skein_hash_hex($dataToHashBinary);
		}

		// Get the length of the keystream in bits
		$keystreamLengthInHex = strlen($keystreamHex);
		$keystreamBitsLength = $this->converter->convertNumOfHexSymbolsToNumOfBits($keystreamLengthInHex);

		// If too many bits were generated
		if ($keystreamBitsLength > $numOfBitsRequired)
		{
			// Truncate the output to the correct length
			$keystreamHex = substr($keystreamHex, 0, $numOfHexSymbolsRequired);
		}

		return $keystreamHex;
	}

	/**
	 * A function to XOR two hexadecimal strings together
	 * @param string hexStringA The first string of hexadecimal symbols e.g. 'a7d9'
	 * @param string hexStringB The second string of hexadecimal symbols e.g. 'c72a'
	 * @return string The result of the strings XORed together e.g. '60f3'
	 */
	public function xorHex($hexStringA, $hexStringB)
	{
		// Convert the hexadecimal to binary strings e.g. 1010
		$bitStringA = $this->converter->convertHexToBinaryString($hexStringA);
		$bitStringB = $this->converter->convertHexToBinaryString($hexStringB);

		$output = '';

		// For each binary character in the message
		for ($i = 0; $i < strlen($bitStringA); $i++)
		{
			// Get binary number of the two bitstreams at the same position
			$binaryDigitA = intval($bitStringA[$i]);
			$binaryDigitB = intval($bitStringB[$i]);

			// XOR the binary character of the pad and binary text character together and append to output
			$output .= $binaryDigitA ^ $binaryDigitB;
		}

		// Convert back to hexadecimal
		$xoredBitsHex = $this->converter->convertBinaryStringToHex($output);

		return $xoredBitsHex;
	}
}