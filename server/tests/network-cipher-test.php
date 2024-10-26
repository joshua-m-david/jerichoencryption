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
use Jericho\NetworkCipher;

use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the network encryption and decryption
 */
class NetworkCipherTest extends TestCase
{
	/**
	 * @var Converter $converter The common conversion functions
	 */
	private $converter;

	/**
	 * @var NetworkCipher The encryption and decryption helper functions
	 */
	private $networkCipher;


	/**
	 * Main setup which is run for each unit test
	 */
	protected function setUp(): void
	{
		// Load the helper functions
		$this->converter = new Converter();
		$this->networkCipher = new NetworkCipher($this->converter);
	}


	/**
	 * Test vectors for Skein-512-512 from: http://www.skein-hash.info/sites/default/files/skein1.3.pdf
	 * Spaces were removed for simplicity.
	 */
	public function testSkein()
	{
		// Lowercase the test hexadecimal input so consistent with output, then pack into binary format for PHP
		$testVectorA = strtolower('FF');
		$testVectorBinaryA = $this->converter->convertHexToBinaryData($testVectorA);
		$resultA = skein_hash_hex($testVectorBinaryA);
		$correctResultA = strtolower('71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A');

		$testVectorB = strtolower('FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0');
		$testVectorBinaryB = $this->converter->convertHexToBinaryData($testVectorB);
		$resultB = skein_hash_hex($testVectorBinaryB);
		$correctResultB = strtolower('45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B');

		$testVectorC = strtolower('FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180');
		$testVectorBinaryC = $this->converter->convertHexToBinaryData($testVectorC);
		$resultC = skein_hash_hex($testVectorBinaryC);
		$correctResultC = strtolower('91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7');

		$this->assertSame($correctResultA, $resultA);
		$this->assertSame($correctResultB, $resultB);
		$this->assertSame($correctResultC, $resultC);
	}

	public function testXorTwoHexadecimalStringsTogether()
	{
		// Test converting 4 hex symbols
		$firstStringA = 'a7d9';     // 1010011111011001
		$secondStringA = 'c72a';    // 1100011100101010
		$resultA = $this->networkCipher->xorHex($firstStringA, $secondStringA);
		$expectedResultA = '60f3';  // 0110000011110011

		// Test converting 1 hex symbol
		$firstStringB = '3';    // 0011
		$secondStringB = '5';   // 0101
		$resultB = $this->networkCipher->xorHex($firstStringB, $secondStringB);
		$expectedResultB = '6'; // 0110

		// Test xoring all hex symbols
		$firstStringC =  '0123456789abcdef';    // 0000000100100011010001010110011110001001101010111100110111101111
		$secondStringC = 'fedcba0987654321';    // 1111111011011100101110100000100110000111011001010100001100100001
		$resultC = $this->networkCipher->xorHex($firstStringC, $secondStringC);
		$expectedResultC = 'ffffff6e0ece8ece';  // 1111111111111111111111110110111000001110110011101000111011001110

		$this->assertSame($resultA, $expectedResultA);
		$this->assertSame($resultB, $expectedResultB);
		$this->assertSame($resultC, $expectedResultC);
	}

	public function testGenerateKeystream()
	{
		// Test keystream generation with random key and nonce
		$keyHexA = '8c74e18270229f9ce2a717a0396d6c687daca5b45826d98a5d5ad0ad2ecb68988359097538596d52ea34735e223adfd103d734bad8cd06953f9be2a704ea7701';
		$nonceHexA = 'a3c2bc6e5e21d2294e2988739cd509780b738d188a7f665befa74ec00065922ae4c57f441eb7babd6438ea8dff930d1a3a56ac61a8fcfb93341a5fc2f2a3445a';
		$messageHexA = 'abcdef0123456789';
		$keystreamA = $this->networkCipher->generateKeystream($keyHexA, $nonceHexA, $messageHexA);
		$keystreamLengthA = strlen($keystreamA);
		$expectedKeystreamA = 'c79e45de734c6f82';
		$expectedKeystreamLengthA = strlen($expectedKeystreamA);

		$this->assertSame($expectedKeystreamLengthA, $keystreamLengthA);
		$this->assertSame($expectedKeystreamA, $keystreamA);


		// Test keystream generation with a different random key, nonce and message
		$keyHexB = 'abf6e6f365d819e2f054d49c4e68543e45abe9b3047e2d25ebb8d641125225502cba6011ad68ba0aa641812464a7c8ea60a0430f09a9fe4dbf76bef27275f159';
		$nonceHexB = '3f44fd0b15d00752197730a7782c2476f9ece592e956abd0f7a0d52fecf86ccda4efc391e80fe5e42d1d4a794ad297951bae08e57812533c1bb60cdbc58b4fff';
		$messageHexB = '9876543210fedcba';
		$keystreamB = $this->networkCipher->generateKeystream($keyHexB, $nonceHexB, $messageHexB);
		$keystreamLengthB = strlen($keystreamB);
		$expectedKeystreamB = '62be2aa43a6cf00a';
		$expectedKeystreamLengthB = strlen($expectedKeystreamA);

		$this->assertSame($expectedKeystreamLengthB, $keystreamLengthB);
		$this->assertSame($expectedKeystreamB, $keystreamB);
	}

	public function testEncryptOrDecryptPayload()
	{
		// Encrypt then decrypt back to original message with random key and nonce
		$keyHexA = '8c74e18270229f9ce2a717a0396d6c687daca5b45826d98a5d5ad0ad2ecb68988359097538596d52ea34735e223adfd103d734bad8cd06953f9be2a704ea7701';
		$nonceHexA = 'a3c2bc6e5e21d2294e2988739cd509780b738d188a7f665befa74ec00065922ae4c57f441eb7babd6438ea8dff930d1a3a56ac61a8fcfb93341a5fc2f2a3445a';
		$messageHexA = 'abcdef0123456789';
		$messageHexLengthA = strlen($messageHexA);
		$ciphertextHexA = $this->networkCipher->encryptOrDecryptPayload($keyHexA, $nonceHexA, $messageHexA);
		$ciphertextHexLengthA = strlen($ciphertextHexA);
		$expectedCiphertextHexA = '6c53aadf5009080b';
		$decryptedMessageHexA = $this->networkCipher->encryptOrDecryptPayload($keyHexA, $nonceHexA, $expectedCiphertextHexA);

		$this->assertSame($ciphertextHexLengthA, $messageHexLengthA);
		$this->assertSame($ciphertextHexA, $expectedCiphertextHexA);
		$this->assertSame($decryptedMessageHexA, $messageHexA);


		// Try a second encryption and decryption
		$keyHexB = '0d4809e6429bf90070cf8273bb86a6090bcf6fa3663b43803a17d049d9eeb0224bdb3ae427b65b5ed8f03a59d9b30b42c201be88c0afe0aaefe0e1f3a7ac86f8';
		$nonceHexB = '33078d68392706a65da177d1fbe9258f541669e0abcf1aa46fe9440b8d029d2f18e344a71f1eb97e1e8213b6c87e149eb623111790a0c1706334a163d77cf9d9';
		$messageHexB = '9876543210fedcba';
		$messageHexLengthB = strlen($messageHexB);
		$ciphertextHexB = $this->networkCipher->encryptOrDecryptPayload($keyHexB, $nonceHexB, $messageHexB);
		$ciphertextHexLengthB = strlen($ciphertextHexB);
		$expectedCiphertextHexB = '97118322873a993a';
		$decryptedMessageHexB = $this->networkCipher->encryptOrDecryptPayload($keyHexB, $nonceHexB, $expectedCiphertextHexB);

		$this->assertSame($ciphertextHexLengthB, $messageHexLengthB);
		$this->assertSame($ciphertextHexB, $expectedCiphertextHexB);
		$this->assertSame($decryptedMessageHexB, $messageHexB);
	}
}
