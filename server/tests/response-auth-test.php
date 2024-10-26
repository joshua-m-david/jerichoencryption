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


use Jericho\CommonConstants;
use Jericho\Converter;
use Jericho\NetworkCipher;
use Jericho\Response;
use Jericho\ResponseAuth;

use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the response encryption and authentication
 */
class ResponseAuthTest extends TestCase
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
	 * @var ResponseAuth Response serialisation, encryption and authentication functionality
	 */
	private $responseAuth;


	/**
	 * Main setup which is run for each unit test
	 */
	protected function setUp(): void
	{
		// Load the common helper functions
		$this->converter = new Converter();

		// Initialise classes
		$this->networkCipher = new NetworkCipher($this->converter);
		$this->responseAuth = new ResponseAuth($this->converter, $this->networkCipher);
	}


	public function testGenerateNonce()
	{
		// Generate 512 bit nonce as hexadecimal
		$nonceHex = $this->responseAuth->generateNonce();
		$nonceHexLength = strlen($nonceHex);
		$expectedNonceLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::RESPONSE_NONCE_BITS_LENGTH);

		// Check it is the correct length (512 / 4 = 128)
		$this->assertSame($expectedNonceLengthInHex, $nonceHexLength);
	}

	public function testGetRandomBytesForErrorResponse()
	{
		// Convert the min and max number of bits to length in hex
		$minRandomBytesLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::ERROR_RESPONSE_MIN_RANDOM_BITS);
		$maxRandomBytesLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::ERROR_RESPONSE_MAX_RANDOM_BITS);

		// Get random bytes, first test
		$randomBytesA = $this->responseAuth->getRandomBytesForErrorResponse();
		$randomBytesHexA = bin2hex($randomBytesA);
		$randomBytesHexLengthA = strlen($randomBytesHexA);

		// Get random bytes, second test
		$randomBytesB = $this->responseAuth->getRandomBytesForErrorResponse();
		$randomBytesHexB = bin2hex($randomBytesB);
		$randomBytesHexLengthB = strlen($randomBytesHexB);

		// Get random bytes, third test
		$randomBytesC = $this->responseAuth->getRandomBytesForErrorResponse();
		$randomBytesHexC = bin2hex($randomBytesC);
		$randomBytesHexLengthC = strlen($randomBytesHexC);

		$this->assertGreaterThanOrEqual($minRandomBytesLengthInHex, $randomBytesHexLengthA);
		$this->assertLessThanOrEqual($maxRandomBytesLengthInHex, $randomBytesHexLengthA);

		$this->assertGreaterThanOrEqual($minRandomBytesLengthInHex, $randomBytesHexLengthB);
		$this->assertLessThanOrEqual($maxRandomBytesLengthInHex, $randomBytesHexLengthB);

		$this->assertGreaterThanOrEqual($minRandomBytesLengthInHex, $randomBytesHexLengthC);
		$this->assertLessThanOrEqual($maxRandomBytesLengthInHex, $randomBytesHexLengthC);
	}

	public function testGetAuthenticatedResponsePadding()
	{
		// Convert the min and max number of bits to length in hex
		$minPaddingBytesLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::RESPONSE_MIN_PADDING_BITS);
		$maxPaddingBytesLengthInHex = $this->converter->convertNumOfBitsToNumOfHexSymbols(CommonConstants::RESPONSE_MAX_PADDING_BITS);

		// Get random padding of variable length
		$paddingHexTestA = $this->responseAuth->getAuthenticatedResponsePadding();
		$paddingHexLengthTestA = strlen($paddingHexTestA);

		$paddingHexTestB = $this->responseAuth->getAuthenticatedResponsePadding();
		$paddingHexLengthTestB = strlen($paddingHexTestB);

		$paddingHexTestC = $this->responseAuth->getAuthenticatedResponsePadding();
		$paddingHexLengthTestC = strlen($paddingHexTestC);

		// Check within min and max length
		$this->assertGreaterThanOrEqual($minPaddingBytesLengthInHex, $paddingHexLengthTestA);
		$this->assertLessThanOrEqual($maxPaddingBytesLengthInHex, $paddingHexLengthTestA);

		$this->assertGreaterThanOrEqual($minPaddingBytesLengthInHex, $paddingHexLengthTestB);
		$this->assertLessThanOrEqual($maxPaddingBytesLengthInHex, $paddingHexLengthTestB);

		$this->assertGreaterThanOrEqual($minPaddingBytesLengthInHex, $paddingHexLengthTestC);
		$this->assertLessThanOrEqual($maxPaddingBytesLengthInHex, $paddingHexLengthTestC);
	}

	public function testSerialiseResponse()
	{
		// Test 0 User Message Packets
		$userMessagePacketsA = [];
		$responseA = new Response(Response::RESPONSE_SUCCESS_NO_MESSAGES, $userMessagePacketsA);
		$paddingHexA = 'abcdef01234567899876543210fedcba';
		$serialisedResponseHexA = $this->responseAuth->serialiseResponse($responseA, $paddingHexA);
		$expectedSerialisedResponseHexA = $paddingHexA .
			'' .       // No message data (0 bytes)
			'0000' .   // No messages (2 bytes length)
			'01';      // No messages success response code (1 byte length)

		$this->assertSame($expectedSerialisedResponseHexA, $serialisedResponseHexA);


		// Test 1 User Message Packets
		$userMessagePacketsB = [
			[
				'fromUser' => 'alpha',
				'messagePacket' => 'abcdef0123456789'
			]
		];
		$responseB = new Response(Response::RESPONSE_SUCCESS, $userMessagePacketsB);
		$paddingHexB = 'abcdef01234567899876543210fedcba';
		$serialisedResponseHexB = $this->responseAuth->serialiseResponse($responseB, $paddingHexB);
		$expectedSerialisedResponseHexB = $paddingHexB .
			'61' . 'abcdef0123456789' .    // User Message Packet
			'0001' .   // 1 message (2 bytes length)
			'00';      // No messages success response code (1 byte length)

		$this->assertSame($expectedSerialisedResponseHexB, $serialisedResponseHexB);


		// Test 2 User Message Packets
		$userMessagePacketsC = [
			[
				'fromUser' => 'alpha',
				'messagePacket' => 'abcdef0123456789'
			],
			[
				'fromUser' => 'bravo',
				'messagePacket' => '9876543210fedcba'
			]
		];
		$responseC = new Response(Response::RESPONSE_SUCCESS, $userMessagePacketsC);
		$paddingHexC = 'abcdef01234567899876543210fedcba';
		$serialisedResponseHexC = $this->responseAuth->serialiseResponse($responseC, $paddingHexC);
		$expectedSerialisedResponseHexC = $paddingHexC .
			'61' . 'abcdef0123456789' .    // First User Message Packet
			'62' . '9876543210fedcba'.     // Second User Message Packet
			'0002' .   // 2 messages (2 bytes length)
			'00';      // No messages success response code (1 byte length)

		$this->assertSame($expectedSerialisedResponseHexC, $serialisedResponseHexC);
	}

	public function testEncryptSerialisedResponse()
	{
		$groupDerivedEncryptionKeyHex = 'd69a8518a65c7c634268848752547a73e82e9d0406208d1e6114b1fc081a8e113742c6284ce9a59d51d80b693714b85c4c2416219bdd1570948769f389bc9930';
		$responseNonceHex = '0df007f13754d1be80bd196c709e95eb3cd2a2756d5f73401ac5190be18f2e48641d88630ef64f18d0795df2e23b5588a383f583ad89bf6affb3edbdce7f9ea8';
		$serialisedResponseHex = 'abcdef01234567899876543210fedcba61abcdef0123456789629876543210fedcba0010000200';
		$encryptedResponseHex = $this->responseAuth->encryptSerialisedResponse($groupDerivedEncryptionKeyHex, $responseNonceHex, $serialisedResponseHex);
		$expectedEncryptedResponseHex = '1a9bc247f37b1b76716dbfa15ed8b60772046c1239b092e82a8a7c50d17e37a16eeb3a233fd471';

		$this->assertSame($expectedEncryptedResponseHex, $encryptedResponseHex);
	}

	public function testAuthenticateResponse()
	{
		$groupId = 'aabbccddeeff0011';
		$groupServerKey = 'fe89e2bd97df7e3c7e0136e20babdc3104d28d637d611cc3fda5400f83c1b7429d1967fd69501d2c90d446815f1cb430370d19a15105092c68303450087aa0d4';
		$groupDerivedEncKeyHex = 'd69a8518a65c7c634268848752547a73e82e9d0406208d1e6114b1fc081a8e113742c6284ce9a59d51d80b693714b85c4c2416219bdd1570948769f389bc9930';
		$groupDerivedMacKeyHex = 'd86b96006de7ac77d156dfc92138abb29525c79183516a1e4396e1bf86340fab14eebefbe79f9b43f00c2fdbe7cc7a766fce959ca4f2b71e3f2fb882a5d5ff0d';
		$requestMacHex = 'f0b4709d8766edffa6b94e23354b4443c7d30feb50378f3fc4e65dc97b2de884421a1e1f9edca0fefc616804e88acf5e65400f9c1aa3277eed7eb44175872050';
		$responseNonceHex = '46f8b2019296f186c7642d8716effb0cf6360d600f08ef07351db54d6efded908cf1b6531a780e3c2090ddcdec4347d095ff605a5c89e264c2f5968c65a1f718';
		$encryptedSerialisedResponseHex = 'fd17f95925f744cd9fd2db6441290a1ccda069f7a607c41f00dab8144244c6f2a9a00adec6f23d55158d43f5a218cee843ff7b8789216754d388b8fdb1aabc583f43e6e4132610849f164d4b01840a0e75cebdea901561b26b95801fbbef574c0fc7b4e93da6f67a228c7cb128e3c9caea81724e6f1fcdcef6b2d880df2e008b0731193271dd8af2c461b82fe9f5060ede97d921e3f273e9adee3a60a3381640c943a310a72d74d6b22d7f991133132db93aa020e45b2eb63698c7c7c417baef8be794da9c7342047ec413aae2f271a0ad0f248bf1787d68d7c83d05d7a1288a9fbf1ffb7a67';
		$expectedResponseMac = '54882515115192dc574383eb33e5aa4a1f836df551ce588c727bec7402daaa7e2062daf513836b85f8c48a166e3210fa63963639364e85664d43a36b97b71ba1';
		$responseMac = $this->responseAuth->authenticateResponse($groupDerivedMacKeyHex, $requestMacHex, $responseNonceHex, $encryptedSerialisedResponseHex);

		$this->assertSame($expectedResponseMac, $responseMac);
	}

	public function testSerialiseAndEncodeResponse()
	{
		$responseNonceHex = '46f8b2019296f186c7642d8716effb0cf6360d600f08ef07351db54d6efded908cf1b6531a780e3c2090ddcdec4347d095ff605a5c89e264c2f5968c65a1f718';
		$encryptedSerialisedResponseHex = 'fd17f95925f744cd9fd2db6441290a1ccda069f7a607c41f00dab8144244c6f2a9a00adec6f23d55158d43f5a218cee843ff7b8789216754d388b8fdb1aabc583f43e6e4132610849f164d4b01840a0e75cebdea901561b26b95801fbbef574c0fc7b4e93da6f67a228c7cb128e3c9caea81724e6f1fcdcef6b2d880df2e008b0731193271dd8af2c461b82fe9f5060ede97d921e3f273e9adee3a60a3381640c943a310a72d74d6b22d7f991133132db93aa020e45b2eb63698c7c7c417baef8be794da9c7342047ec413aae2f271a0ad0f248bf1787d68d7c83d05d7a1288a9fbf1ffb7a67';
		$responseMac = '51b952b51b96dabf87acd4a5d22bf7b8f4d3621e541d649eb810e473e862ddba2387e951a32a86b88408cd7d55ad4dfa3ab0c1748631546ffcf3aeadcde4f99a';
		$expectedSerialisedResponseBase64 = 'RviyAZKW8YbHZC2HFu/7DPY2DWAPCO8HNR21TW797ZCM8bZTGngOPCCQ3c3sQ0fQlf9gWlyJ4mTC9ZaMZaH3GP0X+Vkl90TNn9LbZEEpChzNoGn3pgfEHwDauBRCRMbyqaAK3sbyPVUVjUP1ohjO6EP/e4eJIWdU04i4/bGqvFg/Q+bkEyYQhJ8WTUsBhAoOdc696pAVYbJrlYAfu+9XTA/HtOk9pvZ6Iox8sSjjycrqgXJObx/Nzvay2IDfLgCLBzEZMnHdivLEYbgv6fUGDt6X2SHj8nPpre46YKM4FkDJQ6MQpy101rItf5kRMxMtuTqgIORbLrY2mMfHxBe674vnlNqcc0IEfsQTquLycaCtDySL8Xh9aNfIPQXXoSiKn78f+3pnUblStRuW2r+HrNSl0iv3uPTTYh5UHWSeuBDkc+hi3bojh+lRoyqGuIQIzX1VrU36OrDBdIYxVG/8866tzeT5mg==';
		$serialisedResponseBase64 = $this->responseAuth->serialiseAndEncodeResponse($responseNonceHex, $encryptedSerialisedResponseHex, $responseMac);

		$this->assertSame($expectedSerialisedResponseBase64, $serialisedResponseBase64);
	}

	public function testSerialiseEncryptAndAuthenticateResponse()
	{
		// Test a response with 2 message packets for the client to decrypt and parse the network response correctly
		$groupId = 'aabbccddeeff0011';
		$groupServerKey = 'fe89e2bd97df7e3c7e0136e20babdc3104d28d637d611cc3fda5400f83c1b7429d1967fd69501d2c90d446815f1cb430370d19a15105092c68303450087aa0d4';
		$encryptionKeyHex = 'd69a8518a65c7c634268848752547a73e82e9d0406208d1e6114b1fc081a8e113742c6284ce9a59d51d80b693714b85c4c2416219bdd1570948769f389bc9930';
		$macKeyHex = 'd86b96006de7ac77d156dfc92138abb29525c79183516a1e4396e1bf86340fab14eebefbe79f9b43f00c2fdbe7cc7a766fce959ca4f2b71e3f2fb882a5d5ff0d';
		$responsePaddingHex = '6d09cf14bd91d2e881c8f2c4222296b4dae2081961a1e87cf4761d58d3b660a1c3fcb3f2c55bdcb84f75964941cfb9ece1e9169e40a67f2110e6fbb00c0d45fe60bb0a38eb0d26372c5b15d7cddc9c78ff4eac109bcfa0f40ea01de5436c4c755039b56f7ce40a2e699d9e977a38ca4902f9f6c9b6678380816677f16cf34e2e5191dd04244b3eddeb707ba9517bee46eeff5836d9cf0baa308198f525d842490b00a3c6058edd009e182b15596feb2d5dc041b7fc5a936ae2002f545aebd464eb';
		$responseNonceHex = '46f8b2019296f186c7642d8716effb0cf6360d600f08ef07351db54d6efded908cf1b6531a780e3c2090ddcdec4347d095ff605a5c89e264c2f5968c65a1f718';
		$userMessagePackets = [
			[
				// Undecryptable (just random message, to test the network protocol)
				'fromUser' => 'bravo',
				'messagePacket' => 'b46765ecab98ac4d9631e44a9fe844da7cf6fa9e19cf0106ff085765936c82a7dfd89a606dde2422251b811b1175b5b3a18f219eb2ef4b4f4afc7ae6bfc944ba345c4fa811fdcd893999ffa229cc2bf080375de6c843cd302dc57cd0ac869c9cf60073ace3271d9eadc4ecf57cb741819b523d3cce96cd713522c2d5a84a1cd2aa2c8f3979ee70b45f85b4ec929f90a4e3c2d6f5f8c309974f8d865c466f14ddbf60abd484e10dc43257f1a6b635e2a5cc240156e6195f0d3b7f19ff726e4015'
			],
			[
				// Undecryptable (just random message, to test the network protocol)
				'fromUser' => 'bravo',
				'messagePacket' => 'fe83145267799bd0f4899670d187745fcc13258a6c5ea71d09a7c08e8d81cfe57facc0d4197bdaf6537f7dbc25fb218044f1201c4a7ba9be6f2091ffaff50f24583145972924e809aea68315df29f5d396e8bd760423120ffe2f8dd77436e465b0c2d7f10ebdac87f635e0c9eb65fc9b5cd6263de812106f2b65789cde4e6188fefffeb90d5e9a28d2aff125efb2a5bf3dc4958337b7e81bd72f8bf17d3a96d56035b646603ecd4db84f14e8431f2de08c6d89b89817301efd4aaf5df0efed26'
			]
		];
		$response = new Response(Response::RESPONSE_SUCCESS, $userMessagePackets);
		$requestBase64 = 'lic1dR4FbzrnZSWxJyxZfeADUkV118d1u45O5UMyRaUmUyQQUKspM+TzyGleaWsCSXkXmp22nkROXkoHakYa8XM9TGaF5pcjPeO9Q119oN2Uv6oukPseuOr19kns9bUVMFun0SKkAifiSBRLTJCM6ZY74Y8rhhdlDbSsZmRYbaZKjdOO1oPaAFuqls6IH4BMI0NxYCDknlktOCBSOpUl5/mjM5nafzulE66TvAZyJVwAWxgz7QFY131g0+cUFb9EYZopRJN7gCJrEkvjS7d/FvGvAOdcIatOGP4kP3Gph6DtL2sa5BJ3bHSBZfIS15DZZHm+ta0GAt8a9IqaDLT+jxfEmZU7stFX5jHUPHcZbHPsYU2PwGGjKbzSQZz0p6PCzb62PR9SZha1qBWjX4uukSIOQ5jqqBJheXX6olX3rRelzLTpYFUF6qkIYee0jKjnaAsEn7QaBEA7oRwNR1M0HX4+jc+ugG0ZtXq/3XHm4aUfAeoKLZIbltbrYem76gVaEJDUKvybvs3jSW+Iezh7q+y/eYLOCdUoHfcFLigK2L56NTVXcmtj5yywZgWiSZrDRnlru9vUfSsZNK80S6ru+q/xSUhEb7BU9yYRsvvvF87EoGBpEwhq08dsLv6K/Yl8ML1Zkv7r2QrDwammfBxTBS8hVHXIVWOaf2XPUuefs8XSVaGaM9yAxree9K+qHRvlqvEx9jfFl53yoafa4XnVLoa3kXYf/cN7dIHa3I26EN19Ei/w08edcRhkmBXsnA09eOKAXke9/xxsF1oFGH1wt18QLc1gIuj9ur8kHbHo80Rpclt/GhxAyRSkcxXLtzR/h3rJSjviVsFxoxQnkKtHgYFHpC3JM9D9XMa9+JLplKwOOiqH7RIbD4c27T0zvfOK46EAvSvwrFn8QfAe757fX1CZqDpaq9y7kq5l0VZiIeZqj2fthJFYgLs='; // From testPerformClientRequestAuthenticationAndDecryption
		$requestHex = '962735751e056f3ae76525b1272c597de003524575d7c775bb8e4ee5433245a52653241050ab2933e4f3c8695e696b024979179a9db69e444e5e4a076a461af1733d4c6685e697233de3bd435d7da0dd94bfaa2e90fb1eb8eaf5f649ecf5b515305ba7d122a40227e248144b4c908ce9963be18f2b8617650db4ac6664586da64a8dd38ed683da005baa96ce881f804c2343716020e49e592d3820523a9525e7f9a33399da7f3ba513ae93bc0672255c005b1833ed0158d77d60d3e71415bf44619a2944937b80226b124be34bb77f16f1af00e75c21ab4e18fe243f71a987a0ed2f6b1ae412776c748165f212d790d96479beb5ad0602df1af48a9a0cb4fe8f17c499953bb2d157e631d43c77196c73ec614d8fc061a329bcd2419cf4a7a3c2cdbeb63d1f526616b5a815a35f8bae91220e4398eaa812617975faa255f7ad17a5ccb4e9605505eaa90861e7b48ca8e7680b049fb41a04403ba11c0d4753341d7e3e8dcfae806d19b57abfdd71e6e1a51f01ea0a2d921b96d6eb61e9bbea055a1090d42afc9bbecde3496f887b387babecbf7982ce09d5281df7052e280ad8be7a353557726b63e72cb06605a2499ac346796bbbdbd47d2b1934af344baaeefaaff14948446fb054f72611b2fbef17cec4a0606913086ad3c76c2efe8afd897c30bd5992feebd90ac3c1a9a67c1c53052f215475c855639a7f65cf52e79fb3c5d255a19a33dc80c6b79ef4afaa1d1be5aaf131f637c5979df2a1a7dae179d52e86b791761ffdc37b7481dadc8dba10dd7d122ff0d3c79d7118649815ec9c0d3d78e2805e47bdff1c6c175a05187d70b75f102dcd6022e8fdbabf241db1e8f34469725b7f1a1c40c914a47315cbb7347f877ac94a3be256c171a3142790ab47818147a42dc933d0fd5cc6bdf892e994ac0e3a2a87ed121b0f8736ed3d33bdf38ae3a100bd2bf0ac59fc41f01eef9edf5f5099a83a5aabdcbb92ae65d1566221e66a8f67ed84915880bb';
		$requestMacHex = 'c6bdf892e994ac0e3a2a87ed121b0f8736ed3d33bdf38ae3a100bd2bf0ac59fc41f01eef9edf5f5099a83a5aabdcbb92ae65d1566221e66a8f67ed84915880bb';
		$serialisedResponseBase64 = $this->responseAuth->serialiseEncryptAndAuthenticateResponse(
			$encryptionKeyHex, $macKeyHex, $responsePaddingHex, $responseNonceHex, $response, $requestMacHex
		);
		$expectedSerialisedResponseBase64 = 'RviyAZKW8YbHZC2HFu/7DPY2DWAPCO8HNR21TW797ZCM8bZTGngOPCCQ3c3sQ0fQlf9gWlyJ4mTC9ZaMZaH3GKUOvl33DnpK8uGnHX/qtW6G5YM04K+vszaKX9YXSO0R5NhxGJ8Z5Bfw6KZF6H7L+DXB6wUhs8JiORNkYBaeA/1gI9T86vkrUJ4AxXgxd87eOzG9u5jW2lYbyM1WDu6vPcPLLBF0XW8SIlRlt1hkkKSobgtI9THPFk/bL6fpwH+fG7SpZlpyE9FJyQqZjNb3OSD/8C93P6Zgji6asrsYBn/Nu44CWeF11XhZV0NZUTjl9w3tKHGnJhjXrushcQAhB6pK+ePqp2SzdabZhQJNhu73tVW3pw650Dct5KPP7A/OMRghI+AHm2Z3oGwuLOSgFJ5wVkdd32TDE9MlGeOKDLbpizP4URyBjkkT1qSHwSVThx37BXGSxDUy38msEqNKu1IkzYrluxTh2RVvf6vbog7ALdrbTVaD0rNS37uKnRy2iRNg6Nj4Mx0YFQxY+3QrGRZJO2nD9aDi3ilr/Wek1a6YGpHO7syaYqPh4xyHdS1J44aZzZRvLAVE6Loi36y2YzQSQpOOnii6PikWrzo0YQN62bH+MdHShaCpIPq2+qTMrQql/9MphbYVs/2ObzHBP2LM+FClpVfM1HTZPsKSNZ/QOqDuSigq3hO5bu8AR/VEikmTaHDzcqK8L/MKZDJG6HGgJLgqS9te/2OoU8ppToo1pcnVRxiJODdQy/8HZF+440zZGzv0Q4ZZQIVki42ZxrD3Mea/3txVN+kZTMgR0n1jG9DL2JQNv7Docg1Gsllblgb5DORL2LYvx9gkF8TszD2m+zcsgSvOQJ6b2mMgo8xZnYH9bRdoE/v2jypk6uey0ECk4DH5SiOrrrX1EPO9Xhc1h7HVfUXR/8KkrpB9yygn95SqQv0=';

		$this->assertSame($expectedSerialisedResponseBase64, $serialisedResponseBase64);
	}
}
