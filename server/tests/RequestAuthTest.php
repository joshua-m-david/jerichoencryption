<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2026  Joshua M. David
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
use Jericho\Database;
use Jericho\NetworkCipher;
use Jericho\RequestAuth;

use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the request authentication, decryption and validation
 */
class RequestAuthTest extends TestCase
{
	/**
	 * @var Converter $converter The common conversion functions
	 */
	private $converter;

	/**
	 * @var Database $db The Database object
	 */
	private $db;

	/**
	 * @var NetworkCipher The encryption and decryption helper functions
	 */
	private $networkCipher;

	/**
	 * @var RequestAuth $requestAuth The request authentication functionality
	 */
	private $requestAuth;


	/**
	 * Main setup which is run for each unit test
	 */
	protected function setUp(): void
	{
		// Load the common helper functions
		$this->converter = new Converter();

		// Get the absolute path to the test configuration file e.g. /var/www/html/tests/config/config.json
		$configFilePath = realpath(__DIR__ . '/config/config.json');

		// Load the configuration into memory
		$config = $this->converter->loadAndDecodeConfig($configFilePath);
		$databaseConfig = $config['databaseConfig'];

		// Initialise classes
		$this->db = new Database($databaseConfig);
		$this->networkCipher = new NetworkCipher($this->converter);
		$this->requestAuth = new RequestAuth($this->db, $this->converter, $this->networkCipher);

		// Get the test database name from the group config.
		// NB: there is only one group config in the config file
		$testGroupConfig = $config['groupConfigs'][0];
		$testDatabaseName = $testGroupConfig['groupDatabaseName'];

		// Connect to the database
		$this->db->updateConfigDatabaseName($testDatabaseName);
		$this->db->connect();
	}

	protected function tearDown(): void
	{
		// Truncate the nonces and messages tables for each test to run cleanly
		$this->db->preparedUpdate('TRUNCATE TABLE nonces');
		$this->db->preparedUpdate('TRUNCATE TABLE messages');
	}

	public function testConnectionToDatabase()
	{
		// Connect to the database and make sure there are no error messages
		$dbConnectionSuccess = $this->db->connect();
		$errorMessage = $this->db->getErrorMsg();

		$this->assertTrue($dbConnectionSuccess);
		$this->assertFalse($errorMessage);
	}

	public function testValidatingRequestLength()
	{
		// Test success cases
		$minLengthRequest = 'w0uZxjmsv+Bru2LHxBrrM4+kbssxIEVCnfW874brIlG8WERejbvo3/7nUD2wXEMOZ6ng2lN4O8+lR+gNlN++GZk5gLkUZ6VD4gGgkoc9+plQnMiEXILZzi1EsHSSMeVfH232+dXTYRwUgtS16CfxBpnlTxUSJgOaEXNc6yRxGW2Xkxu0sjDIZfU3iJ062Y/nDd7H53SPLgKJlMWmKZqQ4Z52tsbhn3QmjcM9iA5RyoobXd5JgxOUdlyZ5mBctDOWuDhZBSRivoAaDOfJsubsbWpjiXIQTSHZZNjjvyyCoxqPIip59M1VQPHvTqJi8h1xmQZQBcyTHWDCxZ99p0J8Hv1yYw1THP6Ivq7n9Ew9PQo/dcHciRzmzPbWsgWBXgKNNUeEMUzEd0qaPtO94nvHAleEDcJCDE5MAx7RQWtEAQWedPaV6ajszYs=';
		$normalLengthRequest = 'B0OA6q+DkKARt2PaMmErVXd2mEg5LejHu871w3f9J784p8XL5J213uDjdJyYEt88tWUl3GNtN16A0IwjlDzvtSzVZi4/NnZd37uPNDviojY7gYY/C9afo+1WRHMg+4Mp9lQgh5tKZhYnhYvb6/w/71fC5/CWBMySaV50dNxzLnGq+7rP1bQO60jFIMHfV+cnTSg9TW2EYRHke5X5jWVsySkf8sHXLTGeqRqEdof/QX2qbzoKlCtTaOYnsPm4uvYPq75IZcUbARF4RYTw/IFjTSfaSqH3g77BxQSpbgS2sYeAI0JhOlxX/vJaKd5EiYNKYuRDJ4k6sQ+oaaH301NBdKr93exhJPMqiNsRpyXQbwLEkkoc/egoNjRInop6N7Z1sATKucGvov1p53BVpli2l71fYVlMInP2/AkKOzvY2O9rVC5J0tXm9xw76jzMgSQUmu+9RjVih8gLJBNK4Wx7rH5IjdXM0mZMxlY8nKTrKG1MRz9u2r+k8ovdU/r7zjNMyG1O7OmXCkTAc13Sc7dTysK/UB+yFrbana321EBmn43YVGDQePeF8yn10y7Nakg7ichidbAM9IEtcxuKz6Ab+3t4GREfLmXKlyD73MKos8E893tpLXUlXYGm/EZYrlpARdfV2B0=';
		$maxLengthRequest = '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'; // 7 messages padding + 7 messages
		
		$minLengthCheck = $this->requestAuth->validateRequestLength($minLengthRequest);
		$normalLengthCheck = $this->requestAuth->validateRequestLength($normalLengthRequest);
		$maxLengthCheck = $this->requestAuth->validateRequestLength($maxLengthRequest);

		$this->assertTrue($minLengthCheck);
		$this->assertTrue($normalLengthCheck);
		$this->assertTrue($maxLengthCheck);


		// Test failure cases
		$nullRequest = null;
		$zeroLengthRequest = '';
		$nonStringFloatRequest = 123.4;
		$nonStringArrayRequest = [];
		$nonStringObjectRequest = new stdClass();
		$tooShortLengthRequest = rtrim($minLengthRequest, '='); // Remove last character from minimum length request
		$tooLongLengthRequest = $maxLengthRequest . 'X';        // Add a letter to max length request, doesn't have to be valid Base64

		$nullRequestCheck = $this->requestAuth->validateRequestLength($nullRequest);
		$zeroLengthCheck = $this->requestAuth->validateRequestLength($zeroLengthRequest);
		$nonStringFloatCheck = $this->requestAuth->validateRequestLength($nonStringFloatRequest);
		$nonStringArrayCheck = $this->requestAuth->validateRequestLength($nonStringArrayRequest);
		$nonStringObjectCheck = $this->requestAuth->validateRequestLength($nonStringObjectRequest);
		$tooShortLengthCheck = $this->requestAuth->validateRequestLength($tooShortLengthRequest);
		$tooLongLengthCheck = $this->requestAuth->validateRequestLength($tooLongLengthRequest);

		$this->assertFalse($nullRequestCheck);
		$this->assertFalse($zeroLengthCheck);
		$this->assertFalse($nonStringFloatCheck);
		$this->assertFalse($nonStringArrayCheck);
		$this->assertFalse($nonStringObjectCheck);
		$this->assertFalse($tooShortLengthCheck);
		$this->assertFalse($tooLongLengthCheck);
	}

	public function testValidatingAndDecodingBase64()
	{
		// Valid request
		$successCaseRawBase64 = 'z7DTvGBXJbBixUt/rkEw3VPEkDsLlK0eaAJt0J/dzsLuiueYsyA2BOppajggko1C9gCIqTQ2v1+v+rrjNKKMraQSslLWP+XUE1GSlR1Nmc3hdZkNrZ8R0rc0ULkUadrvKhowKPd+OTMsWCBK6H4KWRe7yAH7qNLnj8cZK6WQik6f7dHN';
		$successCaseResult = $this->requestAuth->validateAndDecodeBase64($successCaseRawBase64);

		// Failure case - invalid Base64 decode
		$invalidBase64 = 'z7DTvGBXJbBixUtrk==';
		$invalidBase64Result = $this->requestAuth->validateAndDecodeBase64($invalidBase64);

		// Failure case - Invalid Base64 chars
		$invalidBase64Chars = 'z7D!TvGBXJbB!ixUt-rk==';
		$invalidBase64CharsResult = $this->requestAuth->validateAndDecodeBase64($invalidBase64Chars);

		// Failure case - Invalid equals signs in middle of string
		$invalidEqualsSigns = 'z7D!T=vGB==XJbB!ixUt-rk';
		$invalidEqualsSignsResult = $this->requestAuth->validateAndDecodeBase64($invalidEqualsSigns);

		// Failure case - Invalid format (plain text)
		$invalidPlainText = 'I am not base 64 encoded';
		$invalidPlainTextResult = $this->requestAuth->validateAndDecodeBase64($invalidPlainText);

		// Failure case - Invalid format (array)
		$invalidFormatArray = [];
		$invalidFormatArrayResult = $this->requestAuth->validateAndDecodeBase64($invalidFormatArray);

		// Failure case - Invalid format (binary data)
		$invalidFormatBinaryData = 'Æ4õ%±I{ Nj?i²5 â¤tücU7';
		$invalidFormatBinaryDataResult = $this->requestAuth->validateAndDecodeBase64($invalidFormatBinaryData);

		$this->assertNotFalse($successCaseResult);
		$this->assertFalse($invalidBase64Result);
		$this->assertFalse($invalidBase64CharsResult);
		$this->assertFalse($invalidEqualsSignsResult);
		$this->assertFalse($invalidFormatArrayResult);
		$this->assertFalse($invalidPlainTextResult);
		$this->assertFalse($invalidFormatBinaryDataResult);
	}

	public function testEncodeBinaryToHex()
	{
		// Validate and decode a valid request in Base64 into the data parts
		$dataRawBase64 = 'DkCjCi2jEWPVXobON+SDTzbZ9s5dOxZHLJzrxQ9x4qB0HBFtsVA4k5YesGiKwg4JYhZBDS7hEkckQsFZ2ZT+2n16aUrdpTxxobQWYjPmTHO7Cs0AQPczSJC8GoNAbJkR9Ccs95IhHzwVJelzpY0GNtRNVC6pSaMFDOkZo/J3W9m7tDuaWv172//N2vvcaGNZSLkEI1LpsF+eLy8bjFAaZLKy0GZvMb5NXr3b/Mar59jpPVE+Gn2I4UDzs/unPKhZdVPMkxeJKIustnUpj0tweBcWLj70jOkFJ3u3EoXLosSd0s7kX69Q5cPbBGHc8IxbszdU/EGJiLtLxYCZPbPTfwgq9Bn2ydkYKkzwLRNeE4NoxhbZBPVSFDo6YEm+5MGNt9VK+KOJ3kV9YBr1vj6FA0GoUGosyJPoXrmeXz5vKyYV+C2bASnu8ptcfY8MW9dTPNyprbpJdWR278dCvm9Md4jHFiN4ktLa75jqBoVoJLoIL8JipznD8iJVwkFDwHC218LLeFs4HklXFzTFE0E6U2nFbUV8';
		$dataBinary = $this->requestAuth->validateAndDecodeBase64($dataRawBase64);
		$dataHex = $this->requestAuth->encodeBinaryToHexAndValidate($dataBinary);
		$expectedDataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c';

		// Test failed encoding
		$badDataRawBase64 = 'DkCjCi2jEW&PVXobON+';
		$badDataBinary = $this->requestAuth->validateAndDecodeBase64($badDataRawBase64);
		$badDataHex = $this->requestAuth->encodeBinaryToHexAndValidate($badDataBinary);
		$expectedBadDataHex = false;

		$this->assertSame($expectedDataHex, $dataHex);
		$this->assertSame($expectedBadDataHex, $badDataHex);
	}

	public function testParseNonceFromHex()
	{
		// Valid request decoded from Base64 and encoded to hex
		$dataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c';
		$nonceHex = $this->requestAuth->parseNonceFromHex($dataHex);
		$expectedNonceHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda';

		// Try data that is too short
		$tooShortDataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9ceb';
		$tooShortNonceHex = $this->requestAuth->parseNonceFromHex($tooShortDataHex);
		$expectedTooShortNonceHex = false;

		$this->assertSame($expectedNonceHex, $nonceHex);
		$this->assertSame($expectedTooShortNonceHex, $tooShortNonceHex);
	}

	public function testParseMacFromHex()
	{
		// Valid request decoded from Base64 and encoded to hex
		$dataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c';
		$macHex = $this->requestAuth->parseMacFromHex($dataHex);
		$expectedMacHex = '49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c';

		// Try data that is too short
		$tooShortDataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9ceb';
		$tooShortMacHex = $this->requestAuth->parseMacFromHex($tooShortDataHex);
		$expectedTooShortMacHex = false;

		$this->assertSame($expectedMacHex, $macHex);
		$this->assertSame($expectedTooShortMacHex, $tooShortMacHex);
	}

	public function testParseCiphertextFromHex()
	{
		// Valid request decoded from Base64 and encoded to hex
		$dataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c';
		$ciphertextHex = $this->requestAuth->parseCiphertextFromHex($dataHex);
		$expectedCiphertextHex = '7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba';

		// Try data that is too short
		$tooShortDataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9ceb';
		$tooShortCiphertextHex = $this->requestAuth->parseCiphertextFromHex($tooShortDataHex);
		$expectedTooShortCiphertextHex = false;

		// Try data that is too long
		$tooLongDataHex = '53dc1867d6fa54fb82505a394822e9c88fd9a4e47cdcda93a6d5e668df1d45a923df211bac2b8217e2bd3875e7866c74c2eb3182ac5c43a00ab2c87aaa417aad52d50061b58944993623d0c287b6a5944e6b362a05578d0fb8ddf9f8604caafc5c9c2ba82cc98bdfaae8610a4bca9580a05703fd60330eaa9b8a324a62c6c3223459aec3a0323dcaac1fdc987669c5455b6daa92fc9d159b23b74a0df5b14b4175359bfb523de5186d289277713659efc3fa1a02e5b1b31c11e98181a3aa136888e03934dd0270a2b9e0e259983aa88917a20beb6e32651ba494908a2c69d46bc6d52797352e411ec74f0786e9386dc94c2efd0630a124a238feadd199dbd7c3f885115902c39af7d2da110237c6aac3ad57b7d8b871c349fd2d28a12e853cfa068d39c224573099de1980e2bfd7b7c756614d11c1196e570327fca0d3c48fe3677ff9950f7745ca980f2d66af6871b2f1a4d22a0413de770d0e73680ba274dca713e242a15e41d88884ecc50c92d35e0cb75e58e61bad88626ac0d04fb5733982d1cc11549ddfc201efa564144bf154b28d5fa5c26aad5c29ba4b9d606950baa88927a80eb2bef5bfea86764704adeb49c8b0553b4eb41f94d14c18ff536c46f5a195687e31a72b2f0a8fcde30d1de818b51d87cff7bd85c284969157dd6f49cb0082119e6bfdeab9d44be947aaeea2e3dda930322d47aaca9747842029b239b444ed88632690cd13f7d83e67506071f197974d11042c69b3a0545a217ae2fd5a2158315fcd08d8d8e81767872727f78490694763cf29e7918e2f6a0ac09a733caddf3d0e4e5e31e80daac1367bb517b4b03350bcd3acbf3db7dcc006ad05e9b0106e14c590015223cfebfab3a47bb6b32d6ba7ae3f47ad135cd43f3b5182e6df8c3f791fdccea54d0589c74ad074631311f388804b28171d2427953f5239ff877a3fa18ccc22ad7c5a64008325675c5bfe90d8e362ae43770be4215b0e85f0545c67fe9314ae50d7aa40713b09ebdc04efc2f4b2639d0cf14380f8b19b7607911e3d9415d82f057f2b2e6da685a39c5ab04c68f0d9ac769b1087bbbed5010b0e2dabd63500f89518088bbd29d445f1a116a09ce81cee5aa13442c4aca2cec49fe7400b0976373c1876e3f5a1c1b5e26693250211975b4499e7517ed9dc695bffc34ecc0e4cbe1a194775ffd543914e599264b152a5191f1f3e244e9c7e5a61e9a9942f8ad867caf664f4f69442f001d390ba48ff2c4b177476553e000d0e9579478557e09f210207550eb05d338837e314df3fba614e43790489e0e95c60446eec05f9af7f93696e808e8ed284c652b3503ed061c52b107fcd64517ec38b7feedea757155e82422545e1f9a65b67acdecc23554d6920de208d48cf9f8422b0a52f47f9724f90561e4516037be9268eeecea72b7ad9c74693bf1d3314ec23b7aaa81cbebdc9de601c3beabb49e3393f12a69f2868d31abb5352f9f42503aa1f46fd5d158055c7a9d80474ffaa795a04d5275affc80ba547ec86b0f8d3d8f4df8d06196a862cf3bafdf049ea243ca01c1fb2052ae1ad2fd815bce0f838a951d866996f939ef6fd1213871fd2e822d5d8c092d2f7ec620eae10749d585cb62685e11ea877dcf33e8b506f1795a6c18d8f31a6f54701a2824566fc880af6f9be1a7005eaba4b69eccb53b30e85dc19aec2ee2a7ecadb976a2c0ff5c2450c47bdeec28f8561bccd814c97d2c71d4363bfcfee496fbb8e93ad89bd1f4c0d9e28cfb912399cdda4c0315192663ff2af925f5699d5451dfa54d26899be35c9646120521f44c7a2f12d3697a7f27e2208f645dafde78d01a4047a2993039af5f14fd459eef24ead121f0590bad63d6c3e65e643a363c87d58e72c930bd8294b9ae4269d4bc2339d3948a3c0a7abf1d39624d7f6b23126225964cbc92dc50f8922f15e30835a7b2060448bb22d9c184316cf28c7c522ec5713f2f4011649a8990a5325a1f13a4f3ad6e90c8f95c409938c87a56702623e8f93fb01b6ac6ad84f86af4934a83cf178815429dfb097773a9ef7b852916c7ee6eb6809affe84e85c0805ef985622871d62ba4ccf49c9458cbbdea63b229802b56561155c7177e8590729bb2a396384f2221d1831add9af2f77c490395168b79828ac69df914e596487b22aee6c3074096a767a608e754764f06c4fb059130cb36cb665b20441587939c1be517b81df53878b88106b9a54e2a2933670a72e670507ac106e9ed7e32e01a75c728165a03743f0cf88ced0bf6a0637559302f83384b8700433bb7802cc92f36fa0f7351ad0e53d3d9353b7e95cf584f40d2156a42fb6013dc32cdfd96e201c24841033d3a0b4994dcae0eca9ebb00a6aac81b53d1a848f255a5add70eebcc2622089bf8aed61d13064ee175350f7db2351bf9993a70f4be94f1d59d3bf5da0cd0ffbccdcae6bcf40090c954be659c29d8841334fc876d08ec5b7adfd30d9975c483c4d5e3d1c368d84084b3cb5f19998cf9816f19ad78c175824f630fd839779773f9ba4eb4b4e0700b84ca454d5ec33ff599e57d62604e462ec204ad8af0f441af6b098daf7854319d0c5c59594c59a90ceea1785bdc662aeadff996539ab91e9df8b941430dac0d423710e66206ebb773c4685fd9c80fed3bdb41d0e4ca17e1bdcdbf5a9fbb79ef57537822e46334c65576dcb227aa75a736c8342c140165f947a3b2294838f28465cdcab12181d32a58173debdc761cf55ed1b20e775bb163b250568175953727ee1b55a7e3ad85bac4414304f0aee48761047740063f87ff6f706a5c7ee74a9c6cd166dca5d3a9a70835d68740dc79d132f1cc29593b1086934c4cb07c162b399b448c1fc05aec859a698bacf4f3c43788370fbe7d512d8d98960aff0f88360ffb46fe0416f833c905976d9692abc01b0d2cb05b907e7bfa38757b49972bcf26013485613162f2f641a62e5bc9bffdbc22e948b0c28325d4c96959428bf9d562d69ceca5fd72ba82326ab3cfab83a238c40a5236688cb15880ea984e48a8981ebda82faff86fe8bc51d1ddd7e5755da998e2733f29e708dfb8a572f954fe884b7e90966cdcdf9c54db272ef851488508a455d427521aea80d254d5ed7eb711a648e566f053dff8aaf2bf3a39c0568d4dc5e70618ebcbfc15dfe113d5b9b1e2820f0aa1e3bc31baf87c85300f1610ff196d7f42419e882676f1ee16d8e10a65c532ef0ea88f0ba18309537d67551f3695817f66df8b7be0bfd335a93649adb919eb5a8727df75763bfb6975b16b5030e13e0981fe37264b11cd376a3353d519f8138f10e5ac92ca285f782f0076296336913bc76c692153f736a0c1acaf63fa69dc7bd0b51b7cb6d56eb102ca113d850accf52995f2f4d8366ec2ed08930b24c5665a50df04d8597fd96dfc4ae6d9dd324bf78131616576b3c995a6de09e0fb50d528dbbff72e6729f9142fad4b1716f04548e4a140a0fd799795af30658b613e42052770973b70dc371989a14552682cd6e53c65cea44f015bbc386f5605c7abf59936c9178dd38ccb06fb20d800e857d8af70d569680b9d9b0b216b3047af9256f03ab8d5c4829e62cd2038e53670110e8c2f0b4b4b4eeaca59f65a2af6cfb9b9dfba7773f26a44fb8abcee4c736fb1dfc6554e276a9f363028c464d27f9ae80af9d36ed3808c7e9102db66f3af141a19b83b29213b4b2071a0a73882d0d942ae3a8aace381ec488287b72bc5c210d56ae35166065d63a246eab601247eb4d0cca99176369af56fece5cccfb6862c9c874b05500b27ea83a917a717d4a782194caad8e4a4812c5b34271b7305646fe8b20266be57997c1d373f9193c2fe499f8101265df28eedea7946adbb10be755bfc74d2348244e8745ea7c08035e0c403f583fcd722addb2ace2944e93e8c164f57121c63ff377c40d74a4522168160b4846661d6604b93535fabc2c1fcb4cd6a64380f49708c0774b34ca98d2656fcb47d5' . '00'; // Add a bit extra on from max ciphertext length for 7 messages padding + 7 messages
		$tooLongCiphertextHex = $this->requestAuth->parseCiphertextFromHex($tooLongDataHex);
		$expectedTooLongCiphertextHex = false;

		// Try ciphertext data that is odd length (an odd number of bytes (must be even to allow for successful decryption))
		$oddLengthDataHex = '0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457c0e40a30a2da31163d55e86ce37e4834f36d9f6ce5d3b16472c9cebc50f71e2a0741c116db1503893961eb0688ac20e096216410d2ee112472442c159d994feda7d7a694adda53c71a1b4166233e64c73bb0acd0040f7334890bc1a83406c9911f4272cf792211f3c1525e973a58d0636d44d542ea949a3050ce919a3f2775bd9bbb43b9a5afd7bdbffcddafbdc68635948b9042352e9b05f9e2f2f1b8c501a64b2b2d0666f31be4d5ebddbfcc6abe7d8e93d513e1a7d88e140f3b3fba73ca8597553cc931789288bacb675298f4b707817162e3ef48ce905277bb71285cba2c49dd2cee45faf50e5c3db0461dcf08c5bb33754fc418988bb4bc580993db3d37f082af419f6c9d9182a4cf02d135e138368c616d904f552143a3a6049bee4c18db7d54af8a389de457d601af5be3e850341a8506a2cc893e85eb99e5f3e6f2b2615f82d9b0129eef29b5c7d8f0c5bd7533cdca9adba49756476efc742be6f4c7788c716237892d2daef98ea06856824ba082fc262a739c3f22255c24143c070b6d7c2cb785b381e49571734c513413a5369c56d457';
		$oddLengthCiphertextHex = $this->requestAuth->parseCiphertextFromHex($oddLengthDataHex);
		$expectedOddLengthCiphertextHex = false;


		$this->assertSame($expectedCiphertextHex, $ciphertextHex);
		$this->assertSame($expectedTooShortCiphertextHex, $tooShortCiphertextHex);
		$this->assertSame($expectedTooLongCiphertextHex, $tooLongCiphertextHex);
		$this->assertSame($expectedOddLengthCiphertextHex, $oddLengthCiphertextHex);
	}

	public function testSerialiseDataForAuthentication()
	{
		$nonceHex = 'a0b1c2d3e4f5a6b7c8d9';
		$encryptedPayloadHex = '00112233445566778899aabbccddeeff';
		$groupIdentifierHex = 'aabbccddeeff0011';
		$dataForAuthentication = $this->requestAuth->serialiseDataForAuthentication($nonceHex, $encryptedPayloadHex, $groupIdentifierHex);
		$expectedDataForAuthentication = $groupIdentifierHex
		                               . $nonceHex
		                               . $encryptedPayloadHex;

		$this->assertSame($expectedDataForAuthentication, $dataForAuthentication);
	}

	public function testConstantTimeStringCompare()
	{
		// Test match
		$firstStringTestA = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$secondStringTestA = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$resultTestA = $this->requestAuth->constantTimeStringCompare($firstStringTestA, $secondStringTestA);

		// Test 1 char length mismatch, fail early
		$firstStringTestB = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$secondStringTestB = '8f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$resultTestB = $this->requestAuth->constantTimeStringCompare($firstStringTestB, $secondStringTestB);

		// Test mismatched values
		$firstStringTestC = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$secondStringTestC = '78f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';
		$resultTestC = $this->requestAuth->constantTimeStringCompare($firstStringTestC, $secondStringTestC);

		$this->assertTrue($resultTestA);
		$this->assertFalse($resultTestB);
		$this->assertFalse($resultTestC);
	}

	public function testDeriveEncryptionAndMacKeys()
	{
		// Test valid derivation to match the client side example
		$serverKeyHex = '8028582a460feb96ea23abadaed3a91d8669e0f8258158e7691ac366e25576e242ddfbe71e2fa0733298492eca25c603940eb40c87fdccd2e2e19ae7a70f1141';
		$encAndMacKeys = $this->requestAuth->deriveEncryptionAndMacKeys($serverKeyHex);
		$encKey = $encAndMacKeys['encryptionKey'];
		$macKey = $encAndMacKeys['macKey'];
		$expectedEncKey = '624fdca738ef2b2744944725f852c302a209d7e91651436c332c861128af2af5800dc404b440aeac225926d21837a3f7b3c41d983690661387d21acd002a4522';
		$expectedMacKey = '8f6250115adca883f4f47c24a8e6c82d14e967d5ab798130f6226c5dded49715964bbc8fae4f1f79d9eada33172ba05665ce687a7af5feb64f7c7e0bbe6c1f69';

		$this->assertSame($expectedEncKey, $encKey);
		$this->assertSame($expectedMacKey, $macKey);
	}

	public function testValidateDataMac()
	{
		// Test valid MAC
		$dataHexTestA = 'aabbccddeeff0011a3c2bc6e5e21d2294e2988739cd509780b738d188a7f665befa74ec00065922ae4c57f441eb7babd6438ea8dff930d1a3a56ac61a8fcfb93341a5fc2f2a3445a005feff6c83b67991bb2357c41d4c5e254aa7d980673b7dacdd5af933dc2e07d8ff91991191efaa10538a303376f17cd582f6289af6ff1fc944963dbb9542eac051f55c417c2e0ef90e816221b3e4ec154eee560136b71389236d28df75a2d595773525118f1c1f893d5b6510b72b1af9844a02350bd36c4f3637271e2e2442edc7c32617bef0e64ae46440d2d775016abe7c758e6810c1604130407477fea28d1493ef94bf6a2e44fb00de9c213f26c9af351283f2380fd276e85afe4710a7e947ffba2fd955cdeb4e5703e8c4c985ef3b7';
		$macKeyHexTestA = '8f6250115adca883f4f47c24a8e6c82d14e967d5ab798130f6226c5dded49715964bbc8fae4f1f79d9eada33172ba05665ce687a7af5feb64f7c7e0bbe6c1f69';
		$receivedMacTestA = 'b8b5ec5c8411e3d9bfbac328ca763774e1ee79aa0ccaa7f04724e117dea76bed5114d37ac9d55d00dda48d1205470d5a626567a6b222e56ad33d4e5ca003fa32';
		$validMacTestA = $this->requestAuth->validateDataMac($dataHexTestA, $macKeyHexTestA, $receivedMacTestA);

		// Test invalid MAC (1 char wrong in data)
		$dataHexTestB = 'babbccddeeff0011a3c2bc6e5e21d2294e2988739cd509780b738d188a7f665befa74ec00065922ae4c57f441eb7babd6438ea8dff930d1a3a56ac61a8fcfb93341a5fc2f2a3445a005feff6c83b67991bb2357c41d4c5e254aa7d980673b7dacdd5af933dc2e07d8ff91991191efaa10538a303376f17cd582f6289af6ff1fc944963dbb9542eac051f55c417c2e0ef90e816221b3e4ec154eee560136b71389236d28df75a2d595773525118f1c1f893d5b6510b72b1af9844a02350bd36c4f3637271e2e2442edc7c32617bef0e64ae46440d2d775016abe7c758e6810c1604130407477fea28d1493ef94bf6a2e44fb00de9c213f26c9af351283f2380fd276e85afe4710a7e947ffba2fd955cdeb4e5703e8c4c985ef3b7';
		$macKeyHexTestB = '8f6250115adca883f4f47c24a8e6c82d14e967d5ab798130f6226c5dded49715964bbc8fae4f1f79d9eada33172ba05665ce687a7af5feb64f7c7e0bbe6c1f69';
		$receivedMacTestB = 'b8b5ec5c8411e3d9bfbac328ca763774e1ee79aa0ccaa7f04724e117dea76bed5114d37ac9d55d00dda48d1205470d5a626567a6b222e56ad33d4e5ca003fa32';
		$validMacTestB = $this->requestAuth->validateDataMac($dataHexTestB, $macKeyHexTestB, $receivedMacTestB);

		$this->assertTrue($validMacTestA);
		$this->assertFalse($validMacTestB);
	}

	public function testFindGroupByMacValidation()
	{
		// Test finding correct MAC by trying group keys to get a match (second group is correct one)
		$groupConfigs = [
			[
				"groupId" => "a0b1c2d3e4f5a6",
				"groupServerKey" => "8f6250115adca883f4f47c24a8e6c82d14e967d5ab798130f6226c5dded49715964bbc8fae4f1f79d9eada33172ba05665ce687a7af5feb64f7c7e0bbe6c1f69",
				"groupNumberOfUsers" => 2
			],
			[
				"groupId" => "aabbccddeeff0011",
				"groupServerKey" => "fe89e2bd97df7e3c7e0136e20babdc3104d28d637d611cc3fda5400f83c1b7429d1967fd69501d2c90d446815f1cb430370d19a15105092c68303450087aa0d4",
				"groupNumberOfUsers" => 2
			]
        ];
		$nonceHex = 'b6feecd6fb2da3d5036518d2b593ccbc4518a347246316be8b8dec0a1a71e137047446e68a1be1b80df41f8176c1853e5966b7c27bbf0ac0f300527214f11531';
		$ciphertextHex = '226f1bbb467170426cb5d4a49737ece7f8e1ad595eede79bce706835b58cff53bcebe65ca9c990e0624a84743e81c055ab96188a7d73b6b314c96eb0ae2f5ae669029851717c11709f2b25572b2d80a20a3d284c6fea6342fa20fa4ee6bd2ceffacf7bac3a626569e2b6160ed90a4683ab1b38a26a83d9d6eb73b31e8673b48e92b209f5eb82d269f3974e0b6faaa8028838e2b2eda10c6bd01d46b0dba6a009c9c42297dfee18557d295a5b4a49cc2c263521fc6424d764db8c6a94151d283d621979a1ecfa88acb0020257dfd4d1e3ee34d4cf05ed2c1ab7adbc563eb310cfc1e6';
		$macHex = '3fce486f2e7d5ad1cdc892a7deeeef51c54903229948af4369de8e257d72494d40099dbf4fde67f91b881b4799074f3068ff6a4ce7ff9288e890b01ad78b0d39';
		$detectedGroup = $this->requestAuth->findGroupByMacValidation($groupConfigs, $nonceHex, $ciphertextHex, $macHex);

		// Test finding again, but with a bad nonce
		$badNonceHex = 'c6feecd6fb2da3d5036518d2b593ccbc4518a347246316be8b8dec0a1a71e137047446e68a1be1b80df41f8176c1853e5966b7c27bbf0ac0f300527214f11531';
		$undetectedGroupA = $this->requestAuth->findGroupByMacValidation($groupConfigs, $badNonceHex, $ciphertextHex, $macHex);

		// Test finding again, but with a bad ciphertext
		$badCiphertextHex = '326f1bbb467170426cb5d4a49737ece7f8e1ad595eede79bce706835b58cff53bcebe65ca9c990e0624a84743e81c055ab96188a7d73b6b314c96eb0ae2f5ae669029851717c11709f2b25572b2d80a20a3d284c6fea6342fa20fa4ee6bd2ceffacf7bac3a626569e2b6160ed90a4683ab1b38a26a83d9d6eb73b31e8673b48e92b209f5eb82d269f3974e0b6faaa8028838e2b2eda10c6bd01d46b0dba6a009c9c42297dfee18557d295a5b4a49cc2c263521fc6424d764db8c6a94151d283d621979a1ecfa88acb0020257dfd4d1e3ee34d4cf05ed2c1ab7adbc563eb310cfc1e6';
		$undetectedGroupB = $this->requestAuth->findGroupByMacValidation($groupConfigs, $nonceHex, $badCiphertextHex, $macHex);

		// Test finding again, but with a bad MAC
		$badMacHex = '4fce486f2e7d5ad1cdc892a7deeeef51c54903229948af4369de8e257d72494d40099dbf4fde67f91b881b4799074f3068ff6a4ce7ff9288e890b01ad78b0d39';
		$undetectedGroupC = $this->requestAuth->findGroupByMacValidation($groupConfigs, $nonceHex, $ciphertextHex, $badMacHex);

		$this->assertSame($groupConfigs[1]['groupId'], $detectedGroup['groupId']);
		$this->assertFalse($undetectedGroupA);
		$this->assertFalse($undetectedGroupB);
		$this->assertFalse($undetectedGroupC);
	}

	public function testGetTimestampFromPlaintextPayload()
	{
		// Get the timestamp from the decrypted serialised payload
		$decryptedPayloadHexA = '004e1100a0a5d86f878da08513f1140c69d2421ee93771658acd130618b960908684c1bcf1e34b68223708013302a0bb1ac6b70eeec43ab33b8c8e90e955f8f41791287cb938352b39725ac4ee476c76006055ee5a6172';
		$timestampA = $this->requestAuth->getTimestampFromPlaintextPayload($decryptedPayloadHexA);
		$expectedTimestampA = 1616244314;

		$decryptedPayloadHexB = '00c2d69629a9b17fc16ab1057c33a48bf4d0787b627cd78c524ae45669cdd9371d7347a0304c5efbec138c3d5d919f7da6854b8877279bbf280dc95b59b57ba0183aecc1aa32eb17fada5437ad1555805b322f0a5c4058087883d58d3a731f86cca28b3db29220af7fb8051b1f17872d5d83e4711fad8ecac6643fea70eebb527188b91377ae2135d76da430a62dd3c010935e56fe27d83060af57e088b36d96726ea6bade59b094d6a10c2b254851a63272063d1f8b98b0b5189f2c09dc9c1fb8d7aeea006055efc26172';
		$timestampB = $this->requestAuth->getTimestampFromPlaintextPayload($decryptedPayloadHexB);
		$expectedTimestampB = 1616244674;

		$decryptedPayloadHexC = '012e6b882af5f03b3847062799ad5b7bc995849dcea01e5847de863d776b422ccf02ebb64fe3fb9c2503a7bc5d9abfd82c933d8003dea33d1612a2025f6d05266c75e175d27119bc87f6bd50518dcf70c0cd1c0a44efdd3e642dfe1105e57af08a731e8a8403c58b9aeac503307279e1b52a15b994b0c7ac4eba98fef7dc53f357896cfeb69b39401c10fe200395153edfb23816861f8fc7723e94f357f92f27fb8ee459f1e804605ff6a689165cea47ca1bd7a968f3b62546ae666efedc118fe88ddf1de105aa3683bd8d62f1414f0b92bd3c7a5522d9436631f2e88bbb637fda784860784d7a80011756325bdfa916a3b0fc2f7dd2799885c131de163f2cc6e2613fd6a2e7d8287950b1660eff5052898c2040aef38025a29e185bd6e4affd3f865a996446a107ec0bafc226b4a1ac006055efe36172';
		$timestampC = $this->requestAuth->getTimestampFromPlaintextPayload($decryptedPayloadHexC);
		$expectedTimestampC = 1616244707;

		$this->assertSame($expectedTimestampA, $timestampA);
		$this->assertSame($expectedTimestampB, $timestampB);
		$this->assertSame($expectedTimestampC, $timestampC);
	}

	public function testValidatePayloadTimestamp()
	{
		$currentTime = time();

		// Test a timestamp in the right range
		$sentTimestampTestA = $currentTime;
		$validCheckTestA = $this->requestAuth->validatePayloadTimestamp($sentTimestampTestA, $currentTime);

		// Minus 20 seconds
		$sentTimestampTestB = $currentTime - 20;
		$validCheckTestB = $this->requestAuth->validatePayloadTimestamp($sentTimestampTestB, $currentTime);

		// Plus 20 seconds
		$sentTimestampTestC = $currentTime + 20;
		$validCheckTestC = $this->requestAuth->validatePayloadTimestamp($sentTimestampTestC, $currentTime);

		// Test a timetamp that is too early
		$sentTimestampTestD = $currentTime - CommonConstants::REQUEST_VALID_WINDOW_SECONDS - 1;
		$invalidCheckTestD = $this->requestAuth->validatePayloadTimestamp($sentTimestampTestD, $currentTime);

		// Test a timetamp that is too far in future
		$sentTimestampTestE = $currentTime + CommonConstants::REQUEST_VALID_WINDOW_SECONDS + 1;
		$invalidCheckTestE = $this->requestAuth->validatePayloadTimestamp($sentTimestampTestE, $currentTime);

		$this->assertTrue($validCheckTestA);
		$this->assertTrue($validCheckTestB);
		$this->assertTrue($validCheckTestC);

		$this->assertFalse($invalidCheckTestD);
		$this->assertFalse($invalidCheckTestD);
		$this->assertFalse($invalidCheckTestE);
	}

	public function testConnectToDatabase()
	{
		// Check the database initialised successfully
		$connectedSuccessfully = $this->requestAuth->connectToDatabase();

		// Run a bad query
		$badQueryResult = $this->db->preparedSelect('SELECT * FROM nonexistant_table');

		$this->assertTrue($connectedSuccessfully);
		$this->assertFalse($badQueryResult);
	}

	public function testValidateDataNonce()
	{
		// Create random nonce
		$nonceLengthInBytes = $this->converter->convertNumOfBitsToNumOfBytes(CommonConstants::REQUEST_NONCE_BITS_LENGTH);
		$nonceHex = bin2hex(random_bytes($nonceLengthInBytes));

		// Check if the static nonce already exists in the database
		$firstCheck = $this->requestAuth->validateDataNonce($nonceHex);

		// Add a random nonce and timestamp
		$timestamp = time();
		$saveNonceResult = $this->requestAuth->addSentNonceToDatabase($nonceHex, $timestamp);

		// Check to see if it now exists in the database, which should not be valid and indicates a replay attack
		$secondCheck = $this->requestAuth->validateDataNonce($nonceHex);

		$this->assertTrue($firstCheck);
		$this->assertTrue($saveNonceResult);
		$this->assertFalse($secondCheck);
	}

	public function testGetApiActionFromPlaintextPayload()
	{
		// Test 'receive'
		$decryptedPayloadHexA = '004e1100a0a5d86f878da08513f1140c69d2421ee93771658acd130618b960908684c1bcf1e34b68223708013302a0bb1ac6b70eeec43ab33b8c8e90e955f8f41791287cb938352b39725ac4ee476c76006055ee5a6172';
		$apiActionA = $this->requestAuth->getApiActionFromPlaintextPayload($decryptedPayloadHexA);

		// Test 'send'
		$decryptedPayloadHexB = '00ac8626b6ff2afd64ee3136cf79f45d7000f8a6f7c634a71fdbc7f11c715c68dfec9f24b26beda89a4ff6738355785c13aada93fd6fc4e24cdbd4991361199e7976f29c5249192a1563512a1dee9b70678d3fd6fc252afea8a97fd9c4b31a8eb8e969c94c761a1bc6038a55248a83d82060cc4ff51c23f140a8225302336db312b8344948f669ce56a237e3ac7db7ca4b3ad124a881a12d81abc6f76ddf686a113e61c2e3e4b6c6658e1fe7cca27bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae6006065ad076173';
		$apiActionB = $this->requestAuth->getApiActionFromPlaintextPayload($decryptedPayloadHexB);

		// Test 'test'
		$decryptedPayloadHexC = '00648691fba5c59c0fc8265250ff13d11ac6b74d358d777a82311587c9edd3c11af35ba00892a8cebcaa33b0bc5486f8d72ce3f6b3790132c4f3070aef145368300811e81c81b23118803258ea53f9f0918b99bce0e6dc7a2ff94d01771366c6ac3a28985e19006065adc76174';
		$apiActionC = $this->requestAuth->getApiActionFromPlaintextPayload($decryptedPayloadHexC);

		$this->assertSame(CommonConstants::API_ACTION_RECEIVE, $apiActionA);
		$this->assertSame(CommonConstants::API_ACTION_SEND, $apiActionB);
		$this->assertSame(CommonConstants::API_ACTION_TEST, $apiActionC);
	}

	public function testValidateApiAction()
	{
		// Test success cases
		$apiActionValidatedA = $this->requestAuth->validateApiAction(CommonConstants::API_ACTION_RECEIVE);
		$apiActionValidatedB = $this->requestAuth->validateApiAction(CommonConstants::API_ACTION_SEND);
		$apiActionValidatedC = $this->requestAuth->validateApiAction(CommonConstants::API_ACTION_TEST);

		// Test failure cases
		$apiActionValidatedD = $this->requestAuth->validateApiAction(false);
		$apiActionValidatedE = $this->requestAuth->validateApiAction('bob');
		$apiActionValidatedF = $this->requestAuth->validateApiAction(null);

		$this->assertTrue($apiActionValidatedA);
		$this->assertTrue($apiActionValidatedB);
		$this->assertTrue($apiActionValidatedC);

		$this->assertFalse($apiActionValidatedD);
		$this->assertFalse($apiActionValidatedE);
		$this->assertFalse($apiActionValidatedF);
	}

	public function testGetFromUserFromPlaintextPayload()
	{
		// Test 'alpha'
		$decryptedPayloadHexA = '004e1100a0a5d86f878da08513f1140c69d2421ee93771658acd130618b960908684c1bcf1e34b68223708013302a0bb1ac6b70eeec43ab33b8c8e90e955f8f41791287cb938352b39725ac4ee476c76006055ee5a6172';
		$fromUserA = $this->requestAuth->getFromUserFromPlaintextPayload($decryptedPayloadHexA);

		// Test 'bravo'
		$decryptedPayloadHexB = '00465b9d8519ab70c259c21093133b96e0d03d0bf5701c7f853b245d04eb5a859bae285680fc1f6b87750ef00a2e4a653db36c6f825dbdee7e3b3996cbd124be29a7163dc102792a006067cd2d6274';
		$fromUserB = $this->requestAuth->getFromUserFromPlaintextPayload($decryptedPayloadHexB);

		// Test 'charlie'
		$decryptedPayloadHexC = '003f234328f7e3f2e48fe01261bde7bb10c07db36675fcb1f191b1c4fd7169b05dbb589c6827f52b20011097b076cbd26b3de474bf30b6b2113c6bac4b2126b3c8006067cdea6374';
		$fromUserC = $this->requestAuth->getFromUserFromPlaintextPayload($decryptedPayloadHexC);

		$this->assertSame('alpha', $fromUserA);
		$this->assertSame('bravo', $fromUserB);
		$this->assertSame('charlie', $fromUserC);
	}

	public function testGetChatGroupUsers()
	{
		// Try valid cases
		$validUsersA = $this->requestAuth->getChatGroupUsers(2);
		$validUsersB = $this->requestAuth->getChatGroupUsers(3);
		$validUsersC = $this->requestAuth->getChatGroupUsers(CommonConstants::MAX_NUM_OF_USERS);

		// Try invalid cases, should return first 2 users
		$validUsersD = $this->requestAuth->getChatGroupUsers(CommonConstants::MAX_NUM_OF_USERS + 1);
		$validUsersE = $this->requestAuth->getChatGroupUsers('bob');

		$this->assertSame(['alpha', 'bravo'], $validUsersA);
		$this->assertSame(['alpha', 'bravo', 'charlie'], $validUsersB);
		$this->assertSame(array_values(CommonConstants::VALID_USER_LIST), $validUsersC);

		$this->assertSame(['alpha', 'bravo'], $validUsersD);
		$this->assertSame(['alpha', 'bravo'], $validUsersE);
	}

	public function testValidateUser()
	{
		// Try valid cases
		$userA = 'alpha';
		$validGroupUsersA = ['alpha', 'bravo'];

		$userB = 'bravo';
		$validGroupUsersB = ['alpha', 'bravo', 'charlie'];

		$userC = 'charlie';
		$validGroupUsersC = ['alpha', 'bravo', 'charlie'];

		// Try invalid cases
		$userD = 'delta';
		$validGroupUsersD = ['alpha', 'bravo', 'charlie'];

		$userE = 'hotel';
		$validGroupUsersE = array_values(CommonConstants::VALID_USER_LIST);

		$validatedUserA = $this->requestAuth->validateUser($userA, $validGroupUsersA);
		$validatedUserB = $this->requestAuth->validateUser($userB, $validGroupUsersB);
		$validatedUserC = $this->requestAuth->validateUser($userC, $validGroupUsersC);
		$validatedUserD = $this->requestAuth->validateUser($userD, $validGroupUsersD);
		$validatedUserE = $this->requestAuth->validateUser($userE, $validGroupUsersE);

		$this->assertTrue($validatedUserA);
		$this->assertTrue($validatedUserB);
		$this->assertTrue($validatedUserC);
		$this->assertFalse($validatedUserD);
		$this->assertFalse($validatedUserE);
	}

	public function testGetMessagesFromPlaintextPayload()
	{
		// Try valid case of one Message Packet
		$decryptedPayloadHexA = '0004bf84e9147bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae600606998f46173';
		$messagePacketsA = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexA);
		$expectedMessagePacketsA = [
			'7bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae6'
		];

		// Try valid case of two Message Packets
		$decryptedPayloadHexB = '001f3452aeca3af166d9e1c79c5226a7b026644697b3ca222a2ff5e0954b472ffd7bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae61490ce0b222b5fe06c5d6f7289fbd993c291d503ed07f6687afdf1a65f40f297005ac5b69092a1ae3f7d2928ababac0d6838e6ee21daf4e9662b9eef44b3d045bd6a4e27d99cc9ff51226ab045c296b70b23dba3d7f351c109499992bf84cdf8fdb40f293e2d491c0e8f33917765fa4b911642de2aaac60d209cd3e87c715a0b8633bf58af37ce0652b34244d12f6215899de5f24446923479841e102119b289dded24d863be96bbe84ce8f2e6426b3b26954e61b0fbb4b647616753fe1f6f7b0060699a896173';
		$messagePacketsB = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexB);
		$expectedMessagePacketsB = [
			'7bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae6',
			'1490ce0b222b5fe06c5d6f7289fbd993c291d503ed07f6687afdf1a65f40f297005ac5b69092a1ae3f7d2928ababac0d6838e6ee21daf4e9662b9eef44b3d045bd6a4e27d99cc9ff51226ab045c296b70b23dba3d7f351c109499992bf84cdf8fdb40f293e2d491c0e8f33917765fa4b911642de2aaac60d209cd3e87c715a0b8633bf58af37ce0652b34244d12f6215899de5f24446923479841e102119b289dded24d863be96bbe84ce8f2e6426b3b26954e61b0fbb4b647616753fe1f6f7b'
		];

		// Try valid case of three Message Packets
		$decryptedPayloadHexC = '0147e5a8bb868f853f68d585ca11f2299751f14ab582a3d4106e41da0b51962458d77eae89439e90a0a514f3f14928108c01c1cbddfb9b0218b881da746a6779c03f8e0b64d0cb4779862aa4e3c24a0204a48b312416ccffc59f631f0c275de24e80870861665951d26901412dbfc4da9f3ade275d80dfe5b53b3b818710232cf2bc9976425bd4c10ffb8b28d92138ab5ec278fbedf3f15ffe59d5343c14bfa89c00e56da5361d9215ceb8354615a2205613a96d8071f9fc94de39afb2c491a6c6eaca8f038f3409b93646c54aab8544764e7cd82dcac3bbb36d3ba46c1b6ef61277664ffcf76c18e583d9010dd7e83a40417cacf19083a215d4dfc3f5a2074c4702e5de64e677d3a2ad2617f5ce36179a92e39bfdbcd5e17f200feb8f125a17fc2daf45438a37d76b51e8d9dcfcf2f3b4ffad7a7c1980c0f60291de61277d74764c3e7e5e4f9d0b937bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae61490ce0b222b5fe06c5d6f7289fbd993c291d503ed07f6687afdf1a65f40f297005ac5b69092a1ae3f7d2928ababac0d6838e6ee21daf4e9662b9eef44b3d045bd6a4e27d99cc9ff51226ab045c296b70b23dba3d7f351c109499992bf84cdf8fdb40f293e2d491c0e8f33917765fa4b911642de2aaac60d209cd3e87c715a0b8633bf58af37ce0652b34244d12f6215899de5f24446923479841e102119b289dded24d863be96bbe84ce8f2e6426b3b26954e61b0fbb4b647616753fe1f6f7b178ab50c844d612614757e277e68291db545cb6e745d625c4fe9fe50a4b7e653f1adc2390295bf324d13c8581e525fb629606cca7b3c47ac91604809531c28e6ece4b35946fc5825845794de7896334a8826a3744a84190c4b10a076df9e842d7137cd395cf7b041b73d0e54cbdb4ba5ad99b3b82bef74760695e010920d0e04e8a848f22c0c4c19c7104a3220a8decdf6e8231b904d8399265dfdacceab17524982590a4ff6b0bfa595842a8689da39e53d9a40199cd7c5e1285c646ce626bf006069a1896173';
		$messagePacketsC = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexC);
		$expectedMessagePacketsC = [
			'7bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae6',
			'1490ce0b222b5fe06c5d6f7289fbd993c291d503ed07f6687afdf1a65f40f297005ac5b69092a1ae3f7d2928ababac0d6838e6ee21daf4e9662b9eef44b3d045bd6a4e27d99cc9ff51226ab045c296b70b23dba3d7f351c109499992bf84cdf8fdb40f293e2d491c0e8f33917765fa4b911642de2aaac60d209cd3e87c715a0b8633bf58af37ce0652b34244d12f6215899de5f24446923479841e102119b289dded24d863be96bbe84ce8f2e6426b3b26954e61b0fbb4b647616753fe1f6f7b',
			'178ab50c844d612614757e277e68291db545cb6e745d625c4fe9fe50a4b7e653f1adc2390295bf324d13c8581e525fb629606cca7b3c47ac91604809531c28e6ece4b35946fc5825845794de7896334a8826a3744a84190c4b10a076df9e842d7137cd395cf7b041b73d0e54cbdb4ba5ad99b3b82bef74760695e010920d0e04e8a848f22c0c4c19c7104a3220a8decdf6e8231b904d8399265dfdacceab17524982590a4ff6b0bfa595842a8689da39e53d9a40199cd7c5e1285c646ce626bf'
		];

		// Try invalid case with short Message Packet of invalid length
		$decryptedPayloadHexD = '0009d2fecaf623b210ebf17bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae006069a4db6173';
		$messagePacketsD = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexD);

		// Try invalid case with two Message Packets but one is of invalid length
		$decryptedPayloadHexE = '004bab21ee7253f5f450a6111e82c2a9d719cffe4e4fd94ca5956aef03baaba61c563a3029191f44ff6ebaa6f5d3d9ac177a5225d92d3a3c960d6891c702cdaeb650a11f97690ac9573679dfa77bf5a652af074fa63ab53c675c432153827b88bc7448f878d800e806203213bddff9a3614bec1b9c6300a4c090612129e3a76c7ed1279ed43d65567769ca0c41aa7d1e2b5f3581c7383c2d84717be03c15ad18270e6f004111830576c5a8b75a1711e819b5b12f2c7740005dd848965ef4b43bf8b53f8fc07a99eb546b088e01baa37c2df96a076354e921a46dab238a1f0e83aff07a91dc146171b028e844aec19732f7ab5f2aac5ad6fb84f0055a20d5bc0618061021de7fb4a0fcb7a6cae61490ce0b222b5fe06c5d6f7289fbd993c291d503ed07f6687afdf1a65f40f297005ac5b69092a1ae3f7d2928ababac0d6838e6ee21daf4e9662b9eef44b3d045bd6a4e27d99cc9ff51226ab045c296b70b23dba3d7f351c109499992bf84cdf8fdb40f293e2d491c0e8f33917765fa4b911642de2aaac60d209cd3e87c715a0b8633bf58af37ce0652b34244d12f6215899de5f24446923479841e102119b289dded24d863be96bbe84ce8f2e6426b3b26954e61b0fbb4b647616753fe1f6f7006069a6126173';
		$messagePacketsE = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexE);

		// Try invalid case with a send packet but no Message Packet data
		$decryptedPayloadHexF = '01465cc8f52bc0047f91c1e224670a3ba1d0d4bbbf0c30c98576ad72b7c794179b7a4a97cf2b82cd8e8f280231871e73954c7c54d29cf30fc69cc13691cc9301403a9198ed2a9fbda625c190327e02c30bd21fe0251d383f2ead3b78599c6b92d596bdaaf7274ba9a2160bc70e6c821ac05d1c53e88544feb90db23603f95be4cfb734c3359836257d6209ce8b8775e9ebee463009fb29dfcb21d05ff67151c50d7e9a669f5f264d2db7d82a9cace64b9900c9614f73f64753576576d35c4d025291a2e21baab1ba158d39d732902f4a6462cae4e66f08c0d5bb1b8a347a325e483782ff2a6c5a2cee5e57b5f020b4614501dc0b015e3a952568e53e0aa01ffe9aeb104c027cdcc70aa72a463c5e6775eff2275ee60044a9666f375f34dc5785eff5227ea4d3c38b74df5aea445231fba0adac1e24e773d272d29abc6ea086aa4d0d911ffbb382d5006069aaa56173';
		$messagePacketsF = $this->requestAuth->getMessagesFromPlaintextPayload($decryptedPayloadHexF);

		$this->assertSame($expectedMessagePacketsA, $messagePacketsA);
		$this->assertSame($expectedMessagePacketsB, $messagePacketsB);
		$this->assertSame($expectedMessagePacketsC, $messagePacketsC);

		$this->assertFalse($messagePacketsD);
		$this->assertFalse($messagePacketsE);
		$this->assertFalse($messagePacketsF);
	}

	public function testPerformClientRequestAuthenticationAndDecryption()
	{
		// Second group is correct one
		$groupConfigs = [
			[
				"groupId" => "a0b1c2d3e4f5a6",
				"groupDatabaseName" => "jerichotestdb",
				"groupServerKey" => "8f6250115adca883f4f47c24a8e6c82d14e967d5ab798130f6226c5dded49715964bbc8fae4f1f79d9eada33172ba05665ce687a7af5feb64f7c7e0bbe6c1f69",
				"groupNumberOfUsers" => 2
			],
			[
				"groupId" => "aabbccddeeff0011",
				"groupDatabaseName" => "jerichotestdb",
				"groupServerKey" => "fe89e2bd97df7e3c7e0136e20babdc3104d28d637d611cc3fda5400f83c1b7429d1967fd69501d2c90d446815f1cb430370d19a15105092c68303450087aa0d4",
				"groupNumberOfUsers" => 2
			]
        ];

		// Perform an overall test of all the validation functions at once, should succeed
		$rawPostBodyDataBase64TestA = 'lic1dR4FbzrnZSWxJyxZfeADUkV118d1u45O5UMyRaUmUyQQUKspM+TzyGleaWsCSXkXmp22nkROXkoHakYa8XM9TGaF5pcjPeO9Q119oN2Uv6oukPseuOr19kns9bUVMFun0SKkAifiSBRLTJCM6ZY74Y8rhhdlDbSsZmRYbaZKjdOO1oPaAFuqls6IH4BMI0NxYCDknlktOCBSOpUl5/mjM5nafzulE66TvAZyJVwAWxgz7QFY131g0+cUFb9EYZopRJN7gCJrEkvjS7d/FvGvAOdcIatOGP4kP3Gph6DtL2sa5BJ3bHSBZfIS15DZZHm+ta0GAt8a9IqaDLT+jxfEmZU7stFX5jHUPHcZbHPsYU2PwGGjKbzSQZz0p6PCzb62PR9SZha1qBWjX4uukSIOQ5jqqBJheXX6olX3rRelzLTpYFUF6qkIYee0jKjnaAsEn7QaBEA7oRwNR1M0HX4+jc+ugG0ZtXq/3XHm4aUfAeoKLZIbltbrYem76gVaEJDUKvybvs3jSW+Iezh7q+y/eYLOCdUoHfcFLigK2L56NTVXcmtj5yywZgWiSZrDRnlru9vUfSsZNK80S6ru+q/xSUhEb7BU9yYRsvvvF87EoGBpEwhq08dsLv6K/Yl8ML1Zkv7r2QrDwammfBxTBS8hVHXIVWOaf2XPUuefs8XSVaGaM9yAxree9K+qHRvlqvEx9jfFl53yoafa4XnVLoa3kXYf/cN7dIHa3I26EN19Ei/w08edcRhkmBXsnA09eOKAXke9/xxsF1oFGH1wt18QLc1gIuj9ur8kHbHo80Rpclt/GhxAyRSkcxXLtzR/h3rJSjviVsFxoxQnkKtHgYFHpC3JM9D9XMa9+JLplKwOOiqH7RIbD4c27T0zvfOK46EAvSvwrFn8QfAe757fX1CZqDpaq9y7kq5l0VZiIeZqj2fthJFYgLs=';
		$currentTimestampTestA = 1617599791;
		$validatedRequestTestA =  $this->requestAuth->performClientRequestAuthenticationAndDecryption(
			$groupConfigs, $rawPostBodyDataBase64TestA, $currentTimestampTestA
		);

		// Try second overall test, should succeed
		$rawPostBodyDataBase64TestB = 'hfZ6XgtWj6paRW2e/urCqTpAy4TT1amjCFSa1T+Ep7lDzW6+gzCpalesc99dpG3I9ay9Zcz/bc/wddHWqvSHhsySyFZm+aBxGNgRdymgEYDoe6MfutL5N3jMp13AvVxT9mVJylj2RytQu62jUFAuT81k178dvdovpHEiwknyGTWpbZlCAB/OtVx+78I7ukelLm6BgigXHcm6u2QTjhDz3A99FxXOFiBguSFlKTsuW7bHukLxJNGM0v3pyCYLRXSPhfXhEXjxy+czL3plEnt3Es/MZueq8pbC16WrmWPkclIRGsX56lULJZ6tCde8X0i+Uo0UxXki1hpv6f/RD51Idq9hrdvdX6tknCjbewHUykshId7N3EDh6U61l+GAb+IDxDQCVCUYLvbjes0rlGkvhEWakFjDYAG0sAd042tEJt+LsWaq0Ei/PmOFVZ/2Se7xJWV2xenfNMPSAAAcUdhHEnXA2zc/aL3QJYxhQFUxvj42081N6tMuiiESTb5K4sW0x5DbpCRhb+Rwc/yPN/tKFrUB+rnh17ajnsX6/GVTYlV2kr8WB9ysAK7+84ksdN8BgI6JswcL94YHDIB39cYLAi76YDR8s3zbi4+HdS5Zux36MixiacE93HfCJ51ha9ZOHat3XMgO2HikSkT9lC97qJGGNYvaAmwYNfgWxH6jB5odjqcQXyYg649yRB8BhOPv9RVaza0YxV0HzARUpi3v7FxM7zA8MpeWqs7qeP18H19LBYQbllNdNRgAwH7FAFNEAonI5XUJhchMPhM0eK9XAh87ep0i0DrVV3nWLTDeB6Tob65bzHAOw+mBw5iTPydhLM6rQWD4kXu+cJN5LuVRTmYbC/MUTw3uqvOAQ0tXFGq9xxfSZGVv7kbidQWthihBCTRXAE0UXSLbMDsm9xsKKPW47EfPk3YoHUgb7QRwbqdca5G4/T4v8kJYRkhCdY92yuo7jHlUBDJsdyvOGtp0/J/8cw==';
		$currentTimestampTestB = 1617618459;
		$validatedRequestTestB =  $this->requestAuth->performClientRequestAuthenticationAndDecryption(
			$groupConfigs, $rawPostBodyDataBase64TestB, $currentTimestampTestB
		);

		// Try third overall test with tampered data, should fail
		$rawPostBodyDataBase64TestC = 'ahfZ6XgtWj6paRW2e/urCqTpAy4TT1amjCFSa1T+Ep7lDzW6+gzCpalesc99dpG3I9ay9Zcz/bc/wddHWqvSHhsySyFZm+aBxGNgRdymgEYDoe6MfutL5N3jMp13AvVxT9mVJylj2RytQu62jUFAuT81k178dvdovpHEiwknyGTWpbZlCAB/OtVx+78I7ukelLm6BgigXHcm6u2QTjhDz3A99FxXOFiBguSFlKTsuW7bHukLxJNGM0v3pyCYLRXSPhfXhEXjxy+czL3plEnt3Es/MZueq8pbC16WrmWPkclIRGsX56lULJZ6tCde8X0i+Uo0UxXki1hpv6f/RD51Idq9hrdvdX6tknCjbewHUykshId7N3EDh6U61l+GAb+IDxDQCVCUYLvbjes0rlGkvhEWakFjDYAG0sAd042tEJt+LsWaq0Ei/PmOFVZ/2Se7xJWV2xenfNMPSAAAcUdhHEnXA2zc/aL3QJYxhQFUxvj42081N6tMuiiESTb5K4sW0x5DbpCRhb+Rwc/yPN/tKFrUB+rnh17ajnsX6/GVTYlV2kr8WB9ysAK7+84ksdN8BgI6JswcL94YHDIB39cYLAi76YDR8s3zbi4+HdS5Zux36MixiacE93HfCJ51ha9ZOHat3XMgO2HikSkT9lC97qJGGNYvaAmwYNfgWxH6jB5odjqcQXyYg649yRB8BhOPv9RVaza0YxV0HzARUpi3v7FxM7zA8MpeWqs7qeP18H19LBYQbllNdNRgAwH7FAFNEAonI5XUJhchMPhM0eK9XAh87ep0i0DrVV3nWLTDeB6Tob65bzHAOw+mBw5iTPydhLM6rQWD4kXu+cJN5LuVRTmYbC/MUTw3uqvOAQ0tXFGq9xxfSZGVv7kbidQWthihBCTRXAE0UXSLbMDsm9xsKKPW47EfPk3YoHUgb7QRwbqdca5G4/T4v8kJYRkhCdY92yuo7jHlUBDJsdyvOGtp0/J/8cw==';
		$currentTimestampTestC = 1617618459;
		$validatedRequestTestC =  $this->requestAuth->performClientRequestAuthenticationAndDecryption(
			$groupConfigs, $rawPostBodyDataBase64TestC, $currentTimestampTestC
		);

		// Try fourth overall test with good data but server clock too far out of sync, should fail
		$rawPostBodyDataBase64TestD = 'hfZ6XgtWj6paRW2e/urCqTpAy4TT1amjCFSa1T+Ep7lDzW6+gzCpalesc99dpG3I9ay9Zcz/bc/wddHWqvSHhsySyFZm+aBxGNgRdymgEYDoe6MfutL5N3jMp13AvVxT9mVJylj2RytQu62jUFAuT81k178dvdovpHEiwknyGTWpbZlCAB/OtVx+78I7ukelLm6BgigXHcm6u2QTjhDz3A99FxXOFiBguSFlKTsuW7bHukLxJNGM0v3pyCYLRXSPhfXhEXjxy+czL3plEnt3Es/MZueq8pbC16WrmWPkclIRGsX56lULJZ6tCde8X0i+Uo0UxXki1hpv6f/RD51Idq9hrdvdX6tknCjbewHUykshId7N3EDh6U61l+GAb+IDxDQCVCUYLvbjes0rlGkvhEWakFjDYAG0sAd042tEJt+LsWaq0Ei/PmOFVZ/2Se7xJWV2xenfNMPSAAAcUdhHEnXA2zc/aL3QJYxhQFUxvj42081N6tMuiiESTb5K4sW0x5DbpCRhb+Rwc/yPN/tKFrUB+rnh17ajnsX6/GVTYlV2kr8WB9ysAK7+84ksdN8BgI6JswcL94YHDIB39cYLAi76YDR8s3zbi4+HdS5Zux36MixiacE93HfCJ51ha9ZOHat3XMgO2HikSkT9lC97qJGGNYvaAmwYNfgWxH6jB5odjqcQXyYg649yRB8BhOPv9RVaza0YxV0HzARUpi3v7FxM7zA8MpeWqs7qeP18H19LBYQbllNdNRgAwH7FAFNEAonI5XUJhchMPhM0eK9XAh87ep0i0DrVV3nWLTDeB6Tob65bzHAOw+mBw5iTPydhLM6rQWD4kXu+cJN5LuVRTmYbC/MUTw3uqvOAQ0tXFGq9xxfSZGVv7kbidQWthihBCTRXAE0UXSLbMDsm9xsKKPW47EfPk3YoHUgb7QRwbqdca5G4/T4v8kJYRkhCdY92yuo7jHlUBDJsdyvOGtp0/J/8cw==';
		$currentTimestampTestD = 1617618459 + CommonConstants::REQUEST_VALID_WINDOW_SECONDS + 1;
		$validatedRequestTestD =  $this->requestAuth->performClientRequestAuthenticationAndDecryption(
			$groupConfigs, $rawPostBodyDataBase64TestD, $currentTimestampTestD
		);

		$this->assertTrue($validatedRequestTestA->success);
		$this->assertTrue($validatedRequestTestB->success);

		$this->assertFalse($validatedRequestTestC->success);
		$this->assertFalse($validatedRequestTestD->success);
	}
}
