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
 * A class to store the data for the response before it is encrypted and authenticated
 */
class Response
{
	/******************************
	 * Success codes (range 0 - 99)
	 ******************************/

	/**
	 * @var int RESPONSE_SUCCESS This is the generic response success code. It could mean a message was sent
	 *                           successfully or that messages were received successfully.
	 */
	const RESPONSE_SUCCESS = 0;

	/**
	 * @var int RESPONSE_SUCCESS_NO_MESSAGES This is the response code when it made a successful receive
	 *                                       messages API request but there were no messages to collect
	 */
	const RESPONSE_SUCCESS_NO_MESSAGES = 1;


	/*************************************************
	 * Error codes for server issues (range 100 - 149)
	 *************************************************/

	/**
	 * @var int RESPONSE_ERROR_DB_QUERY_FAILED The DB query failed
	 */
	const RESPONSE_ERROR_DB_QUERY_FAILED = 100;

	/**
	 * @var int RESPONSE_ERROR_DB_NO_TEST_RECORD Could not find the test record in the database
	 */
	const RESPONSE_ERROR_DB_NO_TEST_RECORD = 101;

	/**
	 * @var int RESPONSE_ERROR_INVALID_API_ACTION Invalid or not implemented API action
	 */
	const RESPONSE_ERROR_INVALID_API_ACTION = 102;

	/**
	 * @var int RESPONSE_ERROR_NO_MESSAGES_SENT No messages were sent in the request
	 */
	const RESPONSE_ERROR_NO_MESSAGES_SENT = 103;

	/**
	 * @var int RESPONSE_ERROR_MESSAGES_INSERTED_MISMATCH The number of messages inserted in the DB did not match the
	 *                                                    number of messages that were sent in the request
	 */
	const RESPONSE_ERROR_MESSAGES_INSERTED_MISMATCH = 104;


	/************************************************************************
	 * Error codes reserved for client side decoding errors (range 150 - 199)
	 ************************************************************************/


	/**
	 * @var int $responseCode The response code (use constants for success, specific error codes etc)
	 */
	public $responseCode;

	/**
	 * @var array $userMessagePackets An array of Message Packets and respective Users who sent the packet e.g.
	 *                                ['fromUser' => 'alpha', 'messagePacket' => 'abcdef0123456789...']
	 */
	public $userMessagePackets;

	/**
	 * @var string $errorMessage An optional extra error message to be shown only if debug mode is turned on
	 */
	public $errorMessage;


	/**
	 * Constructor
	 * @param int $responseCode The response code (use constants for success, specific error codes etc)
	 * @param array $userMessagePackets An array of Message Packets and respective Users who sent the packet e.g.
	 *                                  [
	 *                                      'fromUser' => 'alpha',
	 *                                      'messagePacket' => 'abcdef0123456789...'
	 *                                  ]
	 * @param string $errorMessage An optional extra error message to be shown only if debug mode is turned on
	 */
	public function __construct($responseCode = 0, $userMessagePackets = [], $errorMessage = '')
	{
		$this->responseCode = $responseCode;
		$this->userMessagePackets = $userMessagePackets;
		$this->errorMessage = $errorMessage;
	}
}
