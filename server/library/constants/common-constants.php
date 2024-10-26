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
 * A class with common constants used by multiple classes
 */
class CommonConstants
{
	/**
	 * @var string The API Action to receive messages
	 */
	const API_ACTION_RECEIVE = 'receive';

	/**
	 * @var string The API Action to send a message or messages
	 */
	const API_ACTION_SEND = 'send';

	/**
	 * @var string The API Action to send a test request and get a test response back
	 */
	const API_ACTION_TEST = 'test';

	/**
	 * @var array The whitelist of API actions, using the short reference code as the key
	 */
	const VALID_API_ACTIONS = [
		'r' => self::API_ACTION_RECEIVE,
		's' => self::API_ACTION_SEND,
		't' => self::API_ACTION_TEST
	];


	/**
	 * @var array The whitelist of valid usernames, using the From User short
	 *            reference code as the key which is simply the first letter
	 */
	const VALID_USER_LIST = [
		'a' => 'alpha',
		'b' => 'bravo',
		'c' => 'charlie',
		'd' => 'delta',
		'e' => 'echo',
		'f' => 'foxtrot',
		'g' => 'golf'
	];

	/**
	 * @var array The whitelist of valid usernames, using a numerical index 0-n and the From User as the values
	 */
	const VALID_USER_LIST_PLAIN = [
		'alpha',
		'bravo',
		'charlie',
		'delta',
		'echo',
		'foxtrot',
		'golf'
	];

	/**
	 * @var int MIN_NUM_OF_USERS The minimum number of users for a chat group
	 */
	const MIN_NUM_OF_USERS = 2;

	/**
	 * @var int MAX_NUM_OF_USERS The maximum number of users for a chat group (should match count of user list)
	 */
	const MAX_NUM_OF_USERS = 7;



	/**
	 * @var int The bit length of the From User short code (a = alpha, b = bravo etc) portion of the packet
	 */
	const FROM_USER_BITS_LENGTH = 8;

	/**
	 * @var int The bit length of a client encrypted OTP Message Packet (including the pad identifier)
	 */
	const MESSAGE_PACKET_BITS_LENGTH = 1536;

	/**
	 * @var int The bit length of the portion of the packet which identifies the length of the padding
	 */
	const PADDING_LENGTH_IDENTIFIER_BITS_LENGTH = 16;


	/**
	 * @var int The bit length of the API Action (r = receive, s = send etc) portion of the packet
	 */
	const REQUEST_API_ACTION_BITS_LENGTH = 8;

	/**
	 * @var int The bit length of the request nonce, chosen to be the same length as the Skein output size
	 */
	const REQUEST_NONCE_BITS_LENGTH = 512;

	/**
	 * @var int The bit length of the request Skein-512 MAC digest
	 */
	const REQUEST_MAC_BITS_LENGTH = 512;

	/**
	 * @var int Number of seconds after a request has been sent that the request is valid (+/- 5 minutes from server time)
	 */
	const REQUEST_VALID_WINDOW_SECONDS = 60 * 5;

	/**
	 * @var int The bit length of the UNIX Timestamp portion of the packet in bits
	 */
	const REQUEST_TIMESTAMP_BITS_LENGTH = 40;

	/**
	 * @var int The maximum number of messages that can be sent per client per request
	 */
	const REQUEST_MAX_MESSAGE_PACKETS = 3;

	/**
	 * @var int The minimum bit length of the request padding portion, set at the size of 1 Message Packet (384 bytes)
	 *          so a network observer thinks at least 1 message is always being sent.
	 */
	const REQUEST_MIN_PADDING_BITS_LENGTH = self::MESSAGE_PACKET_BITS_LENGTH;

	/**
	 * @var int The maximum bit length of the request padding portion, set at the size of 3 Message Packets (384
	 *          bytes each) so they think at least 1 - 3 messages are always being sent.
	 */
	const REQUEST_MAX_PADDING_BITS_LENGTH = self::MESSAGE_PACKET_BITS_LENGTH * self::REQUEST_MAX_MESSAGE_PACKETS;

	/**
	 * @var int The minimum bit length of the Message Packets portion of the request, set at 0 because not every request
	 *          has messages to be sent (e.g. receive or test packets)
	 */
	const REQUEST_MIN_MESSAGE_PACKETS_BITS_LENGTH = 0;

	/**
	 * @var int The maximum bit length of the Message Packets portion of the request, set at 3 because 3 Message Packets
	 *          can be sent per request
	 */
	const MAX_REQUEST_MESSAGE_PACKETS_BITS_LENGTH = self::MESSAGE_PACKET_BITS_LENGTH * self::REQUEST_MAX_MESSAGE_PACKETS;

	/**
	 * @var int The minimum length of the ciphertext portion of the request in bits. Calculated as:
	 *
	 *          Padding length identifier (2 bytes) +
	 *          Minimum request padding (384 bytes or 1 Message Packet) +
	 *          No encrypted message packets (0 bytes) +
	 *          UNIX Timestamp (5 bytes) +
	 *          From User (1 byte) +
	 *          API Action length (1 byte)
	 */
	const REQUEST_MIN_CIPHERTEXT_BITS_LENGTH = self::PADDING_LENGTH_IDENTIFIER_BITS_LENGTH +
		self::REQUEST_MIN_PADDING_BITS_LENGTH +
		self::REQUEST_MIN_MESSAGE_PACKETS_BITS_LENGTH +
		self::REQUEST_TIMESTAMP_BITS_LENGTH +
		self::FROM_USER_BITS_LENGTH +
		self::REQUEST_API_ACTION_BITS_LENGTH;

	/**
	 * @var int The maximum length of the ciphertext portion of the request in bits. Calculated as:
	 *
	 *          Padding length identifier (2 bytes) +
	 *          Maximum request padding (576 bytes or 3 message packets) +
	 *          3 encrypted message packets (576 bytes or 3 message packets) +
	 *          UNIX Timestamp (5 bytes) +
	 *          From User (1 byte) +
	 *          API Action length (1 byte)
	 */
	const REQUEST_MAX_CIPHERTEXT_BITS_LENGTH = self::PADDING_LENGTH_IDENTIFIER_BITS_LENGTH +
		self::REQUEST_MAX_PADDING_BITS_LENGTH +
		self::MAX_REQUEST_MESSAGE_PACKETS_BITS_LENGTH +
		self::REQUEST_TIMESTAMP_BITS_LENGTH +
		self::FROM_USER_BITS_LENGTH +
		self::REQUEST_API_ACTION_BITS_LENGTH;

	/**
	 * @var int The minimum valid bit length of a raw Base64 request from the client. Calculated as:
	 *
	 *           Nonce (64 bytes) +
	 *           Minimum length encrypted data portion +
	 *           MAC tag (64 bytes)
	 */
	const REQUEST_MIN_VALID_BITS_LENGTH = self::REQUEST_NONCE_BITS_LENGTH +
		self::REQUEST_MIN_CIPHERTEXT_BITS_LENGTH +
		self::REQUEST_MAC_BITS_LENGTH;

	/**
	 * @var int The maximum valid bit length of a raw Base64 request from the client. Calculated as:
	 *
	 *           Nonce (64 bytes) +
	 *           Maximum length encrypted data portion +
	 *           MAC tag (64 bytes)
	 */
	const REQUEST_MAX_VALID_BITS_LENGTH = self::REQUEST_NONCE_BITS_LENGTH +
		self::REQUEST_MAX_CIPHERTEXT_BITS_LENGTH +
		self::REQUEST_MAC_BITS_LENGTH;


	/**
	 * @var int The bit length of the response nonce, chosen to be the same length as the Skein output size
	 */
	const RESPONSE_NONCE_BITS_LENGTH = 512;

	/**
	 * @var int The length of the Response Code portion of the response packet in bits
	 */
	const RESPONSE_CODE_BITS_LENGTH = 8;

	/**
	 * @var int The length of the Number of Messages portion of the response packet in bits
	 */
	const RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH = 16;

	/**
	 * @var int The bit length of a User Message Packet in a response (which is the concatenation of the From User and Message Packet)
	 */
	const RESPONSE_USER_MESSAGE_PACKET_BITS_LENGTH = self::FROM_USER_BITS_LENGTH + self::MESSAGE_PACKET_BITS_LENGTH;

	/**
	 * @var int The minimum padding size in bits for the response packet. We want any network observer to think that
	 *          at least one message has been returned. This is the length of one User Message Packet (385 bytes),
	 *          which is calculated as the From User (1 byte) + Message Packet (384 bytes) concatenated together.
	 */
	const RESPONSE_MIN_PADDING_BITS = self::RESPONSE_USER_MESSAGE_PACKET_BITS_LENGTH;

	/**
	 * @var int The maximum padding size in bits for the response packet. This is the size of 3 User Message Packets
	 *          which is an estimated upper limit of messages that might get returned on average if the user is online.
	 */
	const RESPONSE_MAX_PADDING_BITS = self::RESPONSE_USER_MESSAGE_PACKET_BITS_LENGTH * 3;

	/**
	 * @var int The minimum User Message Packets length that could be returned in the response. Set at 0 bytes because
	 *          some responses might not contain message packets, i.e. no messages to retrieve, or just a response code.
	 */
	const RESPONSE_MIN_USER_MESSAGE_PACKETS_BITS_LENGTH = 0;

	/**
	 * @var int The minimum size error response in random bits to pretend a real authenticated packet was returned.
	 *          This is calculated as:
	 *
	 * Nonce (64 bytes) ||
	 * Padding (385 bytes) - The size of 1 User Message Packet so an observer always thinks 1 message was returned ||
	 * User Message Packets (0 bytes) - Some responses might not contain message packets, i.e. no messages to retrieve, or just a response code ||
	 * Number of Messages (2 bytes) ||
	 * Response Code (1 byte) ||
	 * MAC (64 bytes)
	 */
	const ERROR_RESPONSE_MIN_RANDOM_BITS = self::RESPONSE_NONCE_BITS_LENGTH +
		self::RESPONSE_MIN_PADDING_BITS +
		self::RESPONSE_MIN_USER_MESSAGE_PACKETS_BITS_LENGTH +
		self::RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH +
		self::RESPONSE_CODE_BITS_LENGTH +
		self::REQUEST_MAC_BITS_LENGTH;

	/**
	 * @var int The maximum size error response in random bytes to pretend a few real authenticated packets were
	 *          returned. This is calculated as:
	 *
	 * Nonce (64 bytes) ||
	 * Padding - Estimating max padding size of 3 User Message Packets (385 bytes each) ||
	 * User Message Packets - Estimating max average of 3 User Message Packets (385 bytes each) ||
	 * Number of Messages (2 bytes) ||
	 * Response Code (1 byte) ||
	 * MAC (64 bytes)
	 */
	const ERROR_RESPONSE_MAX_RANDOM_BITS = self::RESPONSE_NONCE_BITS_LENGTH +
		self::RESPONSE_MAX_PADDING_BITS +
		self::RESPONSE_MAX_PADDING_BITS +
		self::RESPONSE_NUM_OF_MESSAGES_BITS_LENGTH +
		self::RESPONSE_CODE_BITS_LENGTH +
		self::REQUEST_MAC_BITS_LENGTH;
}
