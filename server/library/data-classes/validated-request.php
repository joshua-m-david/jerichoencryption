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
 * A class to store the validated data of the request
 */
class ValidatedRequest
{
	/**
	 * @var bool $success Whether the request succeeded or not
	 */
	public $success;

	/**
	 * @var string $errorMessage The error message to be displayed (only shown if configured to show)
	 */
	public $errorMessage;

	/**
	 * @var string $apiAction The API action i.e. 'send', 'receive', 'test' to be performed (if successfully validated)
	 */
	public $apiAction;

	/**
	 * @var string $fromUser The group user who sent the packet e.g. 'alpha', 'bravo' etc
	 */
	public $fromUser;

	/**
	 * @var array $messagePackets The Message Packets sent in the request (only if a 'send' request)
	 */
	public $messagePackets;

	/**
	 * @var array $currentGroupConfig The detected chat group's configuration
	 */
	public $currentGroupConfig;

	/**
	 * @var string $mac The MAC that was sent in the request as a hexadecimal string
	 */
	public $mac;

	/**
	 * Constructor
	 * @param bool $success Whether the request succeeded or not
	 * @param string $errorMessage The error message to be displayed (only shown if configured to show)
	 * @param string $apiAction The API action i.e. 'send', 'receive', 'test' to be performed (if successfully validated)
	 * @param string $fromUser The group user who sent the packet e.g. 'alpha', 'bravo' etc
	 * @param array $messagePackets The Message Packets sent in the request (only if a 'send' request)
	 * @param array $currentGroupConfig The detected chat group's configuration
	 * @param string $mac The MAC that was sent in the request as a hexadecimal string
	 */
	public function __construct($success = false, $errorMessage = '', $apiAction = '', $fromUser = '', $messagePackets = [], $currentGroupConfig = [], $mac = '')
	{
		// If error will contain these
		$this->success = $success;
		$this->errorMessage = $errorMessage;

		// If success will contain these as well
		$this->apiAction = $apiAction;
		$this->fromUser = $fromUser;
		$this->messagePackets = $messagePackets;
		$this->currentGroupConfig = $currentGroupConfig;
		$this->mac = $mac;
	}
}
