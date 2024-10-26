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

use Jericho\Database;
use Jericho\CommonConstants;


/**
 * Cleanup functionality to be run inside a cron job
 */
class Cleanup {

	/**
	 * @var int Number of seconds that nonces are kept for in the database (1 hour), after this they are deleted
	 */
	const NONCE_EXPIRY_TIME_SECONDS = 60 * 60;

	/**
	 * @var Database The Database object which allows database operations
	 */
	private $db;

	/**
	 * @var array The group configs which contain information about the chat groups on the server
	 */
	private $groupConfigs;


	/**
	 * Constructor takes the initialised database object and helper objects using dependency injection
	 * @param Database $db The database object (not actually connected to DB yet)
	 * @param array $groupConfigs The group configs as an array loaded from config.json
	 */
	public function __construct($db, $groupConfigs)
	{
		$this->db = $db;
		$this->groupConfigs = $groupConfigs;
	}


	/**
	 * Delete read messages and old nonces from the database every cleanup interval
	 * @return boolean Whether the cleanup task ran or not
	 */
	public function performCleanup()
	{
		$successCount = 0;

		// Go through each group config
		foreach ($this->groupConfigs as $groupConfig)
		{
			// Update the database name so it can connect to the database for that group
			$this->db->updateConfigDatabaseName($groupConfig['groupDatabaseName']);

			// Connect to the group database after the timestamp validated as we will need to check nonces etc
			$connectionSuccess = $this->db->connect();

			// Check that the database connection succeeded for this group
			if (!$connectionSuccess)
			{
				continue;
			}

			// Get the current UNIX timestamp
			$currentTimestamp = time();

			// Cleanup messages that have been read by everyone in the group
			$cleanupReadMessages = $this->cleanupReadMessages($groupConfig['groupNumberOfUsers']);

			// Cleanup old nonces that are no longer inside the time window
			$cleanupOldNonces = $this->cleanupOldNonces($currentTimestamp);

			// Check if cleanup was run successfully and update the last time the cleanup was run
			if ($cleanupReadMessages && $cleanupOldNonces && $this->updateLastCleanupTime($currentTimestamp))
			{
				// Increment count of successful group database cleans
				$successCount++;
			}
		}

		// Return true if all groups were successfully cleaned
		return ($successCount === count($this->groupConfigs));
	}

	/**
	 * Updates the database with when the cleanup was last run
	 * @param int $currentTimestamp
	 * @return boolean
	 */
	public function updateLastCleanupTime($currentTimestamp)
	{
		// Run the query
		$query = 'UPDATE settings SET cleanup_last_run = :cleanup_last_run';
		$params = array('cleanup_last_run' => $currentTimestamp);
		$result = $this->db->preparedUpdate($query, $params);

		// If the query returned one row affected, succeed
		if ($result === 1)
		{
			return true;
		}

		return false;
	}

	/**
	 * Removes read messages from the database if everyone in the group has read the message. It does this by reading
	 * the read_by_alpha, read_by_bravo etc flags in the row to see if the user has retrieved them.
	 * @param int $groupNumberOfUsers The number of users in the group (from the group configuration)
	 * @return boolean Whether the query ran successfully or not
	 */
	public function cleanupReadMessages($groupNumberOfUsers)
	{
		// Start delete query
		$query = 'DELETE FROM messages WHERE ';
		$params = array();

		// Build remainder of query
		for ($i = 0; $i < $groupNumberOfUsers; $i++)
		{
			// Build up the query and parameters, checking the read flag for each user
			$readByParam = 'read_by_' . CommonConstants::VALID_USER_LIST_PLAIN[$i];
			$query .= "$readByParam = :$readByParam";
			$params[$readByParam] = true;

			// If there are more users continue adding to query
			if ($i < $groupNumberOfUsers - 1)
			{
				$query .= ' AND ';
			}
		}

		// Run delete query
		$result = $this->db->preparedUpdate($query, $params);

		// If query failed return false
		if ($result === false)
		{
			return false;
		}

		// Success
		return true;
	}

	/**
	 * Removes old nonces that are no longer inside the acceptable timestamp window
	 * @param int $currentTimestamp The current timestamp
	 */
	public function cleanupOldNonces($currentTimestamp)
	{
		// Any nonces older than this timestamp get removed
		$oldestAllowedTimestamp = $currentTimestamp - self::NONCE_EXPIRY_TIME_SECONDS;

		// Cleanup old nonces
		$query = 'DELETE FROM nonces WHERE nonce_sent_timestamp <= :oldest_allowed_timestamp';
		$params = array(
			'oldest_allowed_timestamp' => $oldestAllowedTimestamp
		);

		// Execute the query
		$result = $this->db->preparedUpdate($query, $params);

		// If the query failed then return false. Don't check for number of rows deleted
		// because sometimes there may not be any nonces to delete from the database.
		if ($result === false)
		{
			return false;
		}

		// Otherwise success
		return true;
	}
}
