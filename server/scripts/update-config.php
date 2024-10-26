#!/usr/bin/php
<?php

/**
 * Helper script for modifying the live config file. This is called by setup-group-modifications.sh script.
 */
class UpdateConfig
{
	/**
	 * @var string The path to the live config file
	 */
	public const CONFIG_FILE_PATH = '/var/www/html/config/config.json';

	/**
	 * @param string An error message to be output to the console
	 */
	public $errorMessage = '';


	/**
	 * Constructor
	 * @param array $commandLineArgs The script command line args from special global $argv
	 */
	public function __construct($commandLineArgs)
	{
		$this->commandLineArgs = $commandLineArgs;
	}

	/**
	 * Perform one of the add, list or remove actions based on the first command line argument passed.
	 * NB: Index 0 of the $argv is the script name, which we don't need for this script.
	 * @return string|bool Returns a string for getgroupid or boolean for success/failure of the respective actions
	 */
	public function performAction()
	{
		$action = $this->commandLineArgs[1];

		// Add a chat group
		if ($action === 'add')
		{
			$groupId = $this->commandLineArgs[2];
			$groupDatabaseName = $this->commandLineArgs[3];
			$groupServerKey = $this->commandLineArgs[4];
			$groupNumberOfUsers = $this->commandLineArgs[5];

			return $this->addGroup($groupId, $groupDatabaseName, $groupServerKey, $groupNumberOfUsers);
		}

		// List the current chat groups
		if ($action === 'list')
		{
			return $this->listGroups();
		}

		// Get the Group ID (useful for deleting the group's database)
		if ($action === 'getgroupid')
		{
			// Convert the group list index to int and get the Group ID
			$groupListIndex = (int) $this->commandLineArgs[2];

			return $this->getGroupId($groupListIndex);
		}

		// Remove a chat group
		if ($action === 'remove')
		{
			$groupListIndex = (int) $this->commandLineArgs[2];

			return $this->removeGroup($groupListIndex);
		}

		$this->errorMessage = 'Invalid script action.';
		return false;
	}

	/**
	 * Loads the configuration from the config.json and decodes it from JSON into an associative array
	 * @return array Returns the configuration decoded from JSON into an associative array
	 */
	private function loadAndDecodeConfig()
	{
		// Load the file
		$configJson = file_get_contents(self::CONFIG_FILE_PATH);

		// Decode into an array
		$config = json_decode($configJson, true);

		return $config;
	}

	/**
	 * Encodes the configuration to JSON and saves it to the config.json
	 * @param array The associative array containing the config
	 */
	private function encodeAndSaveConfig($config)
	{
		// Encode into an array
		$configEncoded = json_encode($config, JSON_PRETTY_PRINT);

		// Save the file
		file_put_contents(self::CONFIG_FILE_PATH, $configEncoded);
	}

	/**
	 * Add a new chat group
	 * @param string $groupId
	 * @param string $groupDatabaseName
	 * @param string $groupServerKey
	 * @param string  $groupNumberOfUsers
	 */
	private function addGroup($groupId, $groupDatabaseName, $groupServerKey, $groupNumberOfUsers)
	{
		// Load and decode the config
		$config = $this->loadAndDecodeConfig();

		// Add a new group to the groupConfigs array
		$config['groupConfigs'][] = [
			'groupId' => $groupId,
			'groupDatabaseName' => $groupDatabaseName,
			'groupServerKey' => $groupServerKey,
			'groupNumberOfUsers' => (int) $groupNumberOfUsers
		];

		// Encode the config and save it
		$this->encodeAndSaveConfig($config);
		return true;
	}

	/**
	 * List the active chat groups
	 */
	private function listGroups()
	{
		// Load and decode the config
		$config = $this->loadAndDecodeConfig();

		// Set index, this is used for deletion
		$index = 0;

		// For each group
		foreach ($config['groupConfigs'] as $group)
		{
			// Output to console
			echo "Group $index:\n";
			echo "--------\n";

			// For each key:value pair in the group
			foreach ($group as $groupConfigKey => $groupConfigValue)
			{
				// Set a more readable name for the groupId key
				if ($groupConfigKey === 'groupId')
				{
					$groupConfigName = 'Group ID';
				}

				// Set a more readable name for the groupServerKey key
				if ($groupConfigKey === 'groupServerKey')
				{
					$groupConfigName = 'Group API key';
				}

				// Set a more readable name for the groupNumberOfUsers key
				if ($groupConfigKey === 'groupNumberOfUsers')
				{
					$groupConfigName = 'Group total users';
				}

				// Don't show the database name as typically it's not needed
				if ($groupConfigKey === 'groupDatabaseName')
				{
					continue;
				}

				// Output to console
				echo "$groupConfigName: $groupConfigValue\n";
			}

			// Increment for next item
			$index++;

			// Add extra line break as group separator
			echo "\n";
		}

		return true;
	}

	/**
	 * Get the Group ID which is useful for finding the database to remove
	 * @param int $groupListIndex  The index of the groupConfigs array to be removed
	 * @return string|false Returns the Group ID or false if the index was not valid
	 */
	private function getGroupId($groupListIndex)
	{
		// Load and decode the config
		$config = $this->loadAndDecodeConfig();

		// Init loop counter
		$currentIndex = 0;

		// Search through the group configs
		foreach ($config['groupConfigs'] as $group)
		{
			// If match, return the Group ID
			if ($currentIndex === $groupListIndex)
			{
				return $group['groupId'];
			}

			// Increment for next item
			$currentIndex++;
		}

		$this->errorMessage = 'Invalid group list index.';
		return false;
	}

	/**
	 * Removes a chat group
	 * @param int $groupListIndex The index of the groupConfigs array to be removed
	 */
	private function removeGroup($groupListIndex)
	{
		// Load and decode the config
		$config = $this->loadAndDecodeConfig();

		// Get the current number of groups
		$initialGroupCount = count($config['groupConfigs']);

		// Initialise some variables
		$newGroupList = [];
		$currentIndex = 0;
		$numOfGroupsRemaining = 0;

		// Search through the group configs
		foreach ($config['groupConfigs'] as $group)
		{
			// Only add groups that will remain
			if ($currentIndex !== $groupListIndex)
			{
				$newGroupList[] = $group;
				$numOfGroupsRemaining++;
			}

			// Increment for next item
			$currentIndex++;
		}

		// If no groups were removed, then the group index number was incorrect
		if ($initialGroupCount === $numOfGroupsRemaining)
		{
			$this->errorMessage = 'Invalid group number.';
			return false;
		}

		// Update to the new group list
		$config['groupConfigs'] = $newGroupList;

		// Encode the config and save it
		$this->encodeAndSaveConfig($config);
		return true;
	}
}

// Set the command line args to the class from the special global $argv
$commandLineArgs = $argv;
$updateConfig = new UpdateConfig($commandLineArgs);

// Perform the action based on the command line arguments
$result = $updateConfig->performAction();

// If an error occurred, output that
if ($result === false) {
	echo "\n\n" . $updateConfig->errorMessage . "\n";
}

// Or output the result (for getgroupid action)
else if ($commandLineArgs[1] === 'getgroupid') {
	echo $result;
}

// For the other actions the output is handled in performAction()
