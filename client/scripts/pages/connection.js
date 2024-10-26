/*!
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

// Use ECMAScript 5's strict mode
'use strict';

/**
 * Functions for the server connection testing page
 */
var connectionPage = {

	/**
	 * Initialise the page
	 */
	init: function()
	{
		// Preload the connection details if available and initialise buttons
		connectionPage.preloadServerDetails();
		connectionPage.initTestServerConnectionButton();
		connectionPage.initSaveSettingsButton();
	},

	/**
	 * Preload values into the text boxes if they already have connection settings in localStorage
	 */
	preloadServerDetails: function()
	{
		// Get values from localStorage database
		const serverAddressAndPort = db.padData.info.serverAddressAndPort;
		const serverGroupIdentifier = db.padData.info.serverGroupIdentifier;
		const serverGroupKey = db.padData.info.serverGroupKey;

		// Check if the values are set in localStorage
		if ((serverAddressAndPort !== null) && (serverGroupIdentifier !== null) && (serverGroupKey !== null))
		{
			// Update the text fields
			query.getCached('.jsServerAddressAndPort').val(serverAddressAndPort);
			query.getCached('.jsServerGroupIdentifier').val(serverGroupIdentifier);
			query.getCached('.jsServerGroupKey').val(serverGroupKey);
		}
	},

	/**
	 * Initialise the Test server connection button
	 */
	initTestServerConnectionButton: function()
	{
		// On button click
		query.getCached('.jsTestServerConnectionButton').on('click', function()
		{
			// Get the values from the text fields
			const serverAddressAndPort = query.getCached('.jsServerAddressAndPort').val();
			let serverGroupIdentifier = query.getCached('.jsServerGroupIdentifier').val();
			let serverGroupKey = query.getCached('.jsServerGroupKey').val();

			// Convert possible uppercase chars from user input to lowercase hex symbols
			serverGroupIdentifier = serverGroupIdentifier.toLowerCase();
			serverGroupKey = serverGroupKey.toLowerCase();

			// Test the connection to the server
			common.testServerConnection(serverAddressAndPort, serverGroupIdentifier, serverGroupKey);
		});
	},

	/**
	 * Initialise the Save settings button
	 */
	initSaveSettingsButton: function()
	{
		// On button click
		query.getCached('.jsSaveSettingsButton').on('click', function()
		{
			// Get the details from the text fields
			const serverAddressAndPort = query.getCached('.jsServerAddressAndPort').val();
			let serverGroupIdentifier = query.getCached('.jsServerGroupIdentifier').val();
			let serverGroupKey = query.getCached('.jsServerGroupKey').val();

			// Convert possible uppercase chars from user input to lowercase hex symbols
			serverGroupIdentifier = serverGroupIdentifier.toLowerCase();
			serverGroupKey = serverGroupKey.toLowerCase();

			// Save the server connection details to local storage
			common.saveServerConnectionDetails(serverAddressAndPort, serverGroupIdentifier, serverGroupKey);

			// Show the status message
			app.showStatus('success', 'Settings saved to local database.');
		});
	}
};