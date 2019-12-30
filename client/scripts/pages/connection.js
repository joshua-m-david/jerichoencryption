/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2019  Joshua M. David
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
		var serverAddressAndPort = db.padData.info.serverAddressAndPort;
		var serverKey = db.padData.info.serverKey;

		// Check if the values are set in localStorage
		if ((serverAddressAndPort !== null) && (serverKey !== null))
		{
			// Update the text fields
			query.getCached('.jsServerAddressAndPort').val(serverAddressAndPort);
			query.getCached('.jsServerKey').val(serverKey);
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
			var serverAddressAndPort = query.getCached('.jsServerAddressAndPort').val();
			var serverKey = query.getCached('.jsServerKey').val();

			// Test the connection to the server
			common.testServerConnection(serverAddressAndPort, serverKey);
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
			var serverAddressAndPort = query.getCached('.jsServerAddressAndPort').val();
			var serverKey = query.getCached('.jsServerKey').val();

			// Save the server connection details to local storage
			common.saveServerConnectionDetails(serverAddressAndPort, serverKey);
		});
	}
};