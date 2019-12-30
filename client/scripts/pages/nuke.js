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
 * Functionality to emergency delete everything from the local device storage of every user in the chat group. It does
 * this by sending a special text command 'init auto nuke' which is encrypted and authenticated using the one-time pad.
 * When this command is received by the other users in the group, their local databases will be wiped immediately. The
 * person initiating the auto nuke will have their own one-time pad database wiped once a successful response has been
 * received from the server that the command was sent successfully.
 */
var nukePage = {

	/**
	 * Initialise the page code
	 */
	init: function()
	{
		nukePage.initAutoNukeButton();
		nukePage.initLocalNukeButton();
	},

	/**
	 * Initialises the main automatic nuke process
	 */
	initAutoNukeButton: function()
	{
		// On button click
		query.getCached('.jsInitAutoNukeButton').on('click', function()
		{
			nukePage.fireAutoNuke();
		});
	},

	/**
	 * Initialises the local database wipe process if they are unable to connect to the server for whatever reason
	 */
	initLocalNukeButton: function()
	{
		// On button click
		query.getCached('.jsLocalNukeButton').on('click', function()
		{
			// Clear the local database
			db.nukeDatabase();

			// Show message
			app.showStatus('success', 'The local database was nuked successfully. However encrypted server messages remain and the one-time pads still exist on the other users\' machines.');
		});
	},

	/**
	 * Initialises the process
	 */
	fireAutoNuke: function()
	{
		// Make sure there is data in the database
		if (db.padData.info.serverAddressAndPort === null)
		{
			app.showStatus('error', 'No data in local database to delete.');
			return false;
		}

		// Get the next pad from the local database and use it to encrypt the auto nuke command
		var pad = common.getPadToEncryptMessage();

		// If there's no pads available to encrypt the message, don't let them send it
		if (pad === false)
		{
			app.showStatus('error', 'No available pads. Please generate more pads and exchange them with your chat partner.');
			return false;
		}

		// Encrypt the auto nuke command and create the MAC
		var autoNukeCommand = 'init auto nuke';
		var ciphertextMessageAndMac = common.encryptAndAuthenticateMessage(autoNukeCommand, pad);

		// Get the server address and key
		var serverAddressAndPort = db.padData.info.serverAddressAndPort;
		var serverKey = db.padData.info.serverKey;

		// Package the data to be sent to the server
		var data = {
			'user': db.padData.info.user,
			'apiAction': 'sendMessage',
			'msg': ciphertextMessageAndMac
		};

		// Fire the nuke
		common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseData)
		{
			// If the server response is authentic
			if (validResponse)
			{
				// If it saved the message on the server
				if (responseData.success)
				{
					// Clear the local database
					db.nukeDatabase();

					// Show message
					app.showStatus('success', 'Your contacts will be nuked when they are online. The local database was also nuked successfully.');

					// Return early here so they are not shown the option to
					// clear the local database manually as it is already done
					return true;
				}
				else {
					// Failed to send
					app.showStatus('error', responseData.statusMessage);
				}
			}

			// If response check failed it means there was probably interference from attacker altering data or MAC
			else if (validResponse === false)
			{
				app.showStatus('error', 'An unauthentic response from server was detected. Try again.');
			}

			else {
				// Most likely cause is user has incorrect server url or key entered.
				// Another alternative is the attacker modified their request while en route to the server
				app.showStatus('error', 'There was an error contacting the server. Check: 1) you are connected to the network, '
				                      + '2) the client/server configurations are correct, and 3) client/server system clocks are '
				                      + 'up to date. If everything is correct, the data may have been tampered with by an attacker. '
				                      + 'Double check you are connected to the network and that the client and server configurations '
				                      + 'are correct.');
			}

			// The emergency message to nuke the other users failed so perhaps the lines have
			// been cut already, give the user the option to clear their local database manually
			query.getCached('.jsLocalNukeContainer').show();
		});
	},

	/**
	 * Page cleanup function to be run when the user leaves the page
	 */
	cleanup: function()
	{
		// Hide the local database nuke option as it's only shown if the regular auto nuke method fails
		query.getCached('.jsLocalNukeContainer').hide();
	}
};