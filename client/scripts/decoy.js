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
 * Functionality for sending decoy messages of random data to the other users
 * in the chat group at random intervals to frustrate traffic analysis. This means
 * that anyone watching the traffic between the clients and the server do not even
 * know if real messages are being sent or not because the users could have just
 * left the program running and it was sending decoy messages the whole time. The
 * receiving client of a decoy message will ignore it because the random pad
 * identifier of the decoy message will not belong to any pads of the sending user.
 */
var decoy = {

	// The minimum and maximum time window in milliseconds, a random number between the minimum and maximum number
	// of seconds will be chosen and the decoy message will be triggered to send after this time has elapsed.
	minTimeWindow: 1 * 1000,	// 1 second
	maxTimeWindow: 90 * 1000,	// 90 seconds (1.5 minutes)

	// The time a message was last received from any another user
	lastMessageReceivedTimestamp: null,

	// Time window in seconds to determine if a user is online
	userOnlineTimestampWindow: 300,	// 300 seconds (5 minutes)

	// Timer ID for the decoy timer to send decoy messages
	timerId: null,

	/**
	 * Starts a timer to send a decoy message to the server after a random amount of time
	 */
	startDecoyMessageTimer: function()
	{
		// If a one-time pad database is not loaded, exit out
		if (db.padData.info.user === null)
		{
			return false;
		}

		// Get random number between 1000 milliseconds (1 second) and x milliseconds
		var triggerTimeMilliseconds = common.getRandomIntInRange(decoy.minTimeWindow, decoy.maxTimeWindow);

		// Run timer to execute the code in the function after the number of milliseconds has elapsed
		decoy.timerId = setTimeout(function()
		{
			// If other users have sent messages in the last 3 minutes then we will send a decoy message
			if (decoy.checkIfOtherUsersAreOnline())
			{
				// Get a random pad identifier, then try find it in the user's own set of pads
				var randomPadIdentifier = common.getRandomBits(common.padIdentifierSizeBinary, 'hexadecimal');
				var padData = common.getPadToDecryptMessage(randomPadIdentifier, db.padData.info.user);

				// If the search couldn't find a real pad identifier matching the random pad identifier, then the random
				// pad identifier won't be mistaken for a real message, so now we can safely send it as a decoy message.
				if (padData.padIndex === null)
				{
					// Get the remaining random bits for the decoy message
					var lengthOfMessageBits = common.totalPadSizeBinary - common.padIdentifierSizeBinary;
					var messageBits = common.getRandomBits(lengthOfMessageBits, 'hexadecimal');
					var decoyMessage = randomPadIdentifier + messageBits;

					// Send the decoy message to the server
					decoy.sendDecoyMessageToServer(randomPadIdentifier, decoyMessage, triggerTimeMilliseconds);
				}
			}

			// Start next timer for next decoy message. Note: in the rare case where the generated random pad identifier
			// matched a real pad in the database then we won't send a decoy message this loop and start a new timer anyway.
			decoy.startDecoyMessageTimer();

		}, triggerTimeMilliseconds);
	},

	/**
	 * Don't send decoy messages if other users haven't sent a message in the last 3 minutes, otherwise it looks like
	 * one person is just talking in a one way direction and it doesn't look like a real conversation is taking place.
	 * @returns {Boolean}
	 */
	checkIfOtherUsersAreOnline: function()
	{
		// Get the current UTC timestamp
		var currentUtcTimestamp = common.getCurrentUtcTimestamp();

		// If just opened the chat session and there are no messages received then the
		// program will send one decoy message until another user signs on to start chatting.
		if (decoy.lastMessageReceivedTimestamp === null)
		{
			// Update the last received timestamp to x seconds ago, so in x seconds time if the next loop gets
			// here and there have been no new messages from other users it will stop sending decoy messages.
			decoy.lastMessageReceivedTimestamp = currentUtcTimestamp - decoy.userOnlineTimestampWindow;

			// Return true so a decoy message will be sent
			return true;
		}

		// Get the time difference between the current time and the last time a message was received
		var timeDifference = currentUtcTimestamp - decoy.lastMessageReceivedTimestamp;

		// If there have been messages from other users in the last x seconds, then we will send a decoy message
		if (timeDifference <= decoy.userOnlineTimestampWindow)
		{
			return true;
		}

		// Otherwise if there haven't been any messages from other users in the
		// last x seconds then we won't send any decoy messages this loop.
		else {
			console.info('No recent messages from other users in the last ' + timeDifference + ' seconds, not sending a decoy message.');
			return false;
		}
	},

	/**
	 * Sends the decoy message to the server
	 * @param {String} randomPadIdentifier The pad identifier for the decoy message (used for logging)
	 * @param {String} decoyMessage The decoy message which is just random data and the same length as a normal pad
	 * @param {String} triggerTimeMilliseconds The random time interval after which the decoy message was sent
	 */
	sendDecoyMessageToServer: function(randomPadIdentifier, decoyMessage, triggerTimeMilliseconds)
	{
		// If there's no pad data loaded, stop trying to send decoy messages to the server
		if (db.padData.info.serverAddressAndPort === null)
		{
			app.showStatus('error', "No pads have been loaded into this device's database.");
			decoy.stopTimerForDecoyMessages();

			return false;
		}

		// Package the data to be sent to the server
		const requestData = {
			fromUser: db.padData.info.user,
			apiAction: networkCrypto.apiActionSend,
			serverAddressAndPort: db.padData.info.serverAddressAndPort,
			serverGroupIdentifier: db.padData.info.serverGroupIdentifier,
			serverGroupKey: db.padData.info.serverGroupKey,
			messagePackets: [decoyMessage]
		};

		// Send the message off to the server
		common.sendRequestToServer(requestData, function(validResponse, responseCode)
		{
			// If the server response is authentic and the decoy message was stored successfully on the server
			if (validResponse && responseCode === networkCrypto.RESPONSE_SUCCESS)
			{
				// Log useful information to console
				console.info('Decoy message ' + randomPadIdentifier + ' successfully sent to server at '
				            + common.getCurrentLocalTime() + ' after ' + (triggerTimeMilliseconds / 1000)
				            + 's random delay.');
			}
			else {
				// Most likely cause is user has incorrect server url or key entered.
				// Another alternative is the attacker modified their request while en route to the server
				app.showStatus('error', 'Error sending decoy message to server. '
				                      + networkCrypto.getStatusMessage(responseCode) + ' '
				                      + networkCrypto.getNetworkTroubleshootingText());
			}
		});
	},

	/**
	 * Turn off the decoy messages
	 */
	stopTimerForDecoyMessages: function()
	{
		window.clearTimeout(decoy.timerId);
	}
};