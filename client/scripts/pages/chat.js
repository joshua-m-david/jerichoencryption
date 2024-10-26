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
 * Functionality for the chat page
 */
var chatPage = {

	/** The interval id for checking new messages */
	checkForMessagesIntervalId: null,

	/** How often to check for new messages in milliseconds */
	checkForMessagesIntervalTime: 3000,								// 3 seconds

	/**
	 * This is used as exponential backoff functionality. If a connection to the API fails, it will retry after this
	 * many milliseconds. If it fails after that it will double the current time and then re-try after this time.
	 */
	checkForMessagesRetryIntervalTime: 3000,

	/** Whether this is the first check for new messages or not **/
	firstCheckForNewMessages: true,

	/**
	 * Flag for whether or not a request is currently being processed for receiving messages. This is used to
	 * prevent multiple requests being sent to the server from the same client so it waits for a response first.
	 */
	processingReceiveMessagesRequest: false,

	/** When a message was last received from the user */
	lastMessageReceivedFromUserTimestamps: {
		alpha: null,
		bravo: null,
		charlie: null,
		delta: null,
		echo: null,
		foxtrot: null,
		golf: null
	},

	/**
	 * Initialise the page code
	 */
	init: function()
	{
		// Initialise the page
		chatPage.scrollChatWindowToBottom();
		chatPage.initSendMessageButton();
		chatPage.bindEnterKeyToSendMessage();
		chatPage.initGroupUserStatus();
		chatPage.startIntervalToReceiveMessages();
		chatPage.initDisplayForCharsRemaining();
		chatPage.initToggleAudioButton();
		chatPage.initToggleVibrationButton();
		chatPage.initToggleWebNotificationsButton();
		decoy.startDecoyMessageTimer();
	},

	/**
	 * Make the chat window always scroll to the bottom if there are lots of messages on page load
	 */
	scrollChatWindowToBottom: function()
	{
		query.getCached('.jsMainChat').each(function()
		{
			var scrollHeight = Math.max(this.scrollHeight, this.clientHeight);

			this.scrollTop = scrollHeight - this.clientHeight;
		});
	},

	/**
	 * Initialises the send message button, which when clicked will encrypt and send the message to the server
	 */
	initSendMessageButton: function()
	{
		// If the send message function is clicked
		query.getCached('.jsSendMessageButton').on('click', function()
		{
			// Get plaintext message
			var plaintextMessage = query.getCached('.jsChatInput').val();
			var plaintextLengthInBytes = common.getUtf8TextLengthInBytes(plaintextMessage);

			// Make sure they've entered in some data
			if (plaintextLengthInBytes > common.messageSize)
			{
				app.showStatus('error', 'Message length exceeds allowed limit of ' + common.messageSize + ' bytes.');
				return false;
			}

			// Make sure they've entered in some data
			if (plaintextMessage === '')
			{
				app.showStatus('error', 'Enter a message to send.');
				return false;
			}

			// Get the next pad from the local database and use it to encrypt the message
			var pad = common.getPadToEncryptMessage();

			// If there's no pads available to encrypt the message, don't let them send it
			if (pad === false)
			{
				app.showStatus('error', 'No available pads. Please generate more pads and exchange them with your chat partner.');
				return false;
			}

			// Encrypt the message and create the MAC
			var ciphertextMessageAndMac = common.encryptAndAuthenticateMessage(plaintextMessage, pad);
			var padIdentifier = common.getPadIdentifierFromCiphertext(ciphertextMessageAndMac);

			// Package the data to be sent to the server
			const requestData = {
				fromUser: db.padData.info.user,
				apiAction: networkCrypto.apiActionSend,
				serverAddressAndPort: db.padData.info.serverAddressAndPort,
				serverGroupIdentifier: db.padData.info.serverGroupIdentifier,
				serverGroupKey: db.padData.info.serverGroupKey,
				messagePackets: [ciphertextMessageAndMac]	// ToDo: split long messages into separate message packets
			};

			// Send the message off to the server
			common.sendRequestToServer(requestData, function(validResponse, responseCode)
			{
				// If the server response is authentic and message/s were stored successfully on the server
				if (validResponse && responseCode === networkCrypto.RESPONSE_SUCCESS)
				{
					// Find the message in the chat window with that identifier and update the status to 'Sent'
					query.get('.jsMessage[data-pad-identifier=' + padIdentifier + '] .jsMessageStatus')
							.text('Sent')
							.addClass('isSendSuccess');

					// If the user initiated the auto nuke from typing into the chat,
					// process it now since it's already sent to the other users
					if (plaintextMessage.indexOf('init auto nuke') > -1) {
						chatPage.processAutoNuke(db.padData.info.user);
					}

					// Succeeded so can return early
					return true;
				}

				// Otherwise show a status message and add additional troubleshooting information for the user.
				// Most likely cause is user has incorrect server url/key entered. Another alternative is the
				// attacker modified their request while en route to the server.
				app.showStatus('error', 'Error sending message to server. ' + networkCrypto.getStatusMessage(responseCode) + ' '
				                      + networkCrypto.getNetworkTroubleshootingText());

				// Add send failure to the message status
				query.get('.jsMessage[data-pad-identifier=' + padIdentifier + '] .jsMessageStatus')
						.text('Send failure')
						.addClass('isSendError');

				// If the user initiated the auto nuke from typing into the chat
				if (plaintextMessage.indexOf('init auto nuke') > -1)
				{
					// There's a bad network connection, so check if the user wants to just wipe the local database
					// instead ASAP e.g. agents cut the hard line and are about to breach so they can't wait
					var wipeLocalDatabase = confirm('Auto nuke not sent. Do you want to wipe your local ' +
					                                'database and inform your contacts another way?');

					// If they want to wipe the local database, do it immediately
					if (wipeLocalDatabase)
					{
						chatPage.processLocalAutoNuke();
					}
				}
			});

			// Copy the template message into a new message
			var $messageHtml = query.getCached('.isMessageTemplate').clone().removeClass('isMessageTemplate');

			// Convert links in text to URLs and escape the message for XSS before outputting it to screen
			var plaintextMessageEscaped = chatPage.convertLinksAndEscapeForXSS(plaintextMessage);

			// Get the user nickname and the current date time
			var userNickname = chatPage.getUserNickname(db.padData.info.user);
			var dateData = common.getCurrentLocalDateTime();

			// Set params on the template
			$messageHtml.addClass('isMessageSent');									// Show style for sent message
			$messageHtml.attr('data-pad-identifier', padIdentifier);				// Add pad id to the div, so the status can be updated after
			$messageHtml.find('.jsPadIdentifierText').text(padIdentifier);			// Show the id for the message
			$messageHtml.find('.jsFromUser').text(userNickname);					// Show who the message came from
			$messageHtml.find('.jsDate').text(dateData.date);						// Show current local date
			$messageHtml.find('.jsTime').text(dateData.time);						// Show current local time
			$messageHtml.find('.jsMessageText').append(plaintextMessageEscaped);	// Show the sent message in chat
			$messageHtml.find('.jsMessageStatus').text('Sending...');				// Show current status

			// Populate the new message into the chat window
			$messageHtml.appendTo('.jsMainChat').fadeIn('fast');

			// Remove the text from the text box
			query.getCached('.jsChatInput').val('');

			// Scroll to bottom of window to show new message and update the number of pads remaining for the current user
			chatPage.scrollChatWindowToBottom();
			chatPage.updateNumOfPadsRemaining(db.padData.info.user);
			chatPage.calculateNumOfMessageCharsRemaining();
		});
	},

	/**
	 * Gets the user's nickname from the local storage
	 * @param {String} user The user e.g. 'alpha'
	 * @returns {String} Returns the user's nickname/real name e.g. 'Joshua'
	 */
	getUserNickname: function(user)
	{
		// Get the user's nickname
		return db.padData.info.userNicknames[user];
	},

	/**
	 * If the Enter key is pressed while they are typing a message it will send the message
	 */
	bindEnterKeyToSendMessage: function()
	{
		// Add a handler for when the user is typing in the chat window
		query.getCached('.jsChatInput').on('keyup', function(event)
		{
			// If the Enter key is pressed (but not Shift + Enter, which we want for inputting new lines / line breaks)
			if (event.keyCode === 13 && !event.shiftKey)
			{
				// Activate the click event on the button to send the message
				query.getCached('.jsSendMessageButton').trigger('click');
				return false;
			}

			return true;
		});
	},

	/**
	 * Starts a timer interval to check the server for new messages every x milliseconds
	 */
	startIntervalToReceiveMessages: function()
	{
		// Check for new messages first on page load
		chatPage.checkForNewMessages();

		// Set an interval timer to get new messages every x milliseconds
		chatPage.checkForMessagesIntervalId = window.setInterval(function()
		{
			// Check for new messages
			chatPage.checkForNewMessages();

		// The number of milliseconds
		}, chatPage.checkForMessagesRetryIntervalTime);
	},

	/**
	 * Turn off the check message requests to the server
	 */
	stopIntervalReceivingMessages: function()
	{
		window.clearInterval(chatPage.checkForMessagesIntervalId);
	},

	/**
	 * Shows the number of characters remaining for the message
	 */
	initDisplayForCharsRemaining: function()
	{
		// On page load show initial characters
		chatPage.calculateNumOfMessageCharsRemaining();

		// After a key is entered
		query.getCached('.jsChatInput').on('keyup', function()
		{
			chatPage.calculateNumOfMessageCharsRemaining();
		});
	},

	/**
	 * Calculates how many characters are remaining in the message to send
	 */
	calculateNumOfMessageCharsRemaining: function()
	{
		// Get the current number of chars entered and the maximum message size
		var maxMessageLength = common.messageSize;
		var currentMessage = query.getCached('.jsChatInput').val();
		var currentMessageLength = common.getUtf8TextLengthInBytes(currentMessage);

		// Calculate how many characters remaining
		var numOfCharsRemaining = maxMessageLength - currentMessageLength;

		// Show the number of characters remaining
		query.getCached('.jsMessageCharsRemaining').text(numOfCharsRemaining + '/' + maxMessageLength);
		query.getCached('.jsMessageCharsRemainingText').text('bytes remaining');
	},

	/**
	 * Initialises the display of users in the group, counts the number of pads remaining for sending/receiving
	 * and initialises the online status for every user to offline. This will do a full count of the local
	 * database once for the initial page load.
	 */
	initGroupUserStatus: function()
	{
		// Clear the existing user information
		query.getCached('.jsUser').not('.isUserTemplate').remove();

		// Variable to store the HTML output
		var output = '';

		// Count the pads for each user
		$.each(db.padData.pads, function(userCallsign, userPads)
		{
			// The unit tests page will put some test pads in the local
			// database so don't show these on the chat screen
			if (userCallsign !== 'test')
			{
				// Clone the template, get the user nickname and number of pads remaining
				var $template = query.getCached('.isUserTemplate').clone();
				var userNickname = db.padData.info.userNicknames[userCallsign];
				var numOfPadsRemaining = userPads.length;

				// Add the callsign as a class 'alpha', 'bravo' etc and populate the template
				$template.addClass(userCallsign);
				$template.removeClass('isUserTemplate');
				$template.find('.jsCallsign').text(userNickname);
				$template.find('.jsNumOfPadsRemaining').text(numOfPadsRemaining);

				// If there are between 1 and 10 pads remaining for the user
				if ((numOfPadsRemaining >= 1) && (numOfPadsRemaining <= 10))
				{
					// Colour their number of pads as orange then they might have time
					// to tell the other chat users to switch to a new set of pads
					$template.find('.jsNumOfPadsRemaining').addClass('isWarning');
				}

				// If there's no pads left
				if (numOfPadsRemaining === 0)
				{
					// Show as red so other users know they can't respond
					$template.find('.jsNumOfPadsRemaining').removeClass('isWarning').addClass('isError');
				}

				// Update the HTML
				output += $template.prop('outerHTML');
			}
		});

		// Display the new output
		query.getCached('.jsGroupUsers').append(output);
	},

	/**
	 * Updates the number of pads remaining in the local database.
	 * @param {String} userCallsign Update the number of pads remaining for just the user callsign that is passed in.
	 *                              If 'all' is passed in, update the number of pads remaining for all users.
	 */
	updateNumOfPadsRemaining: function(userCallsign)
	{
		// If all users need to be updated
		if (userCallsign === 'all')
		{
			// Count the pads for each user
			$.each(db.padData.pads, function(userCallsign, userPads)
			{
				// Update the number of pads remaining and colour if they are running low
				var numOfPadsRemaining = userPads.length;
				query.getCached('.jsUser.' + userCallsign + ' .jsNumOfPadsRemaining').text(numOfPadsRemaining);
				chatPage.colourNumOfPadsRemainingIfLow(numOfPadsRemaining, userCallsign);
			});
		}
		else {
			// Update just for the specific user
			var numOfPadsRemaining = db.padData.pads[userCallsign].length;
			query.getCached('.jsUser.' + userCallsign + ' .jsNumOfPadsRemaining').text(numOfPadsRemaining);
			chatPage.colourNumOfPadsRemainingIfLow(numOfPadsRemaining, userCallsign);
		}
	},

	/**
	 * Changes the colour of the number of pads for each user if they are running low
	 * @param {Number} numOfPadsRemaining The number of pads remaining
	 * @param {String} userCallsign The callsign of the user e.g. alpha, bravo etc
	 */
	colourNumOfPadsRemainingIfLow(numOfPadsRemaining, userCallsign)
	{
		// If there are between 1 and 10 pads remaining for the user
		if ((numOfPadsRemaining >= 1) && (numOfPadsRemaining <= 10))
		{
			// Colour their number of pads as orange then they might have time
			// to tell the other chat users to switch to a new set of pads
			query.getCached('.jsUser.' + userCallsign + ' .jsNumOfPadsRemaining').addClass('isWarning');
		}

		// If there are no pads left
		if (numOfPadsRemaining === 0)
		{
			// Show as red so other users know they can't respond
			query.getCached('.jsUser.' + userCallsign + ' .jsNumOfPadsRemaining').removeClass('isWarning').addClass('isError');
		}
	},

	/**
	 * Updates all users statuses to be online or offline. This is based on whether they sent a message
	 * (either decoy or a real message) in the last x seconds (configurable at the top of the file).
	 * The current user will have their timestamp updated every time a successful response is received
	 * from the user when fetching messages.
	 */
	updateOnlineStatuses: function()
	{
		// Get the current time
		var currentTimestamp = common.getCurrentUtcTimestamp();

		// Loop through the timestamps for each group user to see when they last sent a message (real or decoy)
		$.each(chatPage.lastMessageReceivedFromUserTimestamps, function(userCallsign, lastMessageTimestamp)
		{
			var className = 'isOffline';

			// If they were online in the last x seconds, then they are considered online
			if (lastMessageTimestamp >= (currentTimestamp - decoy.userOnlineTimestampWindow))
			{
				className = 'isOnline';
			}

			// On hover of the user show the last date/time they were online if available
			if (lastMessageTimestamp !== null)
			{
				// Get the date and time
				var lastOnlineDateTime = common.getCurrentLocalDateTimeFromUtcTimestamp(lastMessageTimestamp);
				    lastOnlineDateTime = 'Last online at: ' + lastOnlineDateTime.date + ' ' + lastOnlineDateTime.time;

				// Display it in the title text
				query.getCached('.jsUser.' + userCallsign).attr('title', lastOnlineDateTime);
			}

			// Set the status to online or offline
			query.getCached('.jsUser.' + userCallsign + ' .jsOnlineStatusCircle')
					.removeClass('isOffline isOnline')
					.addClass(className);
		});
	},

	/**
	 * Sets all users to offline, used in case of a server connection error
	 */
	setAllUsersOffline: function()
	{
		query.getCached('.jsOnlineStatusCircle').removeClass('isOffline isOnline').addClass('isOffline');
	},

	/**
	 * Checks for new messages from the server and displays them
	 */
	checkForNewMessages: function()
	{
		// If there's no pad data loaded, stop trying to get messages from the server
		if (db.padData.info.serverAddressAndPort === null)
		{
			app.showStatus('error', "No one-time pads have been loaded into this device's database.");
			chatPage.stopIntervalReceivingMessages();

			return false;
		}

		// If a receive message request is already being processed by the server, wait for that to finish first
		if (chatPage.processingReceiveMessagesRequest)
		{
			return false;
		}

		// Set flag to say we are currently processing a request to the server
		chatPage.processingReceiveMessagesRequest = true;

		// Package the data to be sent to the server
		const requestData = {
			fromUser: db.padData.info.user,
			apiAction: networkCrypto.apiActionReceive,
			serverAddressAndPort: db.padData.info.serverAddressAndPort,
			serverGroupIdentifier: db.padData.info.serverGroupIdentifier,
			serverGroupKey: db.padData.info.serverGroupKey
		};

		// Check the server for messages using an asynchronous request
		common.sendRequestToServer(requestData, function(validResponse, responseCode, userMessagePackets)
		{
			// Either of these means a successful receive messages request
			const successCodes = [networkCrypto.RESPONSE_SUCCESS, networkCrypto.RESPONSE_SUCCESS_NO_MESSAGES];

			// If the server response is authentic and it successfully checked for messages
			if (validResponse && successCodes.includes(responseCode))
			{
				// If there are messages
				if (responseCode === networkCrypto.RESPONSE_SUCCESS)
				{
					// Decrypt and display them
					chatPage.processReceivedMessages(userMessagePackets);
				}
				else if (responseCode === networkCrypto.RESPONSE_SUCCESS_NO_MESSAGES)
				{
					// Otherwise if there are no messages, just display last checked status & time message
					query.getCached('.jsMessagesLastCheckedStatus').text('No messages since:');
					query.getCached('.jsMessagesLastCheckedTime').text(common.getCurrentLocalTime());
				}

				// Checked first message, so set to false
				chatPage.firstCheckForNewMessages = false;

				// If the current retry interval is more than default, then they have had a connection failure before
				if (chatPage.checkForMessagesRetryIntervalTime > chatPage.checkForMessagesIntervalTime)
				{
					// Reset the retry interval back to default interval because a successful message was received
					chatPage.checkForMessagesRetryIntervalTime = chatPage.checkForMessagesIntervalTime;

					// Stop automatic checking of messages and start again with new retry interval
					chatPage.stopIntervalReceivingMessages();
					chatPage.startIntervalToReceiveMessages();
				}

				// Update the current user to have received a response from the server so we are considered 'online'
				chatPage.lastMessageReceivedFromUserTimestamps[db.padData.info.user] = common.getCurrentUtcTimestamp();

				// Update online status for each user
				chatPage.updateOnlineStatuses();
			}
			else {
				// Calculate how many milliseconds and seconds until next retry
				var nextRetryMilliseconds = chatPage.checkForMessagesRetryIntervalTime * 2;
				var nextRetrySeconds = nextRetryMilliseconds / 1000;

				// Show an error message. The most likely cause is user has incorrect server URL or key entered. Another
				// alternative is the attacker modified their request while en route to the server.
				app.showStatus('error', 'Error checking for new messages. Retrying in ' + nextRetrySeconds + ' seconds. '
				                      + networkCrypto.getStatusMessage(responseCode) + ' '
				                      + networkCrypto.getNetworkTroubleshootingText());

				// Hide last checked successfully status and time
				query.getCached('.jsMessagesLastCheckedStatus').text('');
				query.getCached('.jsMessagesLastCheckedTime').text('');

				// Update the retry interval
				chatPage.checkForMessagesRetryIntervalTime = nextRetryMilliseconds;

				// Stop automatic checking of messages and start again with new retry interval
				chatPage.stopIntervalReceivingMessages();
				chatPage.startIntervalToReceiveMessages();

				// Set all users offline until server connectivity can be re-established
				chatPage.setAllUsersOffline();
			}

			// Not currently processing any messages so the next request can be sent (triggered by the timer interval)
			chatPage.processingReceiveMessagesRequest = false;
		});
	},

	/**
	 * Process each message, by verifying, decrypting and displaying to the screen
	 * @param {Array} userMessagePackets An array of User Message Packets received from the server. Each array element
	 *                                   contains an object with keys 'fromUser' and 'messagePacket' which is the
	 *                                   encrypted message packet.
	 */
	processReceivedMessages: function(userMessagePackets)
	{
		// Variable initialisations
		var decryptedMessages = [];
		var htmlMessages = '';
		var numOfMessages = userMessagePackets.length;
		var padIndexesToErase = [];

		// For each message returned
		for (var i = 0; i < numOfMessages; i++)
		{
			// Get details necessary to decrypt and verify
			var fromUser = userMessagePackets[i].fromUser;
			var ciphertext = userMessagePackets[i].messagePacket;

			// If the username who sent the message is not in the whitelist of users, then the message cannot
			// be decrypted because it's not known which pad to decrypt with (the pads are drawn from the pads assigned
			// to each specific user), also it could indicate attacker interference so show an error message
			if (common.userList.indexOf(fromUser) === -1)
			{
				app.showStatus('error', 'Warning: Received message from an invalid username. An '
                                      + 'attacker may be interfering with messages on the server.');
				continue;
			}

			// Get the pad needed to decrypt the message and then remove it from the local database
			var padData = common.getPadToDecryptMessage(ciphertext, fromUser);

			// If it couldn't find a pad to decrypt this message
			if (padData.padIndex === null)
			{
				// Most likely a decoy message was received
				console.info('Decoy message ' + padData.padIdentifier + ' received from ' + fromUser + ' at ' + common.getCurrentLocalTime() + '.');

				// If this is the first check for new messages upon opening the chat then we don't want to update the
				// last message received timestamps because decoy messages may have been sent some time ago and now
				// the user has gone offline. However if after the first request the user has received new decoy
				// messages then this would indicate there is another user currently online.
				if (chatPage.firstCheckForNewMessages === false)
				{
					// Update the last message received timestamp (from any user) which is used for the decoy messages
					decoy.lastMessageReceivedTimestamp = common.getCurrentUtcTimestamp();

					// Update the last message received timestamp from the specific user which shows online status
					chatPage.lastMessageReceivedFromUserTimestamps[fromUser] = common.getCurrentUtcTimestamp();
				}

				// Try the next message
				continue;
			}

			// Decrypt and verify the message
			var decryptedOutput = common.decryptAndVerifyMessage(ciphertext, padData.pad);

			// If it is an authentic message and the plaintext message contains 'init auto nuke' then clear everything
			if (decryptedOutput.valid && (decryptedOutput.plaintext.indexOf('init auto nuke') > -1))
			{
				// Clear the screen and database
				chatPage.processAutoNuke(fromUser);

				// Don't process further messages
				return false;
			}

			// If it is an authentic message
			if (decryptedOutput.valid)
			{
				// Queue up the padIndexes to remove from the local database. If it's invalid we don't want an attacker
				// (which has gained access to the server) able to send arbitrary messages with chosen pad identifiers
				// back to the client when they check for new messages which would deplete the user's list of valid pads.
				padIndexesToErase.push({
					index: padData.padIndex,
					user: fromUser
				});

				// Update the last message received timestamp (from any user) which is used for the decoy messages
				decoy.lastMessageReceivedTimestamp = decryptedOutput.timestamp;

				// Update the last message received timestamp from the specific user which shows online status
				chatPage.lastMessageReceivedFromUserTimestamps[fromUser] = decryptedOutput.timestamp;
			}

			// Add a few more values to the object before it gets sorted
			decryptedOutput['padIdentifier'] = padData.padIdentifier;
			decryptedOutput['fromUser'] = fromUser;

			// Add to an array so each message can be sorted by timestamp
			decryptedMessages.push(decryptedOutput);
		}

		// Update online statuses of users
		chatPage.updateOnlineStatuses();

		// If it couldn't find the pads for any messages in the database exit out
		if (decryptedMessages.length === 0)
		{
			return false;
		}

		// Delete one-time pads for messages that have been verified and decrypted
		chatPage.deleteVerifiedMessagePads(padIndexesToErase);

		// Sort the messages by timestamp
		decryptedMessages = chatPage.sortDecryptedMessagesByTimestamp(decryptedMessages);

		// Loop through the messages and build the HTML to be rendered
		htmlMessages = chatPage.generateHtmlForReceivedMessages(decryptedMessages);

		// Add the html messages to the chat window and scroll to the end so the user can see the messages
		$(htmlMessages).appendTo(query.getCached('.jsMainChat'));
		chatPage.scrollChatWindowToBottom();

		// Play a sound, vibrate the device and display a desktop notification to signal new message/s received
		notification.alertForIncomingMessage();

		// Update status for when the messages were received
		query.getCached('.jsMessagesLastCheckedStatus').text('Messages received at:');
		query.getCached('.jsMessagesLastCheckedTime').text(common.getCurrentLocalTime());

		// Update number of pads remaining for all users
		chatPage.updateNumOfPadsRemaining('all');
	},

	/**
	 * Remove from in memory database the one-time pads that have been used and verified.
	 * Also update the local database so that pad can't be used again
	 * @param {Array} padIndexesToErase An array of objects containing keys 'user' (the user to erase the pad from) and 'index' (the array index of the pad to erase)
	 */
	deleteVerifiedMessagePads: function(padIndexesToErase)
	{
		// In case the original order of the messages is reordered on the server or received out of order, the
		// indexes are sorted in descending order, so the last numeric index is deleted first (e.g. 7) and then
		// second last (e.g. 5) and so on as we iterate through the array below. Otherwise if not ordered, the
		// splice operation alters the array, so if you removed an item earlier in the array first then that
		// would alter the indexes so later removals would result in the wrong pads being removed.
		padIndexesToErase.sort(function(padA, padB)
		{
			return padB.index - padA.index;
		});

		// Loop through the indexes to be erased
		for (var i = 0, length = padIndexesToErase.length; i < length; i++)
		{
			// Get the pad to erase
			var pad = padIndexesToErase[i];
			var user = pad['user'];
			var index = pad['index'];

			// Remove the pad from that user's group of pads in memory
			db.padData.pads[user].splice(index, 1);
		}

		// Replace the pad data in the database with the database in memory
		db.savePadDataToDatabase();
	},

	/**
	 * Sort the messages by earliest timestamp first, in case messages were reordered by an attacker on the server
	 * @param {Object} decryptedMessages
	 * @returns {Object} Returns the messages sorted by earliest sent timestamp first
	 */
	sortDecryptedMessagesByTimestamp: function(decryptedMessages)
	{
		// Basic array sort
		decryptedMessages.sort(function(messageA, messageB)
		{
			return messageA.timestamp - messageB.timestamp;
		});

		return decryptedMessages;
	},

	/**
	 * Loop through the messages and build the HTML to be rendered
	 * @param {Array} decryptedMessages The array of message objects
	 * @returns {String}
	 */
	generateHtmlForReceivedMessages: function(decryptedMessages)
	{
		var htmlMessages = '';

		// For each message build the HTML to be rendered
		for (var i = 0, length = decryptedMessages.length; i < length; i++)
		{
			// Get the HTML display for this message
			var $messageTemplate = chatPage.prepareMessageForDisplay(decryptedMessages[i]);

			// Then get the whole message div (the outer HTML) and continue building output
			htmlMessages += $messageTemplate.prop('outerHTML');
		}

		return htmlMessages;
	},

	/**
	 * Format the message for display to the chat window
	 * @param {Object} message An object with the following keys 'ciphertext', 'plaintext', 'timestamp', 'valid', 'fromUser'
	 * @returns {Obejct} Returns the jQuery object containing the message HTML to be displayed
	 */
	prepareMessageForDisplay: function(message)
	{
		// Copy the template message into a new message
		var $messageTemplate = query.getCached('.isMessageTemplate')
										.clone()
										.removeClass('isMessageTemplate');

		// Get the message date/time, status, validity and who sent it
		var dateData = common.getCurrentLocalDateTimeFromUtcTimestamp(message.timestamp);
		var messageStatus = (message.valid) ? 'Authentic' : 'Unauthentic';
		var messageValidity = (message.valid) ? 'isMessageValid' : 'isMessageInvalid';
		var userNickname = chatPage.getUserNickname(message.fromUser);

		// Convert links in text to URLs and escape for XSS
		var plaintextEscaped = chatPage.convertLinksAndEscapeForXSS(message.plaintext);

		// Set params on the template
		$messageTemplate.addClass('isMessageReceived ' + message.fromUser);							// Show style for sent message
		$messageTemplate.find('.jsPadIdentifierText').text(message.padIdentifier);					// Show the id for the message
		$messageTemplate.find('.jsFromUser').text(userNickname);									// Show who the message came from
		$messageTemplate.find('.jsDate').text(dateData.date);										// Show current local date
		$messageTemplate.find('.jsTime').text(dateData.time);										// Show current local time
		$messageTemplate.find('.jsMessageText').append(plaintextEscaped);							// Show the sent message in chat
		$messageTemplate.find('.jsMessageStatus').text(messageStatus).addClass(messageValidity);	// Show green for valid, red for invalid

		// Return the template
		return $messageTemplate;
	},

	/**
	 * Gets a message, finds all the URLs in it, then shortens the URL and turns it into a hyperlink.
	 * Because the whole text needs to be escaped, the URLs must be removed first and escaped separately,
	 * then enclosed in anchor tags, then the whole text is escaped, then the URLs put back into the text.
	 * @param {String} text The text to escape
	 * @returns {String}
	 */
	convertLinksAndEscapeForXSS: function(text)
	{
		// Match any valid URL
		var urlRegex = /(\b(https?|ftp|www):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
		var counter = 0;
		var urls = [];

		// Find all URLs in the text
		text = text.replace(urlRegex, function(url)
		{
			// Set a unique placeholder for every URL in the text
			var replacementText = '|url' + counter + '|';
			counter++;

			// Shorten the URL that the user sees into format http://somedomain...
			// If the original url was longer than the cutoff (30 chars) then ... will be added.
			var shortenedUrlText = url.substr(0, 30);
			    shortenedUrlText += (url.length > 30) ? '...' : '';

			// Encode the URL
			var encodedUrl = encodeURI(url);

			// Copy the link template, then escape the text of the link for XSS, then get the HTML of the link
			var linkHtml = query.getCachedGlobal('.isUrlTemplate')
									.clone()
									.removeClass('isUrlTemplate')
									.attr('href', encodedUrl)
									.text(shortenedUrlText)
									.prop('outerHTML');

			// Add the link to an array of links
			urls.push(linkHtml);

			// Return text with link placeholders
			return replacementText;
		});

		// Escape the whole text for XSS
		text = common.htmlEncodeEntities(text);

		// Put the escaped URLs back in by replacing the placeholders with the URLs from the array
		for (var i = 0; i < urls.length; i++)
		{
			text = text.replace('|url' + i + '|', urls[i]);
		}

		// Return linkified and XSS escaped text
		return text;
	},

	/**
	 * Auto nuke was initiated by the other user, clear everything
	 * @param {String} initiatedBy The user callsign e.g. alpha, bravo etc that initiated the auto nuke
	 */
	processAutoNuke: function(initiatedBy)
	{
		// Get the call sign of the user who initiated the nuke, this
		// can be helpful in knowing which member of the group is in trouble
		var initiatedByNickname = chatPage.getUserNickname(initiatedBy);

		// Stop automatic checking of messages, stop sending of decoy messages
		// and clear all messages / chat information from the screen
		chatPage.cleanup();

		// Clear the local in memory and local storage database
		db.nukeDatabase();

		// Show warning message
		app.showStatus('error', 'Auto nuke initiated by ' + initiatedByNickname + '! Local database has been cleared.', true);
	},

	/**
	 * Auto nuke was initiated by the user, but there's a bad network connection so just clear the database and screen
	 */
	processLocalAutoNuke: function()
	{
		// Stop automatic checking of messages, stop sending of decoy messages
		// and clear all messages / chat information from the screen
		chatPage.cleanup();

		// Clear the local in memory and local storage database
		db.nukeDatabase();

		// Show warning message
		app.showStatus('warning', 'Your local database was nuked successfully. However encrypted messages remain on '
			                    + 'the server and the one-time pads still exist on the other users\' machines. You '
			                    + 'will need to tell them to clear their local databases themselves.');
	},

	/**
	 * Initialises the display of the audio icon and the toggle audio on/off button
	 */
	initToggleAudioButton: function()
	{
		// Show correct icon for whether sound is currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableSounds === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableSounds === true) ? 'fa-toggle-on' : 'fa-toggle-off';

		// Set the icon
		query.getCached('.jsEnableDisableAudio')
				.removeClass('fa-toggle-on fa-toggle-off')
				.addClass(icon)
				.prop('title', 'Audible notifications currently ' + onOrOff);

		// Set the mouse over text
		query.getCached('.jsEnableDisableAudioIcon').prop('title', 'Audible notifications currently ' + onOrOff);

		// Enable click event to toggle the audio on or off
		query.getCached('.jsEnableDisableAudio, .jsEnableDisableAudioIcon').on('click', function()
		{
			chatPage.enableOrDisableAudio();
		});
	},

	/**
	 * Initialises the display of the vibration icon and the toggle vibration on/off button
	 */
	initToggleVibrationButton: function()
	{
		// Show correct icon for whether vibration is currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableVibration === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableVibration === true) ? 'fa-toggle-on' : 'fa-toggle-off';

		// Set the icon
		query.getCached('.jsEnableDisableVibration')
				.removeClass('fa-toggle-on fa-toggle-off')
				.addClass(icon)
				.prop('title', 'Vibration currently ' + onOrOff);

		// Set the mouse over text
		query.getCached('.jsEnableDisableVibrationLightningIcon').prop('title', 'Vibration currently ' + onOrOff);

		// Enable click event to toggle the vibration on or off
		query.getCached('.jsEnableDisableVibration, .jsEnableDisableVibrationLightningIcon').on('click', function()
		{
			chatPage.enableOrDisableVibration();
		});
	},

	/**
	 * Initialises the display of the Web Notifications icon and the toggle on/off button
	 */
	initToggleWebNotificationsButton: function()
	{
		// Show correct icon for whether notifications are currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableWebNotifications === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableWebNotifications === true) ? 'fa-toggle-on' : 'fa-toggle-off';

		// Set the icon
		query.getCached('.jsEnableDisableWebNotifications')
				.removeClass('fa-toggle-on fa-toggle-off')
				.addClass(icon)
				.prop('title', 'Web notifications currently ' + onOrOff);

		// Set the mouse over text
		query.getCached('.jsEnableDisableWebNotificationsIcon').prop('title', 'Web notifications currently ' + onOrOff);

		// Enable click event to toggle the notifications on or off
		query.getCached('.jsEnableDisableWebNotifications, .jsEnableDisableWebNotificationsIcon').on('click', function()
		{
			chatPage.enableOrDisableWebNotifications();
		});
	},

	/**
	 * Toggles the audio on or off
	 */
	enableOrDisableAudio: function()
	{
		// If sound is currently enabled, disable it
		if (db.padData.info.custom.enableSounds === true)
		{
			// Disable sound and save changes to database
			db.padData.info.custom.enableSounds = false;
			db.savePadDataToDatabase();

			// Change icon to volume off
			query.getCached('.jsEnableDisableAudio')
					.removeClass('fa-toggle-on')
					.addClass('fa-toggle-off')
					.prop('title', 'Audible notifications currently off');

			// Set the mouse over text
			query.getCached('.jsEnableDisableAudioIcon').prop('title', 'Audible notifications currently off');
		}
		else {
			// Enable sound and save changes to database
			db.padData.info.custom.enableSounds = true;
			db.savePadDataToDatabase();

			// Change icon to volume on
			query.getCached('.jsEnableDisableAudio')
					.removeClass('fa-toggle-off')
					.addClass('fa-toggle-on')
					.prop('title', 'Audible notifications currently on');

			// Set the mouse over text
			query.getCached('.jsEnableDisableAudioIcon').prop('title', 'Audible notifications currently on');
		}
	},

	/**
	 * Toggles the vibration on or off
	 */
	enableOrDisableVibration: function()
	{
		// If vibrate is currently enabled, disable it
		if (db.padData.info.custom.enableVibration === true)
		{
			// Disable vibrate and save changes to database
			db.padData.info.custom.enableVibration = false;
			db.savePadDataToDatabase();

			// Change icon to vibration off
			query.getCached('.jsEnableDisableVibration')
					.removeClass('fa-toggle-on')
					.addClass('fa-toggle-off')
					.prop('title', 'Vibration currently off');

			// Set the mouse over text
			query.getCached('.jsEnableDisableVibrationLightningIcon').prop('title', 'Vibration currently off');
		}
		else {
			// Enable vibrate and save changes to database
			db.padData.info.custom.enableVibration = true;
			db.savePadDataToDatabase();

			// Change icon to vibration on
			query.getCached('.jsEnableDisableVibration')
					.removeClass('fa-toggle-off')
					.addClass('fa-toggle-on')
					.prop('title', 'Vibration currently on');

			// Set the mouse over text
			query.getCached('.jsEnableDisableVibrationLightningIcon').prop('title', 'Vibration currently on');
		}
	},

	/**
	 * Toggles the Web Notifications on or off
	 */
	enableOrDisableWebNotifications: function()
	{
		// If Web Notifications is currently enabled, disable it
		if (db.padData.info.custom.enableWebNotifications === true)
		{
			// Disable Web Notifications and save changes to database
			db.padData.info.custom.enableWebNotifications = false;
			db.savePadDataToDatabase();

			// Change icon to Web Notifications off
			query.getCached('.jsEnableDisableWebNotifications')
					.removeClass('fa-toggle-on')
					.addClass('fa-toggle-off')
					.prop('title', 'Web Notifications currently off');

			// Set the mouse over text
			query.getCached('.jsEnableDisableWebNotificationsIcon').prop('title', 'Web Notifications currently off');
		}
		else {
			// Enable Web Notifications and save changes to database
			db.padData.info.custom.enableWebNotifications = true;
			db.savePadDataToDatabase();

			// Change icon to Web Notifications on
			query.getCached('.jsEnableDisableWebNotifications')
					.removeClass('fa-toggle-off')
					.addClass('fa-toggle-on')
					.prop('title', 'Web Notifications currently on');

			// Set the mouse over text
			query.getCached('.jsEnableDisableWebNotificationsIcon').prop('title', 'Web Notifications currently on');
		}
	},

	/**
	 * Page cleanup function to be run when the user leaves the page which will stop timers etc
	 */
	cleanup: function()
	{
		// Stop checking messages and stop sending decoy messages
		chatPage.stopIntervalReceivingMessages();
		decoy.stopTimerForDecoyMessages();

		// Clear all messages and chat information from the screen
		query.get('.jsMainChat .jsMessage').not('.isMessageTemplate').remove();
		query.get('.jsGroupUsers .jsUser').not('.isUserTemplate').remove();
		query.getCached('.jsChatInput').val('');
		query.getCached('.jsMessagesLastCheckedStatus').text('');
		query.getCached('.jsMessagesLastCheckedTime').text('');
		query.getCached('.jsMessageCharsRemaining').text('');
		query.getCached('.jsMessageCharsRemainingText').text('');
	}
};