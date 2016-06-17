/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2016  Joshua M. David
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
var chat = {
	
	// The interval id for checking new messages, and how often to check for new messages in milliseconds
	checkForMessagesIntervalId: null,
	checkForMessagesIntervalTime: 3000,		// 3 seconds
	
	// This is used as exponential backoff functionality. If a connection to the API fails, it will retry after this 
	// many milliseconds. If it fails after that it will double the current time and then re-try after this time. 
	checkForMessagesRetryIntervalTime: 3000,
		
	// Whether this is the first check for new messages or not
	firstCheckForNewMessages: true,
	
	// Flag for whether or not a request is currently being processed for receiving messages. This is used to 
	// prevent multiple requests being sent to the server from the same client so it waits for a response first.
	processingReceiveMessagesRequest: false,
		
	// When a message was last received from the user
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
	 * Make the chat window always scroll to the bottom if there are lots of messages on page load
	 */
	scrollChatWindowToBottom: function()
	{
		$('.mainChat').each(function() 
		{
			var scrollHeight = Math.max(this.scrollHeight, this.clientHeight);
			
			this.scrollTop = scrollHeight - this.clientHeight;
		});
	},
		
	/**
	 * Initialises the send message button, which when clicked will encrypt and send the message to the server
	 */
	initialiseSendMessageButton: function()
	{
		// If the send message function is clicked
		$('#btnSendMessage').click(function(event)
		{
			// Get plaintext message and remove invalid non ASCII characters from message
			var plaintextMessage = $('#newChatMessage').val();
			plaintextMessage = common.removeInvalidChars(plaintextMessage);
						
			// Make sure they've entered in some data
			if (plaintextMessage === '')
			{
				common.showStatus('error', 'Message empty, non ASCII printable characters are not supported and removed.');
				return false;
			}
			
			// Get the next pad from the local database and use it to encrypt the message
			var pad = common.getPadToEncryptMessage();
			if (pad === false)
			{
				// There's no pads available to encrypt the message so don't let them send it
				common.showStatus('error', 'No available pads. Please generate more pads and exchange them with your chat partner.');
				return false;
			}

			// Encrypt the message and create the MAC
			var ciphertextMessageAndMac = common.encryptAndAuthenticateMessage(plaintextMessage, pad);					
			var padIdentifier = common.getPadIdentifierFromCiphertext(ciphertextMessageAndMac);

			// Get the server address and key
			var serverAddressAndPort = db.padData.info.serverAddressAndPort;
			var serverKey = db.padData.info.serverKey;
			
			// Package the data to be sent to the server
			var data = {
				'user': db.padData.info.user,
				'apiAction': 'sendMessage',
				'msg': ciphertextMessageAndMac
			};
			
			// Send the message off to the server
			common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseData)
			{
				// If the server response is authentic
				if (validResponse)
				{
					// Get message and protect against XSS
					var statusMessage = common.htmlEncodeEntities(responseData.statusMessage);
					
					// If it saved to the database
					if (responseData.success)
					{
						// Find the message in the chat window with that identifier and update the status to 'Sent'
						$('.messageStatus[data-pad-identifier=' + padIdentifier + ']').html(statusMessage).addClass('sendSuccess');
						return true;
					}
					else {
						// Otherwise show error from the server
						common.showStatus('error', statusMessage);
					}
				}
				
				// If response check failed it means there was probably interference from attacker altering data or MAC
				else if (validResponse === false)
				{
					common.showStatus('error', 'Unauthentic response from server detected.');
				}
				
				else {
					// Most likely cause is user has incorrect server url or key entered.
					// Another alternative is the attacker modified their request while en route to the server
					common.showStatus('error', 'Error sending message to server. Check: 1) you are connected to the network, 2) the client/server configurations are correct, and 3) client/server system clocks are up to date. If everything is correct, the data may have been tampered with by an attacker.');
				}
				
				// Add send failure to the message status
				$('.messageStatus[data-pad-identifier=' + padIdentifier + ']').html('Send failure').addClass('sendError');
			});
			
			// Copy the template message into a new message
			var messageHtml = $('.templateMessage').clone().removeClass('templateMessage');
			
			// Convert links in text to URLs and escape the message for XSS before outputting it to screen
			var plaintextMessageEscaped = chat.convertLinksAndEscapeForXSS(plaintextMessage);
			
			// Get the user nickname and the current date time
			var userNickname = chat.getUserNickname(db.padData.info.user);
			var dateData = common.getCurrentLocalDateTime();
			
			// Set params on the template
			messageHtml.addClass('message messageSent');											// Show style for sent message
			messageHtml.find('.padIdentifierText').html(padIdentifier);								// Show the id for the message
			messageHtml.find('.fromUser').html(userNickname);										// Show who the message came from
			messageHtml.find('.date').html(dateData.date);											// Show current local date
			messageHtml.find('.time').html(dateData.time);											// Show current local time
			messageHtml.find('.messageText').html(plaintextMessageEscaped);							// Show the sent message in chat
			messageHtml.find('.messageText').attr('title', 'Pad identifier: ' + padIdentifier);		// Show pad id on mouse hover
			messageHtml.find('.messageStatus').html('Sending...');									// Show current status
			messageHtml.find('.messageStatus').attr('data-pad-identifier', padIdentifier);			// Attach identifier to the div, so the status can be updated after

			// Populate the new message into the chat window
			messageHtml.appendTo('.mainChat').fadeIn('fast');

			// Remove the text from the text box and scroll to bottom of window to show new message
			$('#newChatMessage').val('');
			chat.scrollChatWindowToBottom();
			event.preventDefault();
			
			// Update the number of pads remaining for the current user
			chat.updateNumOfPadsRemaining(db.padData.info.user);
		});
	},
	
	/**
	 * Gets the user's nickname from the local storage
	 * @param {String} user The user e.g. 'alpha'
	 * @returns {String} Returns the user's nickname/real name e.g. 'Joshua'
	 */
	getUserNickname: function(user)
	{
		// Get the user's nickname and escape it for XSS
		var userNickname = db.padData.info.userNicknames[user];
		    userNickname = common.htmlEncodeEntities(userNickname);
			
		return userNickname;
	},
	
	/**
	 * If the Enter key is pressed while they are typing a message it will send the message
	 */
	bindEnterKeyToSendMessage: function()
	{
		// If they are working in the chat window, detect any keypresses
		$('.chatEntry').bind('keypress', function(e)
		{
			// If the Enter key is pressed
			if (e.keyCode === 13)
			{
				// Activate the click event on the button
				$(this).find('#btnSendMessage').click();
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
		chat.checkForNewMessages();

		// Set an interval timer to get new messages every x milliseconds
		chat.checkForMessagesIntervalId = window.setInterval(function()
		{
			// Check for new messages
			chat.checkForNewMessages();

		// The number of milliseconds
		}, chat.checkForMessagesRetryIntervalTime);
	},
	
	/**
	 * Turn off the check message requests to the server
	 */
	stopIntervalReceivingMessages: function()
	{
		window.clearInterval(chat.checkForMessagesIntervalId);
	},
	
	/**
	 * Shows the number of characters remaining for the message
	 */
	initialiseDisplayForCharsRemaining: function()
	{
		// On page load show initial characters
		chat.calculateNumOfMessageCharactersRemaining();
		
		// Set max length on the text field
		var $messageInput = $('#newChatMessage');
		    $messageInput.attr('maxlength', common.messageSize);
		
		// After a key is entered
		$messageInput.keyup(function()
		{
			chat.calculateNumOfMessageCharactersRemaining();
		});
	},
	
	/**
	 * Calculates how many characters are remaining in the message to send
	 */
	calculateNumOfMessageCharactersRemaining: function()
	{
		// Get the current number of chars entered and the maximum message size
		var max = common.messageSize;
		var length = $('#newChatMessage').val().length;		
			
		// Calculate how many characters remaining
		var charsRemaining = max - length;
		$('.messageCharactersRemaining').html('<b>' + charsRemaining + '/' + max + '</b> characters remaining');
	},
	
	/**
	 * Initialises the display of users in the group, counts the number of pads remaining for sending/receiving 
	 * and initialises the online status for every user to offline. This will do a full count of the local 
	 * database once for the initial page load.
	 */
	initGroupUserStatus: function()
	{
		var output = '';
		var $groupUsers = $('.groupUsers');
		
		// Count the pads for each user
		$.each(db.padData.pads, function(userCallsign, userPads)
		{
			// The unit tests page will put some test pads in the local 
			// database so don't show these on the chat screen
			if (userCallsign !== 'test')
			{			
				// Clone the template, get the user nickname and number of pads remaining
				var $template = $groupUsers.find('.userTemplate').clone();
				var userNickname = db.padData.info.userNicknames[userCallsign];
				var numOfPadsRemaining = userPads.length;
				
				// Add the callsign as a class 'alpha', 'bravo' etc and populate the template
				$template.addClass(userCallsign);
				$template.removeClass('userTemplate');
				$template.find('.callsign').text(userNickname);
				$template.find('.numOfPadsRemaining').text(numOfPadsRemaining);
				
				// Update the HTML
				output += common.getOuterHtml($template);
			}
		});
		
		// Display the output
		$groupUsers.append(output);
	},
	
	/**
	 * Updates the number of pads remaining in the local database.
	 * @param {String} userCallsign Update the number of pads remaining for just the user callsign that is passed in.
	 *                              If 'all' is passed in, update the number of pads remaining for all users.
	 */
	updateNumOfPadsRemaining: function(userCallsign)
	{
		// Cache lookup
		var $groupUsers = $('.chatPage .groupUsers');
		
		// If all users
		if (userCallsign === 'all')
		{
			// Count the pads for each user
			$.each(db.padData.pads, function(user, userPads)
			{
				var numOfPadsRemaining = userPads.length;
				$groupUsers.find('.user.' + user + ' .numOfPadsRemaining').text(numOfPadsRemaining);
			});
		}
		else {
			// Update just for the specific user
			var padsRemaining = db.padData.pads[userCallsign].length;
			$groupUsers.find('.user.' + userCallsign + ' .numOfPadsRemaining').text(padsRemaining);
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
		// Cache lookup
		var $groupUsers = $('.chatPage .groupUsers');
		var currentTimestamp = common.getCurrentUtcTimestamp();

		// Loop through the timestamps for each group user to see when they last sent a message (real or decoy)
		$.each(chat.lastMessageReceivedFromUserTimestamps, function(userCallsign, lastMessageTimestamp)
		{
			var className = 'offline';
			
			// If they were online in the last x seconds, then they are considered online
			if (lastMessageTimestamp >= (currentTimestamp - decoy.userOnlineTimestampWindow))
			{
				className = 'online';
			}
			
			// On hover of the user show the last date/time they were online if available
			if (lastMessageTimestamp !== null)
			{
				// Get the date and time
				var lastOnlineDateTime = common.getCurrentLocalDateTimeFromUtcTimestamp(lastMessageTimestamp);
				    lastOnlineDateTime = 'Last online at: ' + lastOnlineDateTime.date + ' ' + lastOnlineDateTime.time;
				
				// Display it in the title text
				$groupUsers.find('.user.' + userCallsign).attr('title', lastOnlineDateTime);
			}
			
			// Set the status to online or offline
			$groupUsers.find('.user.' + userCallsign + ' .onlineStatusCircle').removeClass('offline online');
			$groupUsers.find('.user.' + userCallsign + ' .onlineStatusCircle').addClass(className);
		});
	},
	
	/**
	 * Sets all users to offline, used in case of a server connection error
	 */
	setAllUsersOffline: function()
	{
		$('.chatPage .groupUsers .onlineStatusCircle').removeClass('offline online').addClass('offline');
	},
	
	/**
	 * Checks for new messages from the server and displays them
	 */
	checkForNewMessages: function()
	{
		// If there's no pad data loaded, stop trying to get messages from the server
		if (db.padData.info.serverAddressAndPort === null)
		{
			common.showStatus('error', "No one-time pads have been loaded into this device's database.");
			chat.stopIntervalReceivingMessages();
			
			return false;
		}
		
		// If a receive message request is already being processed by the server, wait for that to finish first
		if (chat.processingReceiveMessagesRequest)
		{
			return false;
		}
		
		// Get the server address and key
		var serverAddressAndPort = db.padData.info.serverAddressAndPort;
		var serverKey = db.padData.info.serverKey;

		// Package the data to be sent to the server
		var data = {
			user: db.padData.info.user,
			apiAction: 'receiveMessages'
		};
		
		// Currently processing a request to the server
		chat.processingReceiveMessagesRequest = true;

		// Check the server for messages using an asynchronous request
		common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseData)
		{
			// If the server response is authentic
			if (validResponse)
			{
				// Get message back from server, and protect against XSS
				var status = responseData.success;
				var statusMessage = common.htmlEncodeEntities(responseData.statusMessage);
								
				// If there are messages
				if (status)
				{
					// Decrypt and display them
					chat.processReceivedMessages(responseData.messages);
				}
				
				// If some other error occurred
				else if ((status === false) && (responseData.statusMessage !== 'No messages in database.'))
				{
					// Otherwise show error from the server and update status
					common.showStatus('error', statusMessage);
					$('.messagesLastCheckedStatus').html('');
					
					// Stop automatic checking of messages
					chat.stopIntervalReceivingMessages();
				}
				
				else {
					// Otherwise if there are no messages, just display last checked status message
					$('.messagesLastCheckedStatus').html('No messages since: <b>' + common.getCurrentLocalTime() + '</b>');
				}
								
				// Checked first message, so set to false
				chat.firstCheckForNewMessages = false;
				
				// If the current retry interval is more than default, then they have had a connection failure before
				if (chat.checkForMessagesRetryIntervalTime > chat.checkForMessagesIntervalTime)
				{
					// Reset the retry interval back to default interval because a successful message was received
					chat.checkForMessagesRetryIntervalTime = chat.checkForMessagesIntervalTime;
					
					// Stop automatic checking of messages and start again with new retry interval
					chat.stopIntervalReceivingMessages();
					chat.startIntervalToReceiveMessages();
				}
				
				// Update the current user to have received a response from the server so we are considered 'online'
				chat.lastMessageReceivedFromUserTimestamps[db.padData.info.user] = common.getCurrentUtcTimestamp();
				
				// Update online status for each user
				chat.updateOnlineStatuses();
			}			
			else {
				// Calculate how many milliseconds and seconds until next retry
				var nextRetryMilliseconds = chat.checkForMessagesRetryIntervalTime * 2;
				var nextRetrySeconds = nextRetryMilliseconds / 1000;
				var statusMessage = '';
				
				// If response check failed it means there was probably interference from attacker altering data or MAC
				if (validResponse === false)
				{
					statusMessage = 'Unauthentic response from server detected. Retrying in ' + nextRetrySeconds + ' seconds.';
				}
				else {
					// Otherwise the most likely cause is user has incorrect server URL or key entered. Another 
					// alternative is the attacker modified their request while en route to the server
					statusMessage = 'Error contacting server. Retrying in ' + nextRetrySeconds + ' seconds. Check: ' +
				                    '1) you are connected to the network, ' +
					                '2) the client/server configurations are correct, and ' + 
					                '3) client/server system clocks are up to date. If everything is correct, ' +
					                'the data may have been tampered with by an attacker.';
				}
				
				// Show status message
				common.showStatus('error', statusMessage);
				
				// Update the retry interval
				chat.checkForMessagesRetryIntervalTime = nextRetryMilliseconds;
				
				// Stop automatic checking of messages and start again with new retry interval
				chat.stopIntervalReceivingMessages();
				chat.startIntervalToReceiveMessages();
				
				// Set all users offline until server connectivity can be re-established
				chat.setAllUsersOffline();
			}
			
			// Not currently processing any messages so the next request can be sent (triggered by the timer interval)
			chat.processingReceiveMessagesRequest = false;
		});
	},
		
	/**
	 * Process each message, by verifying, decrypting and displaying to the screen
	 * @param {Array} messages An array of messages received from the server
	 */
	processReceivedMessages: function(messages)
	{		
		var decryptedMessages = [];
		var htmlMessages = '';
		var numOfMessages = messages.length;
		var padIndexesToErase = [];
					
		// For each message returned
		for (var i = 0; i < numOfMessages; i++)
		{
			// Get details necessary to decrypt and verify
			var fromUser = messages[i].from;
			var ciphertext = messages[i].msg;			
			
			// If the username who sent the message is not in the whitelist of users, then the message cannot 
			// be decrypted because it's not known which pad to decrypt with (the pads are drawn from the pads assigned 
			// to each specific user), also it could indicate attacker interference so show an error message
			if (common.userList.indexOf(fromUser) === -1)
			{
				common.showStatus('error', "Warning: Received message from invalid username '" + fromUser + "'. An attacker may be interfering with messages on the server.");
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
				if (chat.firstCheckForNewMessages === false)
				{
					// Update the last message received timestamp (from any user) which is used for the decoy messages
					decoy.lastMessageReceivedTimestamp = common.getCurrentUtcTimestamp();
					
					// Update the last message received timestamp from the specific user which shows online status
					chat.lastMessageReceivedFromUserTimestamps[fromUser] = common.getCurrentUtcTimestamp();
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
				chat.processAutoNuke(fromUser);
				
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
				chat.lastMessageReceivedFromUserTimestamps[fromUser] = decryptedOutput.timestamp;
			}
			
			// Add a few more values to the object before it gets sorted
			decryptedOutput['padIdentifier'] = padData.padIdentifier;
			decryptedOutput['fromUser'] = fromUser;
			
			// Add to an array so each message can be sorted by timestamp
			decryptedMessages.push(decryptedOutput);
		}
		
		// Update online statuses of users
		chat.updateOnlineStatuses();
		
		// If it couldn't find the pads for any messages in the database exit out
		if (decryptedMessages.length === 0)
		{
			return false;
		}
		
		// Delete one-time pads for messages that have been verified and decrypted
		chat.deleteVerifiedMessagePads(padIndexesToErase);
		
		// Sort the messages by timestamp
		decryptedMessages = chat.sortDecryptedMessagesByTimestamp(decryptedMessages);
		
		// Loop through the messages and build the HTML to be rendered
		htmlMessages = chat.generateHtmlForReceivedMessages(decryptedMessages);
		
		// Add the html messages to the chat window and scroll to the end so the user can see the messages
		$(htmlMessages).appendTo('.mainChat');
		chat.scrollChatWindowToBottom();
		
		// Play a sound, vibrate the device and display a desktop notification to signal new message/s received
		notification.alertForIncomingMessage();

		// Update status and number of pads remaining for all users
		$('.messagesLastCheckedStatus').html('Messages received at: <b>' + common.getCurrentLocalTime() + '</b>');
		chat.updateNumOfPadsRemaining('all');
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
			var html = chat.prepareMessageForDisplay(decryptedMessages[i]);

			// Then get the whole message div (the outer HTML) and continue building output
			htmlMessages += common.getOuterHtml(html);
		}
		
		return htmlMessages;
	},
	
	/**
	 * Format the message for display to the chat window
	 * @param {Object} message An object with the following keys 'ciphertext', 'plaintext', 'timestamp', 'valid', 'fromUser'
	 * @return {String} The HTML to be displayed
	 */
	prepareMessageForDisplay: function(message)
	{
		// Copy the template message into a new message
		var messageHtml = $('.templateMessage').clone().removeClass('templateMessage');
		var dateData = common.getCurrentLocalDateTimeFromUtcTimestamp(message.timestamp);
		var messageStatus = (message.valid) ? 'Authentic' : 'Unauthentic';
		var messageValidity = (message.valid) ? 'messageValid' : 'messageInvalid';
		var userNickname = chat.getUserNickname(message.fromUser);
		
		// Convert links in text to URLs and escape for XSS
		var plaintextEscaped = chat.convertLinksAndEscapeForXSS(message.plaintext);	
		var padIdentifierEscaped = common.htmlEncodeEntities(message.padIdentifier);
									
		// Set params on the template
		messageHtml.addClass('message messageReceived ' + message.fromUser);		// Show style for sent message
		messageHtml.find('.padIdentifierText').html(padIdentifierEscaped);			// Show the id for the message
		messageHtml.find('.fromUser').html(userNickname);							// Show who the message came from
		messageHtml.find('.date').html(dateData.date);								// Show current local date
		messageHtml.find('.time').html(dateData.time);								// Show current local time
		messageHtml.find('.messageText').html(plaintextEscaped);					// Show the sent message in chat
		messageHtml.find('.messageStatus').html(messageStatus);						// Show current status
		messageHtml.find('.messageStatus').addClass(messageValidity);				// Show green for valid, red for invalid
		
		// Return the template
		return messageHtml;
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
			var replacementText = '|' + counter + '|';
			counter++;
			
			// Shorten the URL that the user sees into format http://somedomain...
			// If the original url was longer than the cutoff (30 chars) then ... will be added.
			var shortenedUrlText = url.substr(0, 30);
			shortenedUrlText += (url.length > 30) ? '...' : '';
			
			// Adds the link to an array of links. Finally sanitizes both URLs for XSS
			urls.push('<a target="_blank" href="' + encodeURI(url) + '">' + common.htmlEncodeEntities(shortenedUrlText) + '</a>');
			
			// Return text with link placeholders
			return replacementText;
		});
		
		// Escape the whole text for XSS
		text = common.htmlEncodeEntities(text);
		
		// Put the escaped URLs back in by replacing the placeholders with the URLs from the array
		for (var i = 0; i < urls.length; i++)
		{
			text = text.replace('|' + i + '|', urls[i]);
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
		var initiatedByNickname = chat.getUserNickname(initiatedBy);
		
		// Stop automatic checking of messages and sending of decoy messages
		chat.stopIntervalReceivingMessages();
		decoy.stopTimerForDecoyMessages();
		
		// Clear the local in memory and local storage database
		db.nukeDatabase();
		
		// Clear all messages from the screen
		$('.mainChat').html('');
		$('.chatInput').val('');
		$('.messagesLastCheckedStatus').html('');
		$('.messageCharactersRemaining').html('');
		$('.messagesRemaining').html('');

		// Show warning message
		common.showStatus('error', 'Auto nuke initiated by ' + initiatedByNickname + '! Local database has been cleared.');
	},
		
	/**
	 * Initialises the display of the audio icon and the toggle audio on/off button
	 */
	initialiseToggleAudioButton: function()
	{
		// Show correct icon for whether sound is currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableSounds === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableSounds === true) ? 'fa-toggle-on' : 'fa-toggle-off';
		
		// Set the icon
		$('.enableDisableAudio').removeClass('fa-toggle-on fa-toggle-off').addClass(icon).prop('title', 'Audible notifications currently ' + onOrOff);
		$('.enableDisableAudioIcon').prop('title', 'Audible notifications currently ' + onOrOff);
		
		// Enable click event to toggle the audio on or off
		$('.enableDisableAudio, .enableDisableAudioIcon').click(function()
		{
			chat.enableOrDisableAudio();
		});
	},
	
	/**
	 * Initialises the display of the vibration icon and the toggle vibration on/off button
	 */
	initialiseToggleVibrationButton: function()
	{
		// Show correct icon for whether vibration is currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableVibration === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableVibration === true) ? 'fa-toggle-on' : 'fa-toggle-off';
		
		// Set the icon
		$('.enableDisableVibration').removeClass('fa-toggle-on fa-toggle-off').addClass(icon).prop('title', 'Vibration currently ' + onOrOff);
		$('.enableDisableVibrationLightningIcon').prop('title', 'Vibration currently ' + onOrOff);
		
		// Enable click event to toggle the vibration on or off
		$('.enableDisableVibration, .enableDisableVibrationLightningIcon').click(function()
		{
			chat.enableOrDisableVibration();
		});
	},
	
	/**
	 * Initialises the display of the Web Notifications icon and the toggle on/off button
	 */
	initialiseToggleWebNotificationsButton: function()
	{
		// Show correct icon for whether notifications are currently enabled or disabled
		var onOrOff = (db.padData.info.custom.enableWebNotifications === true) ? 'on' : 'off';
		var icon = (db.padData.info.custom.enableWebNotifications === true) ? 'fa-toggle-on' : 'fa-toggle-off';
		
		// Set the icon
		$('.enableDisableWebNotifications').removeClass('fa-toggle-on fa-toggle-off').addClass(icon);
		$('.enableDisableWebNotifications').prop('title', 'Web notifications currently ' + onOrOff);
		$('.enableDisableWebNotificationsIcon').prop('title', 'Web notifications currently ' + onOrOff);
		
		// Enable click event to toggle the notifications on or off
		$('.enableDisableWebNotifications, .enableDisableWebNotificationsIcon').click(function()
		{
			chat.enableOrDisableWebNotifications();
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
			$('.enableDisableAudio').removeClass('fa-toggle-on').addClass('fa-toggle-off');
			$('.enableDisableAudio').prop('title', 'Audible notifications currently off');
			$('.enableDisableAudioIcon').prop('title', 'Audible notifications currently off');
		}
		else {
			// Enable sound and save changes to database
			db.padData.info.custom.enableSounds = true;
			db.savePadDataToDatabase();
			
			// Change icon to volume on
			$('.enableDisableAudio').removeClass('fa-toggle-off').addClass('fa-toggle-on');
			$('.enableDisableAudio').prop('title', 'Audible notifications currently on');
			$('.enableDisableAudioIcon').prop('title', 'Audible notifications currently on');
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
			$('.enableDisableVibration').removeClass('fa-toggle-on').addClass('fa-toggle-off');
			$('.enableDisableVibration').prop('title', 'Vibration currently off');
			$('.enableDisableVibrationLightningIcon').prop('title', 'Vibration currently off');
		}
		else {
			// Enable vibrate and save changes to database
			db.padData.info.custom.enableVibration = true;
			db.savePadDataToDatabase();
			
			// Change icon to vibration on
			$('.enableDisableVibration').removeClass('fa-toggle-off').addClass('fa-toggle-on');
			$('.enableDisableVibration').prop('title', 'Vibration currently on');
			$('.enableDisableVibrationLightningIcon').prop('title', 'Vibration currently on');
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
			$('.enableDisableWebNotifications').removeClass('fa-toggle-on').addClass('fa-toggle-off');
			$('.enableDisableWebNotifications').prop('title', 'Web Notifications currently off');
			$('.enableDisableWebNotificationsIcon').prop('title', 'Web Notifications currently off');
		}
		else {
			// Enable Web Notifications and save changes to database
			db.padData.info.custom.enableWebNotifications = true;
			db.savePadDataToDatabase();
			
			// Change icon to Web Notifications on
			$('.enableDisableWebNotifications').removeClass('fa-toggle-off').addClass('fa-toggle-on');
			$('.enableDisableWebNotifications').prop('title', 'Web Notifications currently on');
			$('.enableDisableWebNotificationsIcon').prop('title', 'Web Notifications currently on');
		}
	}
};