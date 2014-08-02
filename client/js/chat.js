/*!
 * Jericho Chat - Information-theoretically secure communications
 * Copyright (C) 2013-2014  Joshua M. David
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */

/**
 * Functions for the chat page
 */
var chat = {
	
	// The interval id for checking new messages, and how often to check for new messages in milliseconds
	checkForMessagesIntervalId: null,
	checkForMessagesIntervalTime: 3000,		// 3 seconds
	
	// Running tally of how many pads/messages are remaining
	evenPadsRemaining: 0,
	oddPadsRemaining: 0,
		
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
			common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseDataJson)
			{
				// If the server response is authentic
				if (validResponse)
				{
					// Convert from JSON to object
					var responseData = JSON.parse(responseDataJson);
					
					// Get message back from server, and protect against XSS
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
					common.showStatus('error', 'Error contacting server. Double check you are connected to the network and that the client and server configurations are correct. Another possibility is that the data was modified in transit by an attacker.');
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
	 * @param {string} user The user e.g. 'alpha'
	 * @returns {string} Returns the user's nickname/real name e.g. 'Joshua'
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
		}, chat.checkForMessagesIntervalTime);
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
	 * Counts the number of pads remaining for sending and receiving. This will 
	 * do a full count of the local database once for the initial page load.
	 */
	countNumOfPadsRemaining: function()
	{
		var output = 'Remaining messages per user:<br>';
		
		// Count the pads for each user
		$.each(db.padData.pads, function(user, userPads)
		{
			// The unit tests page will put some test pads in the local 
			// database so don't show these on the chat screen
			if (user !== 'test')
			{			
				// Build the output
				output += db.padData.info.userNicknames[user] + ': <b><span class="' + user + '">' + userPads.length + '</span></b> ';
			}
		});
		
		// Display the count
		$('.messagesRemaining').html(output);
	},
	
	/**
	 * Updates the number of pads remaining in the local database.
	 * @param {string} user Update the number of pads remaining for just the user passed in or 'allUsers' if passed in
	 */
	updateNumOfPadsRemaining: function(user)
	{		
		// Update the number of pads remaining for all users if no user passed in
		if (user === undefined)
		{
			this.countNumOfPadsRemaining();
		}
		else {
			// Otherwise update just for the specific user
			var padsRemaining = db.padData.pads[user].length;
			$('.messagesRemaining .' + user).text(padsRemaining);
		}
	},
	
	/**
	 * Checks for new messages from the server and displays them
	 */
	checkForNewMessages: function()
	{
		// If there's no pad data loaded, stop trying to get messages from the server
		if (db.padData.info.serverAddressAndPort === null)
		{
			common.showStatus('error', "No pads have been loaded into this device's database.");
			chat.stopIntervalReceivingMessages();
			return false;
		}
		
		// Get the server address and key
		var serverAddressAndPort = db.padData.info.serverAddressAndPort;
		var serverKey = db.padData.info.serverKey;

		// Package the data to be sent to the server
		var data = {
			'user': db.padData.info.user,
			'apiAction': 'receiveMessages'
		};

		// Check the server for messages
		common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseDataJson)
		{
			// If the server response is authentic
			if (validResponse)
			{
				// Convert from JSON to object
				var responseData = JSON.parse(responseDataJson);
				
				// Get message back from server, and protect against XSS
				var status = responseData.success;
				var statusMessage = common.htmlEncodeEntities(responseData.statusMessage);
								
				// If there are messages
				if (status)
				{
					// Decrypt and display them
					chat.processReceivedMessages(responseData.messages);
				}
				
				// If another user initiated the auto nuke sequence
				else if ((status === false) && (statusMessage === 'Auto nuke initiated'))
				{
					// Clear the screen and database
					chat.processAutoNuke(statusMessage, responseData.initiatedBy);
					
					// Stop automatic checking of messages
					chat.stopIntervalReceivingMessages();
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
			}
			
			// If response check failed it means there was probably interference from attacker altering data or MAC
			else if (validResponse === false)
			{
				common.showStatus('error', 'Unauthentic response from server detected.');
			}

			else {
				// Most likely cause is user has incorrect server url or key entered.
				// Another alternative is the attacker modified their request while en route to the server
				common.showStatus('error', 'Error contacting server. Double check you are connected to the network and that the client and server configurations are correct. Another possibility is that the data was modified in transit by an attacker.');
				
				// Stop automatic checking of messages
				chat.stopIntervalReceivingMessages();
			}
		});
	},
		
	/**
	 * Process each message, by verifying, decrypting and displaying to the screen
	 * @param {array} messages An array of messages received from the server
	 */
	processReceivedMessages: function(messages)
	{		
		var decryptedMessages = [];
		var htmlMessages = '';
		var numOfMessages = messages.length;
		var padIndexesToErase = [];
					
		// For each message returned
		for (var i=0; i < numOfMessages; i++)
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
				// Show an error message to appear in the chat
				decryptedMessages.push({
					'padIdentifier': padData.padIdentifier,
					'fromUser': fromUser,					
					'plaintext': 'Warning: could not find the one-time pad to decrypt this message. Reference the Message ID and ask them to send the contents of this message again.',
					'timestamp': common.getCurrentUtcTimestamp(),
					'valid': false
				});
								
				// Try the next message
				continue;
			}
			
			// Decrypt and verify the message
			var decryptedOutput = common.decryptAndVerifyMessage(ciphertext, padData.pad);
			
			// If it is an authentic message, queue up the padIndexes to remove from the local database. If it's invalid we 
			// don't want an attacker (which has gained access to the server) able to send arbitrary messages with chosen 
			// pad identifiers back to the client when they check for new messages which would deplete the user's list of valid pads.
			if (decryptedOutput.valid)
			{
				padIndexesToErase.push({
					'index': padData.padIndex,
					'user': fromUser
				});
			}
			
			// Add a few more values to the object before it gets sorted
			decryptedOutput['padIdentifier'] = padData.padIdentifier;
			decryptedOutput['fromUser'] = fromUser;
			
			// Add to an array so each message can be sorted by timestamp
			decryptedMessages.push(decryptedOutput);
		}
		
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
		
		// Play a sound and vibrate the device to signal new message/s received
		chat.playSound('incoming-message.wav');
		chat.vibrateDevice();

		// Update status
		$('.messagesLastCheckedStatus').html('Messages received at: <b>' + common.getCurrentLocalTime() + '</b>');
		chat.updateNumOfPadsRemaining();
	},
		
	/**
	 * Remove from in memory database the one-time pads that have been used and verified.
	 * Also update the local database so that pad can't be used again
	 * @param {array} padIndexesToErase An array of objects containing keys 'user' (the user to erase the pad from) and 'index' (the array index of the pad to erase)
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
		for (var i=0, length = padIndexesToErase.length; i < length; i++)
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
	 * @param {object} decryptedMessages
	 * @returns {object} Returns the messages sorted by earliest sent timestamp first
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
	 * @param {array} decryptedMessages The array of message objects
	 * @returns {string}
	 */
	generateHtmlForReceivedMessages: function(decryptedMessages)
	{	
		var htmlMessages = '';
		
		// For each message build the HTML to be rendered
		for (var i=0, length = decryptedMessages.length; i < length; i++)
		{
			// Get the HTML display for this message
			var html = chat.prepareMessageForDisplay(decryptedMessages[i]);

			// Then get the whole message div (the outer HTML) and continue building output
			htmlMessages += html.clone().wrap('<p>').parent().html();
		}
		
		return htmlMessages;
	},
	
	/**
	 * Format the message for display to the chat window
	 * @param {object} message An object with the following keys 'ciphertext', 'plaintext', 'timestamp', 'valid', 'fromUser'
	 * @return {string} The HTML to be displayed
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
	 * @param {string} text The text to escape
	 * @returns {string}
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
		for (var i=0; i < urls.length; i++)
		{
			text = text.replace('|' + i + '|', urls[i]);
		}
		
		// Return linkified and XSS escaped text
		return text;
	},
	
	/**
	 * Auto nuke was initiated by the other user, clear everything
	 * @param {string} statusMessage The status from the server which will contain which user initiated the nuke
	 * @param {string} initiatedBy The user that initiated the auto nuke
	 */
	processAutoNuke: function(statusMessage, initiatedBy)
	{
		// Get the call sign of the user who initiated the nuke, this 
		// can be helpful in knowing which member of the group is in trouble
		var initiatedByCallSign = chat.getUserNickname(initiatedBy);
		
		// Clear the local in memory and local storage database
		db.nukeDatabase();
		
		// Clear all messages from the screen
		$('.mainChat').html('');
		$('.chatInput').val('');
		$('.messagesLastCheckedStatus').html('');
		$('.messageCharactersRemaining').html('');
		$('.messagesRemaining').html('');

		// Show warning message
		common.showStatus('error', statusMessage + ' by ' + initiatedByCallSign + '!');
	},
	
	/**
	 * Plays a sound in the browser using the HTML5 audio element. 
	 * Chrome, Firefox, Safari and Opera currently have common support using wav audio file format.
	 * @param {string} filename The filename of the audio file in the /client/sounds/ directory
	 */
	playSound: function(filename)
	{
		// Make sure the user has enabled sound
		if (db.padData.custom.enableSounds)
		{
			// Play the sound
			var sound = new Audio('sounds/' + filename);
			sound.load();
			sound.play();
		}
	},
	
	/**
	 * Vibrates the device if supported
	 */
	vibrateDevice: function()
	{
		// Normalise the HTML5 vibration API between browser vendors
		navigator.vibrate = navigator.vibrate || navigator.webkitVibrate || navigator.mozVibrate;
		
		// If it's supported, vibrate the device for 700ms
		if (navigator.vibrate) {
			navigator.vibrate(700);
		}
	},
	
	/**
	 * Initialises the display of the audio icon and the toggle audio on/off button
	 */
	initialiseToggleAudioButton: function()
	{
		// Show correct icon for whether sound is currently enabled or disabled
		var onOrOff = (db.padData.custom.enableSounds === true) ? 'on' : 'off';		
		$('.enableDisableAudio').addClass('ui-icon-volume-' + onOrOff).prop('title', 'Audio currently ' + onOrOff);
		
		// Enable click event to toggle the audio on or off
		$('.enableDisableAudio').click(function()
		{
			chat.enableOrDisableAudio();
		});
	},
	
	/**
	 * Toggles the audio on or off
	 */
	enableOrDisableAudio: function()
	{
		// If sound is currently enabled, disable it
		if (db.padData.custom.enableSounds === true)
		{
			// Disable sound and save changes to database
			db.padData.custom.enableSounds = false;
			db.savePadDataToDatabase();
			
			// Change icon to volume off
			$('.enableDisableAudio').removeClass('ui-icon-volume-on').addClass('ui-icon-volume-off').prop('title', 'Audio currently off');
		}
		else {
			// Enable sound and save changes to database
			db.padData.custom.enableSounds = true;
			db.savePadDataToDatabase();
			
			// Change icon to volume on
			$('.enableDisableAudio').removeClass('ui-icon-volume-off').addClass('ui-icon-volume-on').prop('title', 'Audio currently on');
		}
	}
};