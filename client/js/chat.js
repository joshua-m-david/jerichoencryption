/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
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
	 * Make the chat window always scroll to the bottom if there are lots of messages
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
	 * Focuses the mouse cursor into the chat box so they can start typing immediately
	 */
	focusCursorIntoChatBox: function()
	{
		$('#newChatMessage').focus();
	},
	
	/**
	 * Initialises the send message button, which when clicked will encrypt and send the message to the server
	 */
	initialiseSendMessageButton: function()
	{
		// If the send message function is clicked
		$('#btnSendMessage').click(function()
		{			
			// Get plaintext message and remove invalid non ASCII characters from message
			var plaintextMessage = $('#newChatMessage').val();
			plaintextMessage = common.removeInvalidChars(plaintextMessage);
			
			// Make sure they've entered in some data
			if (plaintextMessage == '')
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

			// Encrypt the message and create the HMAC
			var results = common.encryptAndAuthenticateMessage(plaintextMessage, pad);					
			var padIdentifier = common.getPadIdentifierFromCiphertext(results.ciphertext);

			// If currently user 1 pads are loaded, then this message is being sent to user 2.
			// Otherwise if user 2 pads are loaded, then this mesage is being sent to user 1.
			var messageTo = (db.padData.info.user == 1) ? 2 : 1;

			// Fix the url for any excess slashes
			var serverAddress = common.standardiseUrl(db.padData.info.serverAddressAndPort, 'send-message.php');
			
			// Create AJAX request to chat server
			$.ajax(
			{
				url: serverAddress,
				type: 'POST',
				dataType: 'json',
				data: {
					'username': db.padData.info.serverUsername,			// Username to connect to the server
					'password': db.padData.info.serverPassword,			// Password to connect to the server
					'to': messageTo,									// Who the message is going to
					'msg': results.ciphertext,							// The message ciphertext
					'mac': results.mac									// The MAC of the message
				},
				success: function(data)
				{
					// Get message back from server, and protect against XSS
					var statusMessage = common.htmlEncodeEntities(data.statusMessage);
					
					// If it saved to the database
					if (data.success)
					{
						// Find the message with that identifier and update the status to 'Sent'
						$('.messageStatus[data-pad-identifier=' + padIdentifier + ']').html(statusMessage);
						chat.updateNumOfPadsRemaining(1, 0);
					}
					else {
						// Otherwise show error from the server
						common.showStatus('error', statusMessage);
					}
				},
				error: function(jqXHR, textStatus, errorThrown)
				{
					// Display error
					common.showStatus('error', 'Error contacting server, check you are connected to the internet and that server setup is correct.');
				}
			});

			// Copy the template message into a new message
			var messageHtml = $('.templateMessage').clone().removeClass('templateMessage');
			
			// Convert links in text to URLs and escape the message for XSS before outputting it to screen
			var plaintextMessageEscaped = chat.convertLinksAndEscapeForXSS(plaintextMessage);

			// Set params on the template
			messageHtml.addClass('message messageSent');											// Show style for sent message
			messageHtml.find('.dateTime').html(common.getCurrentLocalDateTime());					// Show current local date time		
			messageHtml.find('.messageText').html(plaintextMessageEscaped);							// Show the sent message in chat
			messageHtml.find('.messageText').attr('title', 'Ciphertext: ' + results.ciphertext);	// Show ciphertext on mouse hover
			messageHtml.find('.messageStatus').html('Sending...');									// Show current status
			messageHtml.find('.messageStatus').attr('data-pad-identifier', padIdentifier);			// Attach identifier to the div, so the status can be updated after

			// Populate the new message into the chat window
			messageHtml.appendTo('.mainChat').fadeIn('fast');

			// Remove the text from the text box and scroll to bottom of window to show new message
			$('#newChatMessage').val('');
			chat.scrollChatWindowToBottom();
			return false;
		});
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
			if (e.keyCode == 13)
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
	showNumOfMessageCharactersRemaining: function()
	{
		$('#newChatMessage').keyup(function ()
		{
			// Get the current number of chars entered and the maximum message size
			var len = $(this).val().length;
			var max = common.messageSize;			
			
			// Calculate how many characters remaining
			var charsRemaining = max - len;
			$('.messageCharactersRemaining').html('<b>' + charsRemaining + '/' + max + '</b> characters remaining');
		});
	},
	
	/**
	 * Counts the number of pads remaining for sending and receiving. This will 
	 * do a full count of the local database once for the initial page load.
	 */
	countNumOfPadsRemaining: function()
	{
		var length = db.padData.pads.length;			
		
		// Loop through all pads	
		for (var i=0; i < length; i++)
		{
			// Count all even numbered pads left in database
			if ((db.padData.pads[i].padNum % 2) == 0)
			{
				this.evenPadsRemaining++;
			}
			else {
				// Count all odd numbered pads left in database
				this.oddPadsRemaining++;
			}
		}
	},
	
	/**
	 * Updates the number of pads remaining in the local database.
	 * To intitialise the display to the current number of pads, 0 and 0 can be passed in.
	 * @param {number} messagesSent To update pass in how many messages were just sent
	 * @param {number} messagesReceived To update pass in how many messages were just received
	 */
	updateNumOfPadsRemaining: function(messagesSent, messagesReceived)
	{
		// Is user using even or odd numbered pads
		var usingEvenNumberedPads = db.padData.info.usingEvenNumberedPads;
		var output = '';
		
		// Format depending on user
		if (usingEvenNumberedPads)
		{
			// Subtract from total
			this.evenPadsRemaining -= messagesSent;
			this.oddPadsRemaining -= messagesReceived;
			
			// User 1 using even numbered
			output = 'Messages to send: <b>' + this.evenPadsRemaining + '</b><br>'
			       + 'Messages to receive: <b>' + this.oddPadsRemaining + '</b><br>';
		}
		else {
			// Subtract from total
			this.oddPadsRemaining -= messagesSent;
			this.evenPadsRemaining -= messagesReceived;			
			
			// User 2 using odd numbered
			output = 'Messages to send: <b>' + this.oddPadsRemaining + '</b><br>'
			       + 'Messages to receive: <b>' + this.evenPadsRemaining + '</b><br>';
		}
		
		// Add total and display to screen
		output += 'Total pads remaining: <b>' + (this.evenPadsRemaining + this.oddPadsRemaining) + '</b><br>';
		$('.messagesRemaining').html(output);
	},
	
	/**
	 * Checks for new messages from the server and displays them
	 */
	checkForNewMessages: function()
	{
		// If there's no pad data loaded, stop trying to get messages from the server
		if (db.padData.info.serverAddressAndPort == null)
		{
			common.showStatus('error', "No pads have been loaded into this device's database.");
			chat.stopIntervalReceivingMessages();
			return false;
		}
		
		// Fix the url for any excess slashes
		var serverAddress = common.standardiseUrl(db.padData.info.serverAddressAndPort, 'receive-messages.php');

		// Create AJAX request to chat server
		$.ajax(
		{
			url: serverAddress,
			type: 'POST',
			dataType: 'json',
			data: {
				'username': db.padData.info.serverUsername,			// Username to connect to the server
				'password': db.padData.info.serverPassword,			// Password to connect to the server
				'to': db.padData.info.user							// Get messages for this user
			},
			success: function(data)
			{
				// Get message back from server, and protect against XSS
				var statusMessage = common.htmlEncodeEntities(data.statusMessage);
								
				// If there are messages
				if (data.success)
				{
					// Decrypt and display them
					chat.processReceivedMessages(data.messages);
				}
				else if ((data.success === false) && (data.statusMessage == 'Auto nuke initiated.'))
				{
					// Other user initiated the auto nuke sequence
					chat.processAutoNuke();
				}
				else if ((data.success === false) && (data.statusMessage != 'No messages in database.'))
				{
					// Otherwise show error from the server and update status
					common.showStatus('error', statusMessage);
					$('.messagesLastCheckedStatus').html('');
					
					// Stop automatic checking of messages
					chat.stopIntervalReceivingMessages();
				}
				else {
					// If there are no messages, just display status message
					$('.messagesLastCheckedStatus').html('No messages since: <b>' + common.getCurrentLocalTime() + '</b>');
				}
			},
			error: function(jqXHR, textStatus, errorThrown)
			{
				// Display error and stop automatic checking of messages
				common.showStatus('error', "Error contacting server, check you are connected to the internet and that server setup is correct.");
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
		var htmlMessages = '';
					
		// For each message returned
		for (var i=0; i < messages.length; i++)
		{
			// Get details necessary to decrypt and verify
			var ciphertext = messages[i].msg;
			var mac = messages[i].mac;
			var padData = common.getPadToDecryptMessage(ciphertext);
			var padIdentifier = padData.padIdentifier;
			var pad = padData.pad;

			// Decrypt and verify the message
			var decryptedOutput = common.decryptAndVerifyMessage(ciphertext, pad, mac);
			
			// Get the html display for this message
			var html = chat.prepareMessageForDisplay(ciphertext, decryptedOutput);

			// Then get the whole message div (the outer HTML) and continue building output
			htmlMessages += html.clone().wrap('<p>').parent().html();
		}

		// Add the html messages to the chat window and scroll to the end so the user can see the messages
		$(htmlMessages).appendTo('.mainChat');
		chat.scrollChatWindowToBottom();
		
		// Play a sound to signal new message/s received
		chat.playSound('sounds/incoming-message.wav');

		// Update status
		$('.messagesLastCheckedStatus').html('Messages received at: <b>' + common.getCurrentLocalTime() + '</b>');
		chat.updateNumOfPadsRemaining(0, messages.length);
	},
	
	/**
	 * Format the message for display to the chat window
	 * @param {string} ciphertext The ciphertext string
	 * @param {array} decryptedOutput The decrypted output containing the plaintext, sent timestamp and HMAC validation result
	 * @return {string} The HTML to be displayed
	 */
	prepareMessageForDisplay: function(ciphertext, decryptedOutput)
	{
		// Copy the template message into a new message
		var messageHtml = $('.templateMessage').clone().removeClass('templateMessage');
		var dateString = common.getCurrentLocalDateTimeFromUtcTimestamp(decryptedOutput.timestamp);
		var messageStatus = (decryptedOutput.valid) ? 'Authenticated' : 'Tampering detected';
		var messageValidity = (decryptedOutput.valid) ? 'messageValid' : 'messageInvalid';
				
		// Convert links in text to URLs and escape for XSS
		var plaintext = chat.convertLinksAndEscapeForXSS(decryptedOutput.plaintext);	
		var ciphertextEscaped = common.htmlEncodeEntities(ciphertext);
					
		// Set params on the template
		messageHtml.addClass('message messageReceived');										// Show style for sent message
		messageHtml.find('.dateTime').html(dateString);											// Show current local date time		
		messageHtml.find('.messageText').html(plaintext);										// Show the sent message in chat
		messageHtml.find('.messageText').attr('title', 'Ciphertext: ' + ciphertextEscaped);		// Show ciphertext on mouse hover
		messageHtml.find('.messageStatus').html(messageStatus);									// Show current status
		messageHtml.find('.messageStatus').addClass(messageValidity);							// Show green for valid, red for invalid
		
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
			
			// Shorten the URL that the user sees into format http://jerichoencryption...
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
	 */
	processAutoNuke: function()
	{
		// Clear the local in memory and local storage database
		db.nukeDatabase();
		
		// Clear all messages from the screen
		$('.mainChat').html('');
		$('.chatInput').val('');
		$('.messagesLastCheckedStatus').html('');
		$('.messageCharactersRemaining').html('');
		$('.messagesRemaining').html('');

		// Show warning message
		common.showStatus('error', 'Auto nuke was initiated by other user!');
	},
	
	/**
	 * Plays a sound in the browser using the HTML5 audio element. 
	 * Chrome, Firefox, Safari and Opera currently have common support using wav audio file format.
	 * @param {string} url The path to the audio file
	 */
	playSound: function(url)
	{
		// Make sure the user has enabled sound
		if (db.padData.custom.enableSounds)
		{
			// Play the sound
			var sound = new Audio(url);
			sound.load();
			sound.play();
		}
	},
	
	/**
	 * Initialises the display of the audio icon and the toggle audio on/off button
	 */
	initialiseToggleAudioButton: function()
	{
		// Show correct icon for whether sound is currently enabled or disabled
		var onOrOff = (db.padData.custom.enableSounds == true) ? 'on' : 'off';		
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
		if (db.padData.custom.enableSounds == true)
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