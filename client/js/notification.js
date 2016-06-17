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
 * Notifies the user using various methods
 */
var notification = {
	
	/**
	 * Play a sound, vibrate the device and show a desktop notification to signal new message/s received
	 */
	alertForIncomingMessage: function()
	{
		// Set the message for the notification
		var message = 'New secure message received at ' + common.getCurrentLocalTime() + '. Click here to read the message.';
		
		// Play sound, vibrate and show desktop notification (if each one is enabled)
		notification.playSound('incoming-message');
		notification.vibrateDevice();
		notification.checkPermissionsAndDisplayNotification(message);
	},
	
	/**
	 * Plays a sound in the browser using the HTML5 audio element. 
	 * Chrome, Firefox, Safari and Opera currently have common support using wav audio file format.
	 * @param {String} filename The filename of the .wav audio file in the /client/sounds/ directory e.g. 'incoming-message'
	 */
	playSound: function(filename)
	{
		// Make sure the user has enabled sound
		if (db.padData.info.custom.enableSounds)
		{
			// Play the sound
			var sound = new Audio('sounds/' + filename + '.wav');
			sound.load();
			sound.play();
		}
	},
	
	/**
	 * Vibrate the device if supported
	 */
	vibrateDevice: function()
	{
		// Make sure the user has enabled vibration
		if (db.padData.info.custom.enableVibration)
		{
			// Normalise the HTML5 vibration API between browser vendors
			navigator.vibrate = navigator.vibrate || navigator.webkitVibrate || navigator.mozVibrate;

			// If it's supported, vibrate the device for 700ms
			if (navigator.vibrate)
			{
				navigator.vibrate(700);
			}
		}
	},
	
	/**
	 * Check support, permissions and display the notification to the user
	 * @param {String} message The message to be displayed to the user
	 */
	checkPermissionsAndDisplayNotification: function(message)
	{
		// If the user has not enabled desktop notifications
		if (!db.padData.info.custom.enableWebNotifications)
		{
			return false;
		}
		
		// If the browser does not support notifications
		if ('Notification' in window === false)
		{
			return false;
		}
				
		// Do not display desktop notifications if the page is already in focus
		if (document.hasFocus())
		{
			return false;
		}
			
		// If the user has allowed desktop notifications
		if (Notification.permission === 'granted')
		{
			notification.displayDesktopNotification(message);
		}

		// If the permission is 'default' and not set yet
		else if (Notification.permission !== 'denied')
		{
			// Ask the user for permission
			Notification.requestPermission(function(permission)
			{
				// If the user has allowed desktop notifications, create a notification
				if (permission === 'granted')
				{
					notification.displayDesktopNotification(message);
				}
			});
		}
	},
	
	/**
	 * Display the desktop notification in the corner of the screen
	 * @param {String} message The message to be displayed to the user
	 */
	displayDesktopNotification: function(message)
	{
		// Create a notification
		var title = 'Jericho Comms:';
		var notification = new Notification(title,
		{
			icon: 'img/touch-icon-196x196.png',
			body: message
		});

		// Go to the screen where the notification originated when clicked
		notification.onclick = function()
		{
			window.focus();
		};
	}
};