/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2015  Joshua M. David
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

// Use ECMAScript 5's strict mode
'use strict';

/**
 * Stores the pad metadata and pads by serialising the data in HTML5 Local Storage.
 * Also provides methods for retrieving and deleting that data
 */

// On page load, initialise the DB
$(function()
{	
	db.initialiseLocalDatabase();
});

/**
 * Database object
 */
var db = {
	
	// Name of the database used as the key for local storage
	databaseName: 'padData',
	
	// Schema for the data to store all the pad information, server connection information, 
	// contact list and nicknames, crypto keys, one-time pads and any custom user settings
	padDataSchema: {
		info: {
			custom: {
				enableSounds: true,				// Enables sounds when a message is received
				enableVibration: true,			// Enables device vibration for incoming messages
				enableWebNotifications: true	// Enables HTML5 desktop notifications
			},
			failsafeRngKey: null,				// The failsafe key for the Salsa20 CSPRNG in case the Web Crypto API fails
			failsafeRngNonce: null,				// The next nonce to use for the failsafe Salsa20 CSPRNG
			serverAddressAndPort: null,			// The server address and port
			serverKey: null,					// The server API key
			user: null,							// The user callsign
			userNicknames: {}					// The custom group user nicknames matching the callsigns			
		},
		crypto: {
			keys: null,							// The encrypted database keys concatenated together
			keysMac: null,						// The MAC of the encrypted database keys for authentication
			padIndexMacs: {},					// The MAC of the pad index numbers for each user's list of one-time pads
			pbkdfKeccakIterations: null,		// The number of Keccak PBKDF iterations used to generate the master key for the database
			pbkdfSkeinIterations: null,			// The number of Skein PBKDF iterations used to generate the master key for the database
			pbkdfSalt: null						// The PBKDF salt / keyfile used to generate the master key for the database
		},
		pads: [],								// The one-time pads
		programVersion: null					// The program version that created this database (can be used for upgrading later if the format changes)
	},
		
	// In memory storage for all the pad information and pads (has same structure as schema above)
	padData: null,
	
	/**
	 * Initialise the database on the machine using the HTML5 local storage library
	 */
	initialiseLocalDatabase: function()
	{
		try {
			// Get the existing database from localStorage if it exists
			var padDataFromLocalStorage = localStorage.getObject(this.databaseName);		

			// If it already exists, use the existing one
			if (padDataFromLocalStorage !== null)
			{
				db.padData = padDataFromLocalStorage;
			}
			else {
				// Initialise to a blank database schema by cloning the schema, then set the local storage db
				db.resetInMemoryPadData();
				localStorage.setObject(this.databaseName, this.padData);
			}
		}
		catch (exception)
		{
			console.error('HTML localStorage is not available. Make sure it is enabled or try a different browser.');
		}
	},
	
	/**
	 * Initialise to a blank in memory database schema by cloning the schema
	 */
	resetInMemoryPadData: function()
	{
		this.padData = this.clone(this.padDataSchema);
	},
	
	/**
	 * Saves the pad information and pads from memory into the local storage database
	 */
	savePadDataToDatabase: function()
	{
		localStorage.setObject(this.databaseName, this.padData);
	},
		
	/**
	 * Clear the database
	 */
	nukeDatabase: function()
	{
		// Remove the existing data from memory and local storage
		this.padData = null;
		localStorage.removeItem(this.databaseName);
		
		// Reset the pad database to clean schema
		this.resetInMemoryPadData();
	},
	
	/**
	 * Clone an object so when assigning an object to a variable we're not using the reference of that object
	 * See http://stackoverflow.com/a/728694
	 * @param {Object} obj The object to be cloned
	 * @return {Object} The cloned object
	 */
	clone: function(obj)
	{
		return JSON.parse(JSON.stringify(obj));
	}
};

/**
 * Serializes an object to a JSON string and stores it in HTML5 local storage.
 * Usage: localStorage.setObject('key', objectValue);
 * @param {String} key The name of the key to store the object under and retrieve later
 * @param {Object} value The JavaScript object to store in HTML5 local storage
 */
Storage.prototype.setObject = function(key, value)
{
    this.setItem(key, JSON.stringify(value));
};

/**
 * Retrieves a serialized object from HTML5 local storage. It deserializes the JSON to a JavaScript object.
 * Usage: localStorage.getObject('key');
 * @param {String} key The name of the object to get from storage
 * @return {Object} Gets the object
 */
Storage.prototype.getObject = function(key)
{
	var storageItem = this.getItem(key);

	// If it doesn't exist return null
	if (storageItem === null)
	{
		return null;
	}
	else {
		// Otherwise unencode the JSON and return as an object
		return storageItem && JSON.parse(storageItem);
	}
};