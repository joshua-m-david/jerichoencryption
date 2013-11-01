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
	
	// Schema for the data to store all the pad information, pads and any custom user settings
	padDataSchema: {
		info: {
			user: null,
			usingEvenNumberedPads: null,
			serverAddressAndPort: null,
			serverUsername: null,
			serverPassword: null
		},
		pads: [],
		custom: {
			enableSounds: true
		}
	},
		
	// In memory storage for all the pad information and pads (has same structure as schema above)
	padData: null,
	
	/**
	 * Initialise the database on the machine using the HTML5 local storage library
	 */
	initialiseLocalDatabase: function()
	{
		var padDataFromLocalStorage = localStorage.getObject(this.databaseName);		
		
		// If it already exists, use the existing one
		if (padDataFromLocalStorage != null)
		{
			this.padData = padDataFromLocalStorage;
		}
		else {
			// Initialise to a blank database schema by cloning the schema, then set the local storage db
			this.resetInMemoryPadData();
			localStorage.setObject(this.databaseName, this.padData);
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
	 * @param {object} obj The object to be cloned
	 * @return {object} The cloned object
	 */
	clone: function(obj)
	{
		// Handle the 3 simple types, and null or undefined
		if (null == obj || "object" != typeof obj) return obj;

		// Handle Date
		if (obj instanceof Date) {
			var copy = new Date();
			copy.setTime(obj.getTime());
			return copy;
		}

		// Handle Array
		if (obj instanceof Array) {
			var copy = [];
			for (var i = 0, len = obj.length; i < len; i++) {
				copy[i] = this.clone(obj[i]);
			}
			return copy;
		}

		// Handle Object
		if (obj instanceof Object) {
			var copy = {};
			for (var attr in obj) {
				if (obj.hasOwnProperty(attr)) copy[attr] = this.clone(obj[attr]);
			}
			return copy;
		}

		throw new Error("Unable to copy obj! Its type isn't supported.");
	}
};

/**
 * Serializes an object to a JSON string and stores it in HTML5 local storage.
 * Usage: localStorage.setObject('key', objectValue);
 * @param {string} key The name of the key to store the object under and retrieve later
 * @param {object} value The JavaScript object to store in HTML5 local storage
 */
Storage.prototype.setObject = function(key, value)
{
    this.setItem(key, JSON.stringify(value));
};

/**
 * Retrieves a serialized object from HTML5 local storage. It deserializes the JSON to a JavaScript object.
 * Usage: localStorage.getObject('key');
 * @param {string} key The name of the object to get from storage
 * @return {object} Gets the object
 */
Storage.prototype.getObject = function(key)
{	
	var storageItem = this.getItem(key);

	// If it doesn't exist return null
	if (storageItem == 'undefined')
	{
		return null;
	}
	else {
		// Otherwise unencode the JSON and return as an object
		return storageItem && JSON.parse(storageItem);
	}
};