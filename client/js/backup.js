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
 * Functions to backup the one-time pads that are in memory and restore them.
 * This functionality can also restore pads from version 1.41 of the program 
 * because the in memory database is roughly the same.
 */
var backupPads = {
	
	/**
	 * Initialise the program
	 */
	init: function()
	{
		this.initBackupButton();
		this.initClearDatabaseButton();
		this.initRestorePadsFromFileButton();
		this.initRestorePadsFromClipboardButton();
	},
	
	/**
	 * Backs up the pads to text file or clipboard
	 */
	initBackupButton: function()
	{
		// Get values from page and backup to clipboard or text file
		$('#btnBackup').click(function()
		{
			// Backup to clipboard or text file
			var exportMethod = $('.exportMethod:checked').val();					
			common.preparePadsForBackup(exportMethod);

			// Allow the clear local database button to be clicked now (this prevents accidental erasure before backing up)
			$('#btnClearLocalDatabase').prop('disabled', false);
		});
	},

	/**
	 * Clears the one-time pads from the localStorage database
	 */
	initClearDatabaseButton: function()
	{
		// Clear the memory and local storage
		$('#btnClearLocalDatabase').click(function()
		{
			db.nukeDatabase();
			common.showStatus('success', 'Local database cleared successfully.');
		});
	},
	
	/**
	 * Restore the pads from text file
	 */
	initRestorePadsFromFileButton: function()
	{	
		// Upload the pads from text file into the database
		$('#padFile').change(function(e)
		{
			backupPads.loadPadsFromTextFile(e);

			// Show a link to the chat page now the pads are loaded
			$('.chatButton').show();
		});
	},

	/**
	 * Restore pads from the clipboard
	 */
	initRestorePadsFromClipboardButton: function()
	{
		// Load pads into the database from the clipboard
		$('#loadPadsFromClipboard').click(function()
		{
			var padDataJson = $('#padDataClipboardInput').val();					
			if (padDataJson !== '')
			{
				// Save to the database
				backupPads.preparePadDataForImport(padDataJson);
				common.showStatus('success', 'Pads loaded successfully from clipboard.');

				// Show a link to the chat page now the pads are loaded
				$('.chatButton').show();
			}
			else {
				common.showStatus('error', 'No pad data to load.');
			}
		});
	},
	
	/**
	 * Load the one-time pads from a text file
	 * @param {event} evt The event object
	 */
	loadPadsFromTextFile: function(evt)
	{
		// FileList object
		var files = evt.target.files;
		var file = files[0];
		
		// List some properties
		var fileInfo = 'Pads loaded: ' + file.name + ', ' + file.type + ', ' + file.size + ' bytes.';
		
		// Set up to read from text file
		var reader = new FileReader();
		reader.readAsText(file);

		// Closure to read the file information
		reader.onload = (function(theFile)
		{
			return function(e)
			{
				// Send the JSON to be loaded to the database
				backupPads.preparePadDataForImport(e.target.result);
				
				// Log loaded file info to console
				common.showStatus('success', 'Pads loaded successfully. ' + fileInfo);
			};
		})(file);
	},
	
	/**
	 * Gets the data back from JSON format and saves it to the two database tables
	 * @param {string} padDataJson The one-time pads and meta data in JSON format
	 */
	preparePadDataForImport: function(padDataJson)
	{
		// Parse the serialized data into a JavaScript object and save to the database
		db.padData = JSON.parse(padDataJson);
		db.savePadDataToDatabase();
	}
};