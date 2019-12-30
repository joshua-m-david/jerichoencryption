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
 * Functions to backup the one-time pads that are in memory and restore them.
 * This functionality can also restore pads from version 1.41 of the program
 * because the in memory database is roughly the same.
 */
var backupPage = {

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
		// On Create Backup button click
		query.getCached('.jsCreateBackupButton').on('click', function()
		{
			// Get the method of export (clipboard or textFile)
			var exportMethod = query.getCached('.jsExportMethod:checked').val();

			// Backup to clipboard or text file
			var success = common.preparePadsForBackup(exportMethod);

			// If the backup succeeded
			if (success)
			{
				// Allow the clear local database button to be clicked now (this prevents accidental erasure before backing up)
				query.getCached('.jsClearLocalDatabaseButton').prop('disabled', false);
			}
		});
	},

	/**
	 * Clears the one-time pads from the localStorage database
	 */
	initClearDatabaseButton: function()
	{
		// On Clear Database button click
		query.getCached('.jsClearLocalDatabaseButton').on('click', function()
		{
			// Clear the memory and local storage then show success message
			db.nukeDatabase();
			app.showStatus('success', 'Local database cleared successfully.');
		});
	},

	/**
	 * Restore the pads from text file
	 */
	initRestorePadsFromFileButton: function()
	{
		// On selecting a file to restore from
		query.getCached('.jsRestorePadFile').on('change', function(event)
		{
			// Upload the pads from text file into the database
			backupPage.loadPadsFromTextFile(event);

			// Show a link to the chat page now the pads are loaded
			query.getCached('.jsChatButtonContainer').show();
		});
	},

	/**
	 * Restore pads from the clipboard
	 */
	initRestorePadsFromClipboardButton: function()
	{
		// On Load button click
		query.getCached('.jsLoadPadsFromClipboardButton').on('click', function()
		{
			// Get the pad data from the clipboard
			var padDataJson = query.getCached('.jsPadDataClipboardInput').val();

			// If the pad data is not empty
			if (padDataJson !== '')
			{
				// Save to the database and show a success message
				backupPage.preparePadDataForImport(padDataJson);
				app.showStatus('success', 'Pads loaded successfully from clipboard.');

				// Show a link to the chat page now the pads are loaded
				query.getCached('.jsChatButtonContainer').show();
			}
			else {
				// Otherwise show an error
				app.showStatus('error', 'No pad data to load.');
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
			return function(event)
			{
				// Send the JSON to be loaded to the database
				backupPage.preparePadDataForImport(event.target.result);

				// Log loaded file info to console
				app.showStatus('success', 'Pads loaded successfully. ' + fileInfo);
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
	},

	/**
	 * Page cleanup function to be run when the user leaves the page
	 */
	cleanup: function()
	{
		// Reset to default export method of Text file
		query.getCached('.jsExportMethod:last-child').prop('checked', true);

		// Re-disable the Clear local database button
		query.getCached('.jsClearLocalDatabaseButton').prop('disabled', true);

		// Reset the Restore pads file selection input
		query.getCached('.jsRestorePadFile').val('');
	}
};