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
 * Combines files with random hexadecimal string data by XORing them together into a single
 * file which can be imported into an external tool for more strenuous randomness testing.
 */
var trngXorCombinerPage = {

	/** The number of files that have been loaded so far */
	numFilesLoaded: 0,

	/** The total number of files selected to be loaded */
	totalNumFiles: 0,

	/** All the hexadecimal data from the files concatenated together */
	allDataHex: '',

	/** The display output row HTML */
	rowHtml: '',

	/**
	 * Initialise the page code
	 */
	init: function()
	{
		// Init
		trngXorCombinerPage.initResetButton();
		trngXorCombinerPage.initBrowseFilesButton();
		trngXorCombinerPage.initExportFileButton();
	},

	/**
	 * When files are uploaded
	 */
	initBrowseFilesButton: function()
	{
		// When the browse files button is clicked and files selected
		query.getCached('.jsFileLoader').on('change', function()
		{
			// Get the files
			var files = $(this)[0].files;
			var totalNumFiles = files.length;

			// Check at least two files selected
			if (totalNumFiles < 2)
			{
				app.showStatus('error', 'You need to select at least two files.');
				return false;
			}

			// Disable adding more files after files selected, they can use the Restart button
			query.getCached('.jsFileLoader').prop('disabled', true);
			query.getCached('.jsFileLoaderLabel').addClass('disabled');

			// Set for use later
			trngXorCombinerPage.totalNumFiles = totalNumFiles;

			// For every file
			for (var i = 0; i < files.length; i++)
			{
				// Load the file information
				trngXorCombinerPage.loadFileInformation(files[i]);
			}
		});
	},

	/**
	 * Loads the file information
	 * @param {Object} file A file with hexadecimal string data
	 */
	loadFileInformation: function(file)
	{
		// Initialise the HTML5 FileReader and get the file name
		var reader = new FileReader();
		var fileName = file.name;

		// Read as a text file
		reader.readAsText(file);

		// Callback when file is loaded
		reader.onload = function(event)
		{
			// Clone the row and calculate the total number of hex symbols loaded
			var $row = query.getCached('.isFileInfoRowTemplate').clone();
			var loadedHexSymbols = event.target.result;
			var numHexSymbolsLoaded = loadedHexSymbols.length;

			// If the number of hexadecimal symbols are not even
			if ((numHexSymbolsLoaded % 2) !== 0)
			{
				// Remove the last hexadecimal symbol so there is only even bytes in the final output
				loadedHexSymbols = loadedHexSymbols.slice(0, -1);
				numHexSymbolsLoaded = numHexSymbolsLoaded - 1;
			}

			// Calculate and format the number of Bytes loaded
			var numLoadedBytes = numHexSymbolsLoaded / 2;
			var numHexSymbolsLoadedFormatted = common.formatNumberWithCommas(numHexSymbolsLoaded);
			var numLoadedBytesFormatted = common.formatNumberWithCommas(numLoadedBytes);

			// Populate values
			$row.removeClass('isFileInfoRowTemplate');
			$row.find('.jsFileName').text(fileName);
			$row.find('.jsFileSize').text(numLoadedBytesFormatted + ' Bytes');
			$row.find('.jsTotalHexSymbols').text(numHexSymbolsLoadedFormatted);

			// If the first file, set it as the initial random data
			if (trngXorCombinerPage.numFilesLoaded === 0)
			{
				trngXorCombinerPage.allDataHex = loadedHexSymbols;
			}
			else {
				// Set the length of the current final data
				var previousLoadedDataLength = trngXorCombinerPage.allDataHex.length;

				// If the previous data is longer than the current data
				if (trngXorCombinerPage.allDataHex.length > numHexSymbolsLoaded)
				{
					// Truncate the previous data
					trngXorCombinerPage.allDataHex = trngXorCombinerPage.allDataHex.substr(0, numHexSymbolsLoaded);
				}

				// Otherwise if the recently loaded data length is more than the previous data loaded
				else if (numHexSymbolsLoaded > previousLoadedDataLength)
				{
					// Truncate the recently loaded data
					loadedHexSymbols = loadedHexSymbols.substr(0, previousLoadedDataLength);
				}

				// Otherwise XOR the data to the previous data
				trngXorCombinerPage.allDataHex = common.xorHex(trngXorCombinerPage.allDataHex, loadedHexSymbols);
			}

			// Increment count of files loaded and add the row to the output
			trngXorCombinerPage.numFilesLoaded += 1;
			trngXorCombinerPage.rowHtml += $row.prop('outerHTML');

			// If all the files are loaded
			if (trngXorCombinerPage.numFilesLoaded === trngXorCombinerPage.totalNumFiles)
			{
				// Enable other buttons
				query.getCached('.jsRestartButton').prop('disabled', false);
				query.getCached('.jsExportFileButton').prop('disabled', false);

				// Show the loaded files
				query.getCached('.jsFileInfoTable').append(trngXorCombinerPage.rowHtml).show();

				// Find the number of hexadecimal symbols and bytes loaded
				var totalHexSymbolsLoaded = trngXorCombinerPage.allDataHex.length;
				var totalBytes = (totalHexSymbolsLoaded / 2);

				// If the number of bytes is not even
				if ((totalBytes % 2) !== 0)
				{
					// Slice a byte off the end so it is even, then NIST tests won't complain
					trngXorCombinerPage.allDataHex = trngXorCombinerPage.allDataHex.slice(0, -2);
					totalHexSymbolsLoaded = totalHexSymbolsLoaded - 2;
					totalBytes = totalBytes - 1;
				}

				// Format the total number of hexadecimal symbols, bytes and megabytes loaded
				var totalHexSymbolsLoadedFormatted = common.formatNumberWithCommas(totalHexSymbolsLoaded);
				var totalBytesFormatted = common.formatNumberWithCommas(totalBytes);
				var totalMegaBytes = (totalBytes / 1024 / 1024).toFixed(3);
				var totalMegaBytesFormatted = common.formatNumberWithCommas(totalMegaBytes);

				// Show final status
				app.showStatus('success', (
						'All data loaded. ' +
						'Total files: ' + trngXorCombinerPage.numFilesLoaded + '. ' +
						'Total hex symbols: ' + totalHexSymbolsLoadedFormatted + '. ' +
						'Total Bytes: ' + totalBytesFormatted + '. ' +
						'Total MB: ' + totalMegaBytesFormatted
				    ), true);
			}
		};
	},

	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset button click
		query.getCached('.jsRestartButton').on('click', function()
		{
			// Hard refresh the page (ignores browser cache)
			location.reload(true);
		});
	},

	/**
	 * Enable the export button which will convert the data to Base64 and prompt a save dialog
	 */
	initExportFileButton: function()
	{
		// Enable the export button and save the file when clicked
		query.getCached('.jsExportFileButton').on('click', function()
		{
			// Convert to Base64
			var outputBase64 = common.convertHexadecimalToBase64(trngXorCombinerPage.allDataHex);

			// Update hidden anchor tag with the Base64 data
			query.getCached('.jsExportFileLink').attr('href', 'data:application/octet-stream;base64,' + outputBase64);

			// Get the native JS element (0) and trigger the click function which will prompt the user to save the file
		    query.getCached('.jsExportFileLink').get(0).click();
		});
	},

	/**
	 * The cleanup function to be run when moving to another page.
	 * This will reset the page to its initial state.
	 */
	cleanup: function()
	{
		// Reset the file upload input so files can be reselected
		query.getCached('.jsFileLoaderLabel').removeClass('disabled');
		query.getCached('.jsFileLoader').prop('disabled', false).val('');

		// Reset Export and Restart buttons to their initial disabled state as the files are not selected yet
		query.getCached('.jsExportFileButton').prop('disabled', true);
		query.getCached('.jsRestartButton').prop('disabled', true);

		// Remove table rows about the loaded files
		query.getCached('.jsFileInfoRow').not('.isFileInfoRowTemplate').remove();

		// Clear the random data from the hidden anchor link
		query.getCached('.jsExportFileLink').attr('href', '');

		// Reset to initial values
		trngXorCombinerPage.numFilesLoaded = 0;
		trngXorCombinerPage.totalNumFiles = 0;
		trngXorCombinerPage.allDataHex = '';
		trngXorCombinerPage.rowHtml = '';
	}
};
