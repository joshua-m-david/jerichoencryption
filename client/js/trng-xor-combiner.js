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
 * Combines files with random hexadecimal string data by XORing them together into a single 
 * file which can be imported into an external tool for more strenuous randomness testing.
 */
var trngXorCombiner = {
	
	/** A jQuery selector for the TRNG combiner page container */
	$page: null,
	
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
		// Cache page selector for faster DOM lookups
		trngXorCombiner.$page = $('.trngCombinerPage');
		
		// Init
		trngXorCombiner.initResetButton();
		trngXorCombiner.initBrowseFilesButton();
		trngXorCombiner.initExportFileButton();
	},
	
	/**
	 * When files are uploaded
	 */
	initBrowseFilesButton: function()
	{
		// When the browse files button is clicked and files selected
		trngXorCombiner.$page.find('#fileLoader').change(function()
		{
			// Disable adding more files after files selected, they can use the Restart button
			trngXorCombiner.$page.find('#fileLoader').attr('disabled', true);
			trngXorCombiner.$page.find('#fileLoaderLabel').addClass('disabled');
			
			// Get the files
			var files = $(this)[0].files;
			var totalNumFiles = files.length;

			// Set for use later
			trngXorCombiner.totalNumFiles = totalNumFiles;

			// For every file
			for (var i = 0; i < files.length; i++)
			{
				// Load the file information
				trngXorCombiner.loadFileInformation(files[i]);
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
			var $row = trngXorCombiner.$page.find('.template').clone();
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
			$row.removeClass('template');
			$row.find('.fileName').text(fileName);
			$row.find('.fileSize').text(numLoadedBytesFormatted + ' Bytes');
			$row.find('.totalHexSymbols').text(numHexSymbolsLoadedFormatted);
			
			// If the first file, set it as the initial random data
			if (trngXorCombiner.numFilesLoaded === 0) {
				trngXorCombiner.allDataHex = loadedHexSymbols;
			}
			else {
				// Set the length of the current final data
				var previousLoadedDataLength = trngXorCombiner.allDataHex.length;
				
				// If the previous data is longer than the current data
				if (trngXorCombiner.allDataHex.length > numHexSymbolsLoaded)
				{
					// Truncate the previous data
					trngXorCombiner.allDataHex = trngXorCombiner.allDataHex.substr(0, numHexSymbolsLoaded);
				}
				
				// Otherwise if the recently loaded data length is more than the previous data loaded
				else if (numHexSymbolsLoaded > previousLoadedDataLength)
				{
					// Truncate the recently loaded data
					loadedHexSymbols = loadedHexSymbols.substr(0, previousLoadedDataLength);
				}				
				
				// Otherwise XOR the data to the previous data
				trngXorCombiner.allDataHex = common.xorHex(trngXorCombiner.allDataHex, loadedHexSymbols);
			}
			
			// Increment count of files loaded and add the row to the output
			trngXorCombiner.numFilesLoaded += 1;
			trngXorCombiner.rowHtml += $row.prop('outerHTML');			
			
			// If all the files are loaded
			if (trngXorCombiner.numFilesLoaded === trngXorCombiner.totalNumFiles)
			{
				// Enable other buttons and show the loaded files
				trngXorCombiner.$page.find('#btnRestart').removeAttr('disabled');
				trngXorCombiner.$page.find('#exportFile').removeAttr('disabled');
				trngXorCombiner.$page.find('.collectionAmounts.fileInfo').append(trngXorCombiner.rowHtml).show();
				
				// Find the number of hexadecimal symbols and bytes loaded
				var totalHexSymbolsLoaded = trngXorCombiner.allDataHex.length;
				var totalBytes = (totalHexSymbolsLoaded / 2);
				
				// If the number of bytes is not even
				if ((totalBytes % 2) !== 0)
				{
					// Slice a byte off the end so it is even, then NIST tests won't complain
					trngXorCombiner.allDataHex = trngXorCombiner.allDataHex.slice(0, -2);
					totalHexSymbolsLoaded = totalHexSymbolsLoaded - 2;
					totalBytes = totalBytes - 1;
				}
				
				// Format the total number of hexadecimal symbols, bytes and megabytes loaded
				var totalHexSymbolsLoadedFormatted = common.formatNumberWithCommas(totalHexSymbolsLoaded);
				var totalBytesFormatted = common.formatNumberWithCommas(totalBytes);
				var totalMegaBytes = (totalBytes / 1024 / 1024).toFixed(3);
				var totalMegaBytesFormatted = common.formatNumberWithCommas(totalMegaBytes);
				
				// Show final status
				common.showStatus('success',
				                  'All data loaded. '
								+ 'Total files: ' + trngXorCombiner.numFilesLoaded + '. '
								+ 'Total hex symbols: ' + totalHexSymbolsLoadedFormatted + '. '
				                + 'Total Bytes: ' + totalBytesFormatted + '. '
				                + 'Total MB: ' + totalMegaBytesFormatted
				                , true);
			}
		};
	},
			
	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset button click
		trngXorCombiner.$page.find('#btnRestart').click(function()
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
		trngXorCombiner.$page.find('#exportFile').click(function()
		{
			// Convert to hexadecimal then WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(trngXorCombiner.allDataHex);
			var outputBase64 = CryptoJS.enc.Base64.stringify(words);

			// Output the binary file and prompt the user to save it
			location.href = 'data:application/octet-stream;base64,' + outputBase64;
		});
	}
};