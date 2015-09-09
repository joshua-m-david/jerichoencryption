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

/**
 * Functionality to load the stored one-time pads into the program
 */
var importPads = {
	
	// Cached jQuery selector for this page
	$page: null,
	
	// Imported pad data to be processed
	padData: null,
	
	/**
	 * Initialise the page code
	 */
	init: function()
	{
		importPads.initLoadMethodChangeHandler();
		importPads.initImportPadsFromTextFile();
		importPads.initImportPadsFromClipboard();
		importPads.initImportKeyfileFromTextFile();
		importPads.initImportPadsButton();
	},
	
	/**
	 * When they change the method to load the pads, show the relevant section
	 */	
	initLoadMethodChangeHandler: function()
	{
		// Cache the selector
		importPads.$page = $('.importPadsPage');
		
		// When the select option changes
		importPads.$page.find('#importMethod').change(function()
		{
			// Get the selected method
			var selectedMethod = $(this).val();
			
			// Hide the other method and show the selected section
			importPads.$page.find('.importSettingsContainer').hide();
			importPads.$page.find('.method').hide();
			importPads.$page.find('.method.' + selectedMethod).show();
			
			// Reset Import button back to visible
			importPads.$page.find('.importButton').show();
			importPads.$page.find('.chatButton').hide();
		});
	},
			
	/**
	 * Load the one-time pads from a text file
	 */
	initImportPadsFromTextFile: function()
	{
		// After file is selected using the Browse button
		importPads.$page.find('#padFile').change(function(event)
		{
			// Get file information
			var files = event.target.files;
			var file = files[0];
			var fileInfo = file.name + ', ' + file.type + ', ' + file.size + ' bytes.';

			// Set to read from text file
			var reader = new FileReader();
			reader.readAsText(file);

			// Closure to read the file information
			reader.onload = (function()
			{
				return function(onLoadEvent)
				{
					// Send the JSON to be loaded to the database
					importPads.preparePadDataForImport(onLoadEvent.target.result, fileInfo);
				};
			})(file);
		});
	},
	
	/**
	 * Import the one-time pads from the clipboard
	 */
	initImportPadsFromClipboard: function()
	{
		// After the Load button is clicked
		importPads.$page.find('#loadPadsFromClipboard').click(function()
		{
			// Get pasted data
			var padDataJson = importPads.$page.find('#padDataClipboardInput').val();					
			
			// Make sure there is text
			if (padDataJson !== '')
			{
				// Send the JSON to be loaded to the database
				importPads.preparePadDataForImport(padDataJson);
			}
			else {
				common.showStatus('error', 'No pad data to load.');
			}
		});
	},
		
	/**
	 * Gets the data back from JSON format presets the pad information.
	 * If the iterations aren't set then let them enter the number of iterations manually.
	 * @param {String} padDataJson The encrypted one-time pad database and meta data in JSON format
	 * @param {String} fileInfo The file information if loaded from a file
	 */
	preparePadDataForImport: function(padDataJson, fileInfo)
	{
		// Show the file information if it is set
		fileInfo = (fileInfo) ? fileInfo : '';
		
		// Parse the serialized JSON data into a JavaScript object
		var padData = common.parseJson(padDataJson);
		
		// If the JSON is invalid show an error
		if (padData === false)
		{			
			common.showStatus('error', 'Could not parse the pad database. ' + fileInfo);
			return false;
		}
				
		// If the version doesn't exist then this database is too old
		if (typeof padData.programVersion === 'undefined')
		{
			common.showStatus('error', 'The version of your one-time pad database is not supported in this version.');
			return false;
		}
		
		// Validate the Keccak iterations
		if (importPads.validateAndLoadKeccakIterations(padData.crypto.pbkdfKeccakIterations) === false)
		{
			common.showStatus('error', 'The number of PBKDF Keccak iterations are invalid indicating the database has been corrupted or tampered with.');
			return false;
		}
		
		// Validate the Skein iterations
		if (importPads.validateAndLoadSkeinIterations(padData.crypto.pbkdfSkeinIterations) === false)
		{
			common.showStatus('error', 'The number of PBKDF Skein iterations are invalid indicating the database has been corrupted or tampered with.');
			return false;
		}
		
		// Validate the keyfile
		if (importPads.validateAndLoadKeyfile(padData.crypto.pbkdfSalt) === false)
		{
			common.showStatus('error', 'The keyfile is invalid indicating the database has been corrupted or tampered with.');
			return false;
		}
		
		// Store in memory for use when the user has entered passphrase and other details
		importPads.padData = padData;
						
		// Show the import and decryption settings, then hide the load pads option
		importPads.$page.find('.importSettingsContainer').show();
		importPads.$page.find('.method').hide();
		
		// Show success
		common.showStatus('success', 'One-time pad file data loaded successfully. ' + fileInfo);
	},
	
	/**
	 * Loads the Keccak iterations if they are set correctly
	 * @param {Number|null} pbkdfKeccakIterations The number of iterations or null if not remembered
	 * @returns {Boolean} Returns false if invalid or true if valid or null
	 */
	validateAndLoadKeccakIterations: function(pbkdfKeccakIterations)
	{
		// Because there's no way to add an invalid number of iterations via the user interface, if the number of 
		// iterations is not a valid integer then it's likely the pad database file is corrupt or tampered with.
		if ((pbkdfKeccakIterations !== null) && (/^[1-9]\d*$/.test(pbkdfKeccakIterations) === false))
		{			
			return false;
		}
		
		// If the number of iterations are set and it is a valid number
		else if (pbkdfKeccakIterations !== null)
		{
			// Cache references
			var $row = importPads.$page.find('.keccakIterationsRow');
			var $input = $row.find('#importPbkdfKeccakIterations');
			
			// Set the iterations and mark the text field as readonly
			$row.addClass('completed');
			$input.val(pbkdfKeccakIterations);
			$input.prop('readonly', true);
		}
		
		return true;
	},
	
	/**
	 * Loads the Skein iterations if they are set correctly
	 * @param {Number|null} pbkdfSkeinIterations The number of iterations or null if not remembered
	 * @returns {Boolean} Returns false if invalid or true if valid or null
	 */
	validateAndLoadSkeinIterations: function(pbkdfSkeinIterations)
	{
		// Because there's no way to add an invalid number of iterations via the user interface, if the number of 
		// iterations is not a valid integer then it's likely the pad database file is corrupt or tampered with.
		if ((pbkdfSkeinIterations !== null) && (/^[1-9]\d*$/.test(pbkdfSkeinIterations) === false))
		{
			common.showStatus('error', 'The number of PBKDF Skein iterations are invalid indicating the database has been corrupted or tampered with.');
			return false;
		}
		
		// If the number of iterations are set and it is a valid number
		else if (pbkdfSkeinIterations !== null)
		{
			// Cache references
			var $row = importPads.$page.find('.skeinIterationsRow');
			var $input = $row.find('#importPbkdfSkeinIterations');
			
			// Set the iterations and mark the text field as readonly
			$row.addClass('completed');
			$input.val(pbkdfSkeinIterations);
			$input.prop('readonly', true);
		}
		
		return true;
	},
	
	/**
	 * Loads the keyfile if it has been set correctly
	 * @param {String} pbkdfSalt The keyfile
	 * @returns {Boolean} Returns false if invalid or true if valid or null
	 */
	validateAndLoadKeyfile: function(pbkdfSalt)
	{
		// Because there's no way to add an invalid salt via the user interface, if the salt is not valid hex digits 
		// of the correct length then it's likely the pad database file is corrupt or tampered with.
		if ((pbkdfSalt !== null) && (/^[0-9A-F]{384}$/i.test(pbkdfSalt) === false))
		{
			common.showStatus('error', 'The keyfile is invalid indicating the database has been corrupted or tampered with.');
			return false;
		}
		
		// Otherwise if the salt is set and a valid string of hex
		else if (pbkdfSalt !== null)
		{
			// Cache references
			var $row = importPads.$page.find('.keyfileRow');
			var $input = $row.find('#importKeyfile');
			
			// Set the salt and mark the text field as readonly
			$row.addClass('completed');
			$input.val(pbkdfSalt);
			$input.prop('readonly', true);
		}		
		else {
			// Get the import method
			var method = importPads.$page.find('#importMethod').val();
			
			// If they chose to import the pads by text file they probably want to import the keyfile by the same method
			if (method === 'textFile')
			{
				// Hide the text box, show the Browse button for the keyfile
				importPads.$page.find('#importKeyfile').hide();
				importPads.$page.find('#importKeyfileFromTextFile').show();
			}
		}
		
		return true;
	},
	
	/**
	 * Load the keyfile from a text file
	 */
	initImportKeyfileFromTextFile: function()
	{
		var $browseKeyfileButton = importPads.$page.find('#importKeyfileFromTextFile');
		
		// After file is selected using the Browse button
		$browseKeyfileButton.change(function(event)
		{
			// Get file information
			var files = event.target.files;
			var file = files[0];
			var fileInfo = file.name + ', ' + file.type + ', ' + file.size + ' bytes';

			// Set to read from text file
			var reader = new FileReader();
			reader.readAsText(file);

			// Closure to read the file information
			reader.onload = (function()
			{
				return function(onLoadEvent)
				{
					// Get the keyfile data
					var keyfile = onLoadEvent.target.result;
					var $keyfileRow = importPads.$page.find('.keyfileRow');
					var $keyfileInput = $keyfileRow.find('#importKeyfile');
					
					// Check it is a valid keyfile format
					if (/^[0-9A-F]{384}$/i.test(keyfile) === false)
					{
						common.showStatus('error', 'The keyfile (' + fileInfo + ') is invalid indicating the database has been corrupted or tampered with.');
						return false;
					}
					
					// Set the keyfile hex digits to the text field and show it
					$keyfileRow.addClass('completed');
					$keyfileInput.val(keyfile);
					$keyfileInput.prop('readonly', true);
					$keyfileInput.show();
					
					// Show success message
					common.showStatus('success', 'The keyfile (' + fileInfo + ') was loaded successfully.');
					
					// Hide the Browse keyfile button
					$browseKeyfileButton.hide();
				};
			})(file);
		});
	},
	
	/**
	 * Initialise functionality for the main Import button
	 */
	initImportPadsButton: function()
	{
		// On Import button click
		importPads.$page.find('#importPads').click(function()
		{
			// Get pre-loaded or details entered manually
			var passphrase = importPads.$page.find('#importPassphrase').val();
			var keyfile = importPads.$page.find('#importKeyfile').val();
			var pbkdfKeccakIterations = importPads.$page.find('#importPbkdfKeccakIterations').val();
			var pbkdfSkeinIterations = importPads.$page.find('#importPbkdfSkeinIterations').val();
			
			// Check the passphrase was entered
			if (passphrase.length === 0)
			{
				common.showStatus('error', 'Please enter a passphrase for decryption.');
				return false;
			}
			
			// Test that the keyfile is a valid hex string of 1536 bits
			if (/^[0-9A-F]{384}$/i.test(keyfile) === false)
			{
				common.showStatus('error', 'The keyfile is invalid.');
				return false;
			}
			
			// Test that the number of Keccak iterations is a valid integer
			if (/^[1-9]\d*$/.test(pbkdfKeccakIterations) === false)
			{
				common.showStatus('error', 'The number of PBKDF Keccak iterations are invalid.');
				return false;
			}
			
			// Test that the number of Skein iterations is a valid integer
			if (/^[1-9]\d*$/.test(pbkdfSkeinIterations) === false)
			{
				common.showStatus('error', 'The number of PBKDF Skein iterations are invalid.');
				return false;
			}
			
			// Show log
			common.showStatus('processing', 'Running PBKDF to generate master key from the passphrase and keyfile.', true);
			
			// Setup the import PBKDF worker
			var worker = common.startWebWorker('import-pads-pbkdf-worker');

			// When the worker is complete
			worker.addEventListener('message', function(event)
			{
				// Continue to verify that the passphrase, keyfile and number of iterations were correct
				importPads.verifyDecryptionDetails(event.data);

			}, false);

			// Send data to the worker
			worker.postMessage({
				passphrase: passphrase,
				keyfile: keyfile,
				pbkdfKeccakIterations: pbkdfKeccakIterations,
				pbkdfSkeinIterations: pbkdfSkeinIterations
			});
		});
	},
	
	/**
	 * Verify that the derived encryption keys are correct and the authenticity of the actual database keys
	 * @param {Object} derivedKeys The derived sub keys 'aesKey', 'salsaKey', 'keccakMacKey', 'skeinMacKey'
	 */
	verifyDecryptionDetails: function(derivedKeys)
	{
		// Get the encrypted keys and MAC of the encrypted keys
		var encryptedKeys = importPads.padData.crypto.keys;
		var encryptedKeysMac = importPads.padData.crypto.keysMac;

		// Check if the passphrase, keyfile and number of iterations is correct
		var valid = dbCrypto.verifyMacOfDatabaseKeys(derivedKeys.keccakMacKey, derivedKeys.skeinMacKey, encryptedKeys, encryptedKeysMac);

		// If invalid then it's likely they have an invalid passphrase, keyfile and number of iterations
		// Alternatively the encrypted database keys or MAC could have been tampered with.
		if (valid === false)
		{
			common.showStatus('error', 'Verification failure. Check that the passphrase, keyfile and number of iterations are correct.');
			return false;
		}
		
		// Decrypt the database keys using the derived keys
		var dbKeys = dbCrypto.decryptDatabaseKeys(derivedKeys.aesKey, derivedKeys.salsaKey, encryptedKeys);

		// Otherwise decryption details are correct, continue as planed
		common.showStatus('processing', 'Database keys decrypted. Now decrypting remaining pad info.');
		
		// Verify and decrypt the database
		importPads.verifyAndDecryptDatabase(dbKeys.dbAesKey, dbKeys.dbSalsaKey, dbKeys.dbKeccakMacKey, dbKeys.dbSkeinMacKey);
	},
	
	/**
	 * Verify and decrypt the database
	 * @param {String} dbAesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} dbSalsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} dbKeccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} dbSkeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 */
	verifyAndDecryptDatabase: function(dbAesKey, dbSalsaKey, dbKeccakMacKey, dbSkeinMacKey)
	{		
		// Verify and decrypt the pad information
		var encryptedPadInfo = importPads.padData.info;
		var decryptedPadInfo = dbCrypto.verifyAndDecryptPadInfo(dbAesKey, dbSalsaKey, dbKeccakMacKey, dbSkeinMacKey, encryptedPadInfo);
		
		// If the MAC did not verify, show an error
		if (decryptedPadInfo === false)
		{
			common.showStatus('error', 'Verification and decryption of pad info failed. Tampering or corruption may have occurred.');
			return false;
		}
		
		// Set the decrypted pad info to the main object
		importPads.padData.info = decryptedPadInfo;
		
		// Setup the verify and decrypt worker
		var worker = common.startWebWorker('import-pads-verify-and-decrypt-worker');

		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			// Display results of verification and decryption
			importPads.completeImportProcess(event.data);

		}, false);

		// Send data to the worker
		worker.postMessage({
			dbAesKey: dbAesKey,
			dbSalsaKey: dbSalsaKey,
			dbKeccakMacKey: dbKeccakMacKey,
			dbSkeinMacKey: dbSkeinMacKey,
			padData: importPads.padData
		});
	},
	
	/**
	 * Completes the import process. Will load the decrypted pads if successfully 
	 * decrypted and also show a button to let the user continue to the chat.
	 * @param {type} workerResults
	 * @returns {Boolean}
	 */
	completeImportProcess: function(workerResults)
	{
		// Get the results from the worker
		var validIndex = workerResults.validIndex;
		var decryptedPads = workerResults.decryptedPads;
		
		// If the MAC did not verify, show an error
		if (validIndex === false)
		{
			common.showStatus('error', 'Verification of the pad database indexes failed. Tampering may have occurred.');
			return false;
		}
				
		// If the pads did not verify or decrypt successfully, show an error
		if (decryptedPads === false)
		{
			common.showStatus('error', 'Verification of the pads and decryption failed. Tampering may have occurred.');
			return false;
		}
		
		// Replace encrypted pads with the decrypted ones, then load pads into memory
		importPads.padData.pads = decryptedPads;
		db.padData = importPads.padData;

		// Save to the database
		db.savePadDataToDatabase();
		common.showStatus('success', 'One-time pads are verified, decrypted and loaded. You should now erase the original text file containing the one-time pads. After this you can begin chatting.', true);

		// Hide the import button and dhow a link to the chat page now that the pads are loaded
		importPads.$page.find('.importButton').hide();
		importPads.$page.find('.chatButton').show();
	}
};