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

/**
 * Functionality to load the stored one-time pads into the program
 */
var importPage = {

	// Imported pad data to be processed
	padData: null,

	/**
	 * Initialise the page code
	 */
	init: function()
	{
		importPage.initLoadMethodChangeHandler();
		importPage.initImportPadsFromTextFile();
		importPage.initImportPadsFromClipboard();
		importPage.initImportKeyfileFromTextFile();
		importPage.initEnterKeyWhileInPasswordField();
		importPage.initImportPadsButton();
	},

	/**
	 * When they change the method to load the pads, show the relevant section
	 */
	initLoadMethodChangeHandler: function()
	{
		// When the select option changes
		query.getCached('.jsImportMethod').on('change', function()
		{
			// Get the selected method
			var selectedMethod = $(this).val();

			// Hide the other method and show the selected section
			query.getCached('.jsImportSettingsContainer').hide();
			query.getCached('.jsMethod').hide();
			query.getCached('.jsMethod.' + selectedMethod).show();

			// Reset Import button back to visible
			query.getCached('.jsImportButtonContainer').show();
			query.getCached('.jsChatButtonContainer').hide();
		});
	},

	/**
	 * Load the one-time pads from a text file
	 */
	initImportPadsFromTextFile: function()
	{
		// After file is selected using the Browse button
		query.getCached('.jsPadFile').on('change', function(event)
		{
			// Get file information
			var files = event.target.files;
			var file = files[0];
			var fileInfo = file.name + ', ' + file.type + ', ' + file.size + ' bytes.';
			var reader = new FileReader();

			// Set to read from text file
			reader.readAsText(file);

			// Closure to read the file information
			reader.onload = (function()
			{
				return function(onLoadEvent)
				{
					// Send the JSON to be loaded to the database
					importPage.preparePadDataForImport(onLoadEvent.target.result, fileInfo);
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
		query.getCached('.jsLoadPadsFromClipboardButton').on('click', function()
		{
			// Get pasted data
			var padDataJson = query.getCached('.jsPadDataClipboardInput').val();

			// Make sure there is text
			if (padDataJson !== '')
			{
				// Send the JSON to be loaded to the database
				importPage.preparePadDataForImport(padDataJson);
			}
			else {
				app.showStatus('error', 'No pad data to load.');
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
			app.showStatus('error', 'Could not parse the pad database. ' + fileInfo);
			return false;
		}

		// If the version doesn't exist then this database is too old
		if (typeof padData.programVersion === 'undefined')
		{
			app.showStatus('error', 'The version of your one-time pad database is not supported in this version.');
			return false;
		}

		// Validate the Keccak iterations
		if (importPage.validateAndLoadKeccakIterations(padData.crypto.pbkdfKeccakIterations) === false)
		{
			app.showStatus('error', 'The number of PBKDF Keccak iterations are invalid indicating '
			                      + 'the database has been corrupted or tampered with.');
			return false;
		}

		// Validate the Skein iterations
		if (importPage.validateAndLoadSkeinIterations(padData.crypto.pbkdfSkeinIterations) === false)
		{
			app.showStatus('error', 'The number of PBKDF Skein iterations are invalid indicating '
			                      + 'the database has been corrupted or tampered with.');
			return false;
		}

		// Validate the keyfile
		if (importPage.validateAndLoadKeyfile(padData.crypto.pbkdfSalt) === false)
		{
			app.showStatus('error', 'The keyfile is invalid indicating the database has been corrupted or tampered with.');
			return false;
		}

		// Store in memory for use when the user has entered passphrase and other details
		importPage.padData = padData;

		// Show the import and decryption settings, then hide the load pads option
		query.getCached('.jsImportSettingsContainer').show();
		query.getCached('.jsMethod').hide();

		// Show success
		app.showStatus('success', 'One-time pad file data loaded successfully. ' + fileInfo);
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
			// Set colour of the text to grey to appear as completed / uneditable
			query.getCached('.jsKeccakIterationsRow').addClass('completed');

			// Set the iterations and mark the text field as readonly
			query.getCached('.jsImportPbkdfKeccakIterations')
					.val(pbkdfKeccakIterations)
					.prop('readonly', true);
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
			app.showStatus('error', 'The number of PBKDF Skein iterations are invalid indicating '
			                      + 'the database has been corrupted or tampered with.');
			return false;
		}

		// If the number of iterations are set and it is a valid number
		else if (pbkdfSkeinIterations !== null)
		{
			// Set colour of the text to grey to appear as completed / uneditable
			query.getCached('.jsSkeinIterationsRow').addClass('completed');

			// Set the iterations and mark the text field as readonly
			query.getCached('.jsImportPbkdfSkeinIterations')
					.val(pbkdfSkeinIterations)
					.prop('readonly', true);
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
			app.showStatus('error', 'The keyfile is invalid indicating the database has been corrupted or tampered with.');
			return false;
		}

		// Otherwise if the salt is set and a valid string of hex
		else if (pbkdfSalt !== null)
		{
			// Set colour of the text to grey to appear as completed / uneditable
			query.getCached('.jsKeyfileRow').addClass('completed');

			// Set the salt and mark the text field as readonly
			query.getCached('.jsImportKeyfileText')
					.val(pbkdfSalt)
					.prop('readonly', true);
		}
		else {
			// Get the import method
			var method = query.getCached('.jsImportMethod').val();

			// If they chose to import the pads by text file they probably want to import the keyfile by the same method
			if (method === 'textFile')
			{
				// Hide the text box, show the Browse button for the keyfile
				query.getCached('.jsImportKeyfileText').hide();
				query.getCached('.jsImportKeyfileFromTextFileButton').show();
			}
		}

		return true;
	},

	/**
	 * Load the keyfile from a text file
	 */
	initImportKeyfileFromTextFile: function()
	{
		// After file is selected using the Browse button
		query.getCached('.jsImportKeyfileFromTextFileButton').on('change', function(event)
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

					// Check it is a valid keyfile format
					if (/^[0-9A-F]{384}$/i.test(keyfile) === false)
					{
						app.showStatus('error', 'The keyfile (' + fileInfo + ') is invalid indicating the '
						                      + 'database has been corrupted or tampered with.');
						return false;
					}

					// Set the keyfile hex digits to the text field and show it
					query.getCached('.jsKeyfileRow').addClass('completed');
					query.getCached('.jsImportKeyfileText')
							.val(keyfile)
							.prop('readonly', true)
							.show();

					// Show success message
					app.showStatus('success', 'The keyfile (' + fileInfo + ') was loaded successfully.');

					// Hide the Browse keyfile button
					query.getCached('.jsImportKeyfileFromTextFileButton').hide();
				};
			})(file);
		});
	},

	/**
	 * Initialise the Enter key to click the Import button when pressed
	 */
	initEnterKeyWhileInPasswordField: function()
	{
		query.getCached('.jsImportPassphraseText').on('keyup', function(event)
		{
			// If the enter key is clicked
			if (event.keyCode === common.keyCodes.enter) {
				query.getCached('.jsImportPadsButton').trigger('click');
			}
		});
	},

	/**
	 * Initialise functionality for the main Import button
	 */
	initImportPadsButton: function()
	{
		// On Import button click
		query.getCached('.jsImportPadsButton').on('click', function()
		{
			// If already processing, wait for that to finish
			if ($(this).hasClass('isDisabled'))
			{
				return false;
			}

			// Get pre-loaded or details entered manually
			var passphrase = query.getCached('.jsImportPassphraseText').val();
			var keyfile = query.getCached('.jsImportKeyfileText').val();
			var pbkdfKeccakIterations = query.getCached('.jsImportPbkdfKeccakIterations').val();
			var pbkdfSkeinIterations = query.getCached('.jsImportPbkdfSkeinIterations').val();

			// Check the passphrase was entered
			if (passphrase.length === 0)
			{
				app.showStatus('error', 'Please enter a passphrase for decryption.');
				return false;
			}

			// Test that the keyfile is a valid hex string of 1536 bits
			if (/^[0-9A-F]{384}$/i.test(keyfile) === false)
			{
				app.showStatus('error', 'The keyfile is invalid.');
				return false;
			}

			// Test that the number of Keccak iterations is a valid integer
			if (/^[1-9]\d*$/.test(pbkdfKeccakIterations) === false)
			{
				app.showStatus('error', 'The number of PBKDF Keccak iterations are invalid.');
				return false;
			}

			// Test that the number of Skein iterations is a valid integer
			if (/^[1-9]\d*$/.test(pbkdfSkeinIterations) === false)
			{
				app.showStatus('error', 'The number of PBKDF Skein iterations are invalid.');
				return false;
			}

			// Disable the button
			$(this).addClass('isDisabled');

			// Show log
			app.showStatus('processing', 'Running PBKDF to generate master key from the passphrase and keyfile.', true);

			// Setup the import PBKDF worker
			var worker = common.startWebWorker('import-pads-pbkdf-worker');

			// When the worker is complete
			worker.addEventListener('message', function(event)
			{
				// Continue to verify that the passphrase, keyfile and number of iterations were correct
				importPage.verifyDecryptionDetails(event.data);

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
		var encryptedKeys = importPage.padData.crypto.keys;
		var encryptedKeysMac = importPage.padData.crypto.keysMac;

		// Check if the passphrase, keyfile and number of iterations is correct
		var valid = dbCrypto.verifyMacOfDatabaseKeys(derivedKeys.keccakMacKey, derivedKeys.skeinMacKey, encryptedKeys, encryptedKeysMac);

		// If invalid then it's likely they have an invalid passphrase, keyfile and number of iterations
		// Alternatively the encrypted database keys or MAC could have been tampered with.
		if (valid === false)
		{
			// Undisable the button
			query.getCached('.jsImportPadsButton').removeClass('isDisabled');

			// Show an error
			app.showStatus('error', 'Verification failure. Check that the passphrase, keyfile and number of iterations are correct.');
			return false;
		}

		// Decrypt the database keys using the derived keys
		var dbKeys = dbCrypto.decryptDatabaseKeys(derivedKeys.aesKey, derivedKeys.salsaKey, encryptedKeys);

		// Otherwise decryption details are correct, continue as planed
		app.showStatus('processing', 'Database keys decrypted. Now decrypting remaining pad info.');

		// Verify and decrypt the database
		importPage.verifyAndDecryptDatabase(dbKeys.dbAesKey, dbKeys.dbSalsaKey, dbKeys.dbKeccakMacKey, dbKeys.dbSkeinMacKey);
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
		var encryptedPadInfo = importPage.padData.info;
		var decryptedPadInfo = dbCrypto.verifyAndDecryptPadInfo(dbAesKey, dbSalsaKey, dbKeccakMacKey, dbSkeinMacKey, encryptedPadInfo);

		// If the MAC did not verify, show an error
		if (decryptedPadInfo === false)
		{
			app.showStatus('error', 'Verification and decryption of pad info failed. Tampering or corruption may have occurred.');
			return false;
		}

		// Set the decrypted pad info to the main object
		importPage.padData.info = decryptedPadInfo;

		// Setup the verify and decrypt worker
		var worker = common.startWebWorker('import-pads-verify-and-decrypt-worker');

		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			// Display results of verification and decryption
			importPage.completeImportProcess(event.data);

		}, false);

		// Send data to the worker
		worker.postMessage({
			dbAesKey: dbAesKey,
			dbSalsaKey: dbSalsaKey,
			dbKeccakMacKey: dbKeccakMacKey,
			dbSkeinMacKey: dbSkeinMacKey,
			padData: importPage.padData
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
			app.showStatus('error', 'Verification of the pad database indexes failed. Tampering may have occurred.');
			return false;
		}

		// If the pads did not verify or decrypt successfully, show an error
		if (decryptedPads === false)
		{
			app.showStatus('error', 'Verification of the pads and decryption failed. Tampering may have occurred.');
			return false;
		}

		// Replace encrypted pads with the decrypted ones, then load pads into memory
		importPage.padData.pads = decryptedPads;
		db.padData = importPage.padData;

		// Save to the database
		db.savePadDataToDatabase();
		app.showStatus('success', 'One-time pads are verified, decrypted and loaded. You should now erase the original text file '
		                        + 'containing the one-time pads. After this you can begin chatting.', true);

		// Hide the import button and dhow a link to the chat page now that the pads are loaded
		query.getCached('.jsImportButtonContainer').hide();
		query.getCached('.jsChatButtonContainer').show();
	},

	/**
	 * Page cleanup function to be run when the user leaves the page
	 */
	cleanup: function()
	{
		// Pre-select the default drop down option of loading from text file
		query.getCached('.jsImportMethod option:first-child').prop('selected', true);

		// Show the text file import method and hide the clipboard method
		query.getCached('.jsMethod.textFile').show();
		query.getCached('.jsMethod.clipboard').hide();

		// Hide the import settings container where all the passphrase, keyfile, PBKDF iterations were displayed
		query.getCached('.jsImportSettingsContainer').hide();

		// Unselect the file that was selected
		query.getCached('.jsPadFile').val('');

		// Clear the password, keyfile and PBKDF iterations that were entered
		query.getCached('.jsImportPassphraseText').val('');
		query.getCached('.jsImportKeyfileText').val('');
		query.getCached('.jsImportPbkdfKeccakIterations').val('');
		query.getCached('.jsImportPbkdfSkeinIterations').val('');

		// Clear the text input for the clipboard entry option
		query.getCached('.jsPadDataClipboardInput').val('');

		// Reset Import button back to visible and hide the Go to chat button
		query.getCached('.jsImportPadsButton').removeClass('isDisabled');
		query.getCached('.jsImportButtonContainer').show();
		query.getCached('.jsChatButtonContainer').hide();

		// Remove temporary store for imported data (either they cancelled the process or it's now in the local database)
		importPage.padData = null;
	}
};