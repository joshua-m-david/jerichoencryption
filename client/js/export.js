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
 * Functions to export the one-time pads for transport or randomness testing by external programs
 */
var exportPads = {
	
	$exportDialog: null,
	
	/**
	 * Configure the Export Pads dialog to open and all functionality within
	 */
	initExportPadsDialog: function()
	{
		// Cache to prevent extra DOM lookups
		exportPads.$exportDialog = $('#exportPadsSettings');
		
		// Configure button to open export dialog
		$('#btnOpenExportPadsSettings').click(function()
		{
			// Hide previous status messages and open the dialog
			common.hideStatus();
			exportPads.$exportDialog.dialog('open');
		});

		// Configure entropy collection settings dialog
		exportPads.$exportDialog.dialog(
		{
			autoOpen: false,
			create: function (event)
			{
				// Set the dialog position as fixed before opening the dialog. See: http://stackoverflow.com/a/6500385
				$(event.target).parent().css('position', 'fixed');
			},
			modal: true,
			resizable: false,
			width: 500
		});
				
		// Initialise other functionality within the dialog
		this.dynamicallySetNicknameTextEntry();
		this.hideOptionsDependingOnExportMethod();
		this.initCreateServerKeyButton();
		this.initDisplayPasswordCheckbox();
		this.initExportPadsButton();
		this.initTestServerConnectionButton();
		this.initPassphraseStrengthCalculator();
	},
	
	/**
	 * Repositions the export dialog to the center of the window because some options
	 * e.g. number of users or export method change the amount of information in the dialog
	 */
	repositionDialogToCenter: function()
	{		
		exportPads.$exportDialog.dialog('option', 'position', { my : 'center', at: 'center', of: window });
	},
	
	/**
	 * When the number of users changes, enable/disable options in the Export for user 
	 * select box and dynamically alter the number of user nicknames they can enter
	 */
	dynamicallySetNicknameTextEntry: function()
	{		
		$('#numOfUsers').change(function()
		{
			// Get the number of users
			var numOfUsers = parseInt($(this).val());
			var nicknames = '';

			// Build list of users so the user can edit the user nicknames
			for (var i=0; i < numOfUsers; i++)
			{
				// Build the HTML to be rendered inside the dialog
				var nicknameCapitalised = common.capitaliseFirstLetter(common.userList[i]);
				nicknames += '<label>' + nicknameCapitalised + '</label> '
						  +  '<input id="nickname-' + common.userList[i] + '" type="text" maxlength="12" value="' + nicknameCapitalised + '"><br>';
			}

			// Display the options
			$('.nicknames').html(nicknames);
			
			// Reposition the dialog to center of screen
			exportPads.repositionDialogToCenter();
		});
	},
	
	/**
	 * Hide or show the last option in the dialog if the export method is changed
	 */
	hideOptionsDependingOnExportMethod: function()
	{
		// On dropdown change
		exportPads.$exportDialog.find('#exportMethod').change(function()
		{
			var exportMethod = $(this).val();		

			// If the pads will be exported for actual use show the Export for User option
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard'))
			{
				exportPads.$exportDialog.find('.helpExplanation .oneTimePads').show();
				exportPads.$exportDialog.find('.helpExplanation .randomData').hide();
				exportPads.$exportDialog.find('.serverDetails').show();
				exportPads.$exportDialog.find('.chatGroupDetails').show();
				exportPads.$exportDialog.find('.databaseEncryptionPassword').show();
				exportPads.$exportDialog.find('.advancedOptions').show();
				exportPads.$exportDialog.find('#btnExportPads').val('3. Export one-time pads');
			}
			else {
				// Otherwise export for testing so hide the one-time pad export options
				exportPads.$exportDialog.find('.helpExplanation .oneTimePads').hide();
				exportPads.$exportDialog.find('.helpExplanation .randomData').show();
				exportPads.$exportDialog.find('.serverDetails').hide();
				exportPads.$exportDialog.find('.chatGroupDetails').hide();
				exportPads.$exportDialog.find('.databaseEncryptionPassword').hide();
				exportPads.$exportDialog.find('.advancedOptions').hide();
				exportPads.$exportDialog.find('#btnExportPads').val('3. Export random data');
			}
			
			// Reposition the dialog to center of screen
			exportPads.repositionDialogToCenter();
		});
	},
		
	/**
	 * Creates a 512 bit server key from the random, extracted 
	 * data and puts it in the export dialog's text field
	 */
	initCreateServerKeyButton: function()
	{
		$('#btnCreateServerKey').click(function()
		{
			// Check there is enough data to create a 512 bit key (128 hexadecimal symbols)
			if (common.randomDataHexadecimal.length < 128)
			{
				common.showStatus('error', 'Not enough bits remaining to create a full 512 bit key.', true);
			}
			else {
				// Take the first 512 bits of the extracted data and convert it to hexadecimal
				var serverKeyHex = common.randomDataHexadecimal.slice(0, 128);

				// After removing the first 512 bits, use the remainder of the bits for the one-time pads
				common.randomDataHexadecimal = common.randomDataHexadecimal.slice(128);

				// Put it in the text field
				$('#serverKey').val(serverKeyHex);
			}
		});
	},
	
	/**
	 * If the user clicks the 'Display password' checkbox show the password as typed.
	 * This is a convenience function for the user so they can check it was typed correctly.
	 */
	initDisplayPasswordCheckbox: function()
	{
		$('#displayPassword').change(function()
		{
			if ($(this).is(':checked'))
			{
				// Set to regular text box
				$('#passphrase').attr('type', 'text');
				$('#passphraseRepeat').attr('type', 'text');
			}
			else {
				// Set to password box with asterisks for each char
				$('#passphrase').attr('type', 'password');
				$('#passphraseRepeat').attr('type', 'password');
			}
		});
	},
	
	/**
	 * Initialise the button to export the one-time pads or random data for external testing
	 */
	initExportPadsButton: function()
	{
		// Export the pads
		$('#btnExportPads').click(function()
		{
			// Get the selected export method
			var exportMethod = $('#exportMethod').val();

			// Export to text, file or database depending on user selection
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard'))
			{
				// Get data from the dialog
				var exportOptions = exportPads.getAndValidateInputs();
				
				// If no validation errors
				if (exportOptions !== false)				
				{
					// Show processing message
					common.showStatus('processing', 'Creating and encrypting the one-time pads...', true);
			
					// Create, encrypt and export the one-time pads
					exportPads.preparePadsForExport(exportOptions, common.randomDataHexadecimal);
				}
			}
			else {
				// Otherwise export the random data for testing using external methods
				exportPads.prepareRandomDataForExternalTesting(exportMethod, common.randomDataHexadecimal);
			}
		});
	},
		
	/**
	 * Exports the random data to the clipboard in various formats or to a binary file
	 * @param {String} exportMethod How to export the data e.g. 'testExportBase64', 'testExportHexadecimal', 'testExportBinaryFile' or 'testExportBinaryString'
	 * @param {String} extractedRandomDataHexadecimal The extracted entropy bits in hexadecimal
	 */
	prepareRandomDataForExternalTesting: function(exportMethod, extractedRandomDataHexadecimal)
	{
		// Instructions for the popup prompt
		var instructions = 'Copy to clipboard (Ctrl + C) then paste into a plain text file';

		// Export to Base 64
		if (exportMethod.indexOf('Base64') !== -1)
		{
			// Convert to WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(extractedRandomDataHexadecimal);
			var output = CryptoJS.enc.Base64.stringify(words);
			
			// Export the Base64 to a dialog which lets the user copy from there to a text file
			window.prompt(instructions, output);
		}
		
		// Export to hexadecimal string
		else if (exportMethod.indexOf('Hexadecimal') !== -1)
		{			
			window.prompt(instructions, extractedRandomDataHexadecimal);
		}
		
		// Export to binary file
		else if (exportMethod.indexOf('BinaryFile') !== -1)
		{
			// Convert to hexadecimal then WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(extractedRandomDataHexadecimal);
			var output = CryptoJS.enc.Base64.stringify(words);
			
			// Output the binary file for the user to save
			location.href = 'data:application/octet-stream;base64,' + output;
		}
	},
	
	/**
	 * Gets the data from the export dialog and validates it
	 * @returns {Boolean|Object} Returns false if invalid, or the data entered into the dialog
	 */
	getAndValidateInputs: function()
	{
		// Get data from the dialog inputs
		var options = {
			exportMethod: exportPads.$exportDialog.find('#exportMethod').val(),
			
			// Server details
			serverAddressAndPort: exportPads.$exportDialog.find('#serverAddressAndPort').val(),
			serverKey: exportPads.$exportDialog.find('#serverKey').val().toLowerCase(),
			
			// Chat group details
			numOfUsers: parseInt(exportPads.$exportDialog.find('#numOfUsers').val()),
			userNicknames: {},
			
			// Database encryption password
			passphrase: exportPads.$exportDialog.find('#passphrase').val(),
			passphraseRepeat: exportPads.$exportDialog.find('#passphraseRepeat').val(),
						
			// Advanced options			
			createSeparateKeyfile: exportPads.$exportDialog.find('#storeKeyfileSeparately').is(':checked'),
			enterPbkdfIterationsOnDecrypt: exportPads.$exportDialog.find('#enterPbkdfIterationsOnDecrypt').is(':checked'),
			pbkdfKeccakIterations: exportPads.$exportDialog.find('#pbkdfKeccakIterations').val(),
			pbkdfSkeinIterations: exportPads.$exportDialog.find('#pbkdfSkeinIterations').val()
		};
		
		// Validate the server key is hex and correct length (in case they entered it themselves)
		if ((/^[0-9A-F]{128}$/i.test(options.serverKey) === false))
		{
			common.showStatus('error', 'Server key must be a hex string of 512 bits (128 hex symbols).', true);
			return false;
		}
		
		// Validate that they entered something for the the passphrase
		else if (!options.passphrase || !options.passphraseRepeat)
		{
			common.showStatus('error', 'The OTP database must be encrypted, please enter a passphrase.', true);
			return false;
		}
		
		// Validate that the passphrases match
		else if (options.passphrase !== options.passphraseRepeat)
		{
			common.showStatus('error', 'Passwords do not match, please re-enter.', true);
			return false;
		}
		
		// Check that the number of iterations is a valid integer and at least 1 iteration each
		else if ((/^[1-9]\d*$/.test(options.pbkdfKeccakIterations) === false) || (/^[1-9]\d*$/.test(options.pbkdfSkeinIterations) === false))
		{
			common.showStatus('error', 'The number of iterations must be an integer of at least 1.', true);
			return false;
		}
		
		// Check that the random data generated has enough for the salt and at least 1 message
		else if (common.randomDataHexadecimal.length < (common.saltLengthHex + common.totalPadSizeHex))
		{
			common.showStatus('error', 'Not enough random data generated.', true);
			return false;
		}
		
		// Loop through the number of users
		for (var i = 0; i < options.numOfUsers; i++)
		{
			// Get the user, nickname, then filter the nickname field so only A-z and 0-9 characters allowed
			var user = common.userList[i];
			var nickname = exportPads.$exportDialog.find('#nickname-' + user).val();
				nickname = nickname.replace(/[^A-Za-z0-9]/g, '');
			
			// If the nickname field has nothing, then use the default user name e.g. Alpha, Bravo
			if (nickname === '')
			{
				// Capitalise the default user
				nickname = user;
				nickname = common.capitaliseFirstLetter(nickname);
			}
			
			// Store the nickname as a key next to the user
			options.userNicknames[user] = nickname;
		}
		
		return options;
	},
		
	/**
	 * Test the server connection when the button is clicked
	 */
	initTestServerConnectionButton: function()
	{						
		$('#testServerConnection').click(function()
		{
			// Get values from text inputs
			var serverAddressAndPort = $('#serverAddressAndPort').val();
			var serverKey = $('#serverKey').val();

			// Check connection and show success or failure message on screen
			common.testServerConnection(serverAddressAndPort, serverKey, function()
			{
				// Reposition the dialog to center of screen if there is a long error message
				exportPads.repositionDialogToCenter();				
			});
		});
	},
		
	/**
	 * Create the one-time pads from the collected and extracted entropy
	 * @param {Number} numOfUsers The number of users in the group ie. 2, 3, 4, 5, 6, 7
	 * @param {String} randomDataHexadecimal A string of hexadecimal random data
	 * @return {Object} Returns an object containing an array of pads for each user
	 */
	createPads: function(numOfUsers, randomDataHexadecimal)
	{
		var pads = {};
		
		// Initialise an empty array of pads for each user
		for (var i = 0; i < numOfUsers; i++)
		{
			// Get the user e.g. 'alpha', 'bravo' etc and set that as the key to hold the pads
			var userCallSign = common.userList[i];
			pads[userCallSign] = [];
		}
		
		// Counters for loop
		var padNumber = 0;
		var currentUserIndex = 0;
		var currentUserCallSign = common.userList[currentUserIndex];	// 'alpha'
		var currentNumOfPadsPerUser = 0;
		
		// Work out the number of pads each user will get roughly
		var randomDataLength = randomDataHexadecimal.length;
		var numOfPads = Math.floor(randomDataLength / common.totalPadSizeHex);
		var numOfPadsPerUser = Math.floor(numOfPads / numOfUsers);		
				
		// Loop through all the entropy hexadecimal chars
		for (var i = 0; i < randomDataLength; i += common.totalPadSizeHex)
		{
			// Get the random hex digits for the pad
			var pad = randomDataHexadecimal.substr(i, common.totalPadSizeHex);
			var padIdentifier = pad.substr(0, common.padIdentifierSizeHex);
			
			// If near the end of the string and there's not enough for one more pad, don't use the remainder
			if (pad.length < common.totalPadSizeHex)
			{
				break;
			}
			
			// The pad number is used as the row level encryption nonce for AES-CTR and Salsa20 so don't create more 
			// pads than the maximum safe integer size in JavaScript (9007199254740991 or 2^53 - 1)
			if (padNumber > Number.MAX_SAFE_INTEGER)
			{
				break;
			}
			
			// Store the pad in an object that can be easily retrieved later
			var padInfo = {
				padNum: padNumber,				// The number of the pad, this will also be used as the nonce for Salsa20 and AES-CTR				
				padIdentifier: padIdentifier,	// A copy of the first x characters of the pad to identify which pad to use, separated for faster DB lookup
				pad: pad						// The full pad including pad identifier
			};
			
			// Add to array of pads for this user
			pads[currentUserCallSign].push(padInfo);
			
			// Update counters for next loop
			currentNumOfPadsPerUser++;
			padNumber++;
			
			// Change to adding pads for the next user when the current user has the allocated number of pads. 
			// If there are any remaining pads over the average they will be added to the last user.
			if ((currentUserIndex !== numOfUsers - 1) && (currentNumOfPadsPerUser === numOfPadsPerUser))
			{
				currentUserIndex++;
				currentUserCallSign = common.userList[currentUserIndex];
				currentNumOfPadsPerUser = 0;				
			}
		}
		
		return pads;
	},
	
	/**
	 * Export the pads to either clipboard, textfile or to the local machine database for each user.
	 * Each user gets allocated their own one-time pads for sending. This prevents each user from using 
	 * each other's pads which could cause them to use a pad more than once. If a one-time pad is used more 
	 * than once then cryptanalysis is possible.
	 * @param {Object} options An object containing the export options on the export dialog
	 * @param {String} extractedRandomDataHex The random data as a hexadecimal string
	 */
	preparePadsForExport: function(options, extractedRandomDataHex)
	{			
		// Setup the export worker
		var worker = common.startWebWorker('export-pads-worker');
				
		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			exportPads.completePadsExport(options, event.data);
		
		}, false);
		
		// Send data to the worker
		worker.postMessage({
			options: options,
			extractedRandomDataHex: extractedRandomDataHex
		});
	},

	/**
	 * Complete the export of the one-time pads after the web worker
	 * @param {Object} options An object containing the export options on the export dialog
	 * @param {Object} workerData The keys and encrypted data from the web worker
	 */
	completePadsExport: function(options, workerData)
	{
		// Get the results from the worker
		var salt = workerData.salt;
		var aesKey = workerData.aesKey;
		var salsaKey = workerData.salsaKey;
		var keccakMacKey = workerData.keccakMacKey;
		var skeinMacKey = workerData.skeinMacKey;
		var encryptedPads = workerData.encryptedPads;
		var encryptedDatabaseKeysAndMac = workerData.encryptedDatabaseKeysAndMac;
		var padIndexMacs = workerData.padIndexMacs;
				
		// Clone database scheme
		var padData = db.clone(db.padDataSchema);
				
		// Set the database values
		padData.crypto.keys = encryptedDatabaseKeysAndMac.keysHex;
		padData.crypto.keysMac = encryptedDatabaseKeysAndMac.macHex;
		padData.crypto.padIndexMacs = padIndexMacs;
		
		// If they don't want to enter the number of PBKDF iterations at decryption time, then store the iterations with the pads
		if (options.enterPbkdfIterationsOnDecrypt === false) {
			padData.crypto.pbkdfKeccakIterations = options.pbkdfKeccakIterations;
			padData.crypto.pbkdfSkeinIterations = options.pbkdfSkeinIterations;
		}
		
		// If they don't want a separate keyfile, store the salt with the pads
		if (options.createSeparateKeyfile === false) {
			padData.crypto.pbkdfSalt = salt;
		}
		else {
			// Otherwise export the keyfile to clipboard or separate text file
			this.exportKeyfile(salt, options.exportMethod);
		}
		
		// Set more database values
		padData.info.serverAddressAndPort = options.serverAddressAndPort;
		padData.info.serverKey = options.serverKey;
		padData.info.userNicknames = options.userNicknames;
		padData.pads = encryptedPads;
		
		// Store which version the pads were created with. For future versions of the program, this will aid in 
		// decrypting old pad databases by knowing which format or structure the database is in prior to importing.
		padData.programVersion = common.programVersion;
		
		// Loop through each user
		for (var userCallSign in options.userNicknames)
		{
			// The current property is not a direct property so skip
			if (!options.userNicknames.hasOwnProperty(userCallSign))
			{
				continue;				
			}
			
			// Clone the pad data object for each user so we don't accidentally overwrite the plaintext pad data info 
			// with the encrypted pad data info in each loop, otherwise subsequent loops would add additional layers 
			// of encryption and make the pad data info unreadable for anyone but the first user.
			var userPadData = db.clone(padData);
			
			// Set the user so each loop will export pads under a different user then there is no 
			// accidental pad re-use from users using the same pads. Then encrypt and MAC the pad info.
			userPadData.info.user = userCallSign;
			userPadData.info = dbCrypto.encryptAndMacPadInfo(aesKey, salsaKey, keccakMacKey, skeinMacKey, userPadData.info);
			
			// Convert to JSON for export to clipboard or text file
			var userPadDataJson = JSON.stringify(userPadData);
			var userNickname = options.userNicknames[userCallSign];
			
			// Export to a dialog which lets the user copy from there to a text file
			if (options.exportMethod === 'clipboard')
			{
				this.exportPadsToClipboard(userPadDataJson, userNickname);			
			}
			else {
				this.exportPadsToTextFile(userPadDataJson, userNickname);
			}
		}
		
		// Show processing message
		common.showStatus('success', 'Creation and encryption of one-time pads was successful.', true);
	},
		
	/**
	 * Exports the pads for each user to a text file
	 * @param {Object} padDataJson The pad data in JSON format
	 * @param {String} userNickname The nickname of the user for who the pads belong to
	 */
	exportPadsToTextFile: function(padDataJson, userNickname)
	{			
		// Check for the various File API support
		if ((window.File && window.FileReader && window.FileList && window.Blob) === false)
		{
			// Show error that saving to file is not supported
			var message = 'The File APIs are not fully supported in this browser, try exporting to clipboard then '
			            + 'pasting to a new plain text file instead.';
				
			common.showStatus('error', message, true);			
			return false;
		}
		
		// Set parameters
		var blob = new Blob([padDataJson], { type: 'text/plain;charset=utf-8' });
		var filename = 'one-time-pads-user-' + userNickname.toLowerCase() + '.txt';

		// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
		saveAs(blob, filename);		
	},
	
	/**
	 * Exports the pads for each user to the clipboard
	 * @param {Object} padDataJson The pad data in JSON format
	 * @param {String} userNickname The nickname of the user for who the pads belong to
	 */
	exportPadsToClipboard: function(padDataJson, userNickname)
	{
		var message = 'User ' + userNickname + '\'s encrypted one-time pads - Copy this to the '
		            + 'clipboard (Ctrl + C) then paste (Ctrl + V) it into a text file with their name as the filename. '
		            + 'You will then give each user their own set of one-time time pads personally. Make sure you '
		            + 'tell them the password and other information necessary to load and decrypt the one-time pads.';
			
		// Popup box to let the user copy the pads
		window.prompt(message, padDataJson);
	},
	
	/**
	 * Exports the PBKDF salt as a separate keyfile. If an attacker can only get a hold of the encrypted database and 
	 * the 1536 bit salt is stored somewhere else and not available to an attacker this makes decrypting the database 
	 * even more difficult.
	 * @param {String} salt The 1536 bit salt in hexadecimal
	 * @param {String} exportMethod The export method e.g. 'clipboard' or 'textFile'
	 */
	exportKeyfile: function(salt, exportMethod)
	{
		// If they have chosen to export to the clipboard
		if (exportMethod === 'clipboard')
		{
			var message = 'Keyfile - Copy this keyfile to a secure location. Each user will need a copy of the keyfile '
			            + 'to be able to decrypt the one-time pad database. Ideally do not store the keyfile on the '
			            + 'same storage as the one-time pads and hide it somewhere else. Copy to clipboard (Ctrl + C) '
			            + 'then paste (Ctrl + V) it into a text file.';
			
			// Popup box to let the user copy the pads
			window.prompt(message, salt);
		}
		else {
			// Otherwise save to text file instead
			var blob = new Blob([salt], { type: 'text/plain;charset=utf-8' });
			var filename = 'keyfile.txt';

			// Pop up a save dialog for the user to save to a text file preferably straight onto removable media such as USB flash drive
			saveAs(blob, filename);
		}
	},
	
	/**
	 * Show the password strength based on the length of the passphrase and number of iterations
	 */
	initPassphraseStrengthCalculator: function()
	{
		// Add keyup event to the passphrase and number of iterations
		exportPads.$exportDialog.find('#passphrase, #pbkdfKeccakIterations, #pbkdfSkeinIterations').keyup(function()
		{
			// Get passphrase and number of iterations
			var passphrase = exportPads.$exportDialog.find('#passphrase').val();
			var pbkdfKeccakIterations = exportPads.$exportDialog.find('#pbkdfKeccakIterations').val();
			var pbkdfSkeinIterations = exportPads.$exportDialog.find('#pbkdfSkeinIterations').val();
			
			// Get the display fields in the dialog
			var $passphraseStrength = exportPads.$exportDialog.find('.passphraseStrength');
			var $passphraseText = exportPads.$exportDialog.find('.passphraseStrength .text');
			var $passphraseBits = exportPads.$exportDialog.find('.passphraseStrength .bits');
						
			// Calculate strength of passphrase
			var bitStrength = dbCrypto.calculatePassphraseStrengthInBits(passphrase, pbkdfKeccakIterations, pbkdfSkeinIterations);
			
			// If they haven't entered a passphrase, hide it
			if (passphrase.length === 0)
			{
				$passphraseStrength.hide();
			}
			else if ((pbkdfKeccakIterations.length === 0) && (pbkdfSkeinIterations.length === 0))
			{
				// If the iterations aren't set, hide it
				$passphraseStrength.hide();
			}
			else if ((/^[1-9]\d*$/.test(pbkdfKeccakIterations) === false) && (/^[1-9]\d*$/.test(pbkdfSkeinIterations) === false))
			{
				// If the number of iterations aren't a valid integer, hide it
				$passphraseStrength.hide();
			}
			else {
				// Otherwise show it
				$passphraseStrength.show();
			}
			
			// Anything below 127 bits is inadequate to secure the one-time pad database
			var bitStrengthClass = 'bad';
			
			// If the bit strength is between 128 and 256 this could be better
			if ((bitStrength >= 128) && (bitStrength < 256))
			{
				bitStrengthClass = 'average';
			}
			else if (bitStrength >= 256)
			{
				// Otherwise anything 256 bits or more is safe from quantum computers
				bitStrengthClass = 'good';
			}
			
			// Add the style and update the text
			$passphraseText.removeClass('bad good average').addClass(bitStrengthClass);
			$passphraseBits.text(bitStrength);
		});
	}
};