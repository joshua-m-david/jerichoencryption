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
 * Functions to export the one-time pads for transport or randomness testing by external programs
 */
var exportPads = {
	
	/** Cached jQuery selector for the Export Pads dialog */
	$dialog: null,
		
	/** The least significant bits in the first image from the TRNG */
	randomBitsFirstImageBinary: '',
	randomBitsFirstImageHex: '',
	
	/** The least significant bits in the second image from the TRNG  */
	randomBitsSecondImageBinary: '',
	randomBitsSecondImageHex: '',
	
	/** Get the least significant bits from both images XORed together from the TRNG */
	randomBitsXoredBinary: '',
	randomBitsXoredHex: '',
	
	/** Get the final bits after randomness extraction from the TRNG */
	randomBitsExtractedBinary: '',
	randomBitsExtractedHex: '',
		
	/**
	 * This is an estimate for the number of random bits that are needed when exporting the one-time pads so that the 
	 * database is encrypted and authenticated and the users have a server key and the failsafe RNG keys. This is 
	 * calculated as:  the PBKDF salt (1536 bits) + AES database encryption key (256 bits) + Salsa20 database encryption 
	 * key (256 bits) + Keccak database MAC key (512 bits) + Skein database MAC key (512 bits) + server API key 
	 * (512 bits) + failsafe RNG keys per user (256 bits * 7 users). The total comes to 5376 bits.
	 */
	bitLengthOfKeysRequiredForExport: 5376,
	
	/**
	 * Configure the Export Pads dialog to open and all functionality within
	 */
	initExportPadsDialog: function()
	{
		// Cache to prevent extra DOM lookups
		this.$dialog = $('#exportPadsSettings');
		
		// Configure button to open export dialog
		$('#btnOpenExportPadsSettings').click(function()
		{
			// Hide previous status messages and open the dialog
			common.hideStatus();
			
			// Open jQueryUI dialog
			exportPads.$dialog.dialog('open');
		});

		// Configure entropy collection settings dialog using jQueryUI
		this.$dialog.dialog(
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
		this.initShowAdvancedOptionsButton();
	},
	
	/**
	 * Repositions the export dialog to the center of the window because some options e.g. 
	 * the number of users or export method change the amount of information in the dialog
	 */
	repositionDialogToCenter: function()
	{
		exportPads.$dialog.dialog('option', 'position', { my : 'center', at: 'center', of: window });
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
			for (var i = 0; i < numOfUsers; i++)
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
		exportPads.$dialog.find('#exportMethod').change(function()
		{
			var exportMethod = $(this).val();		

			// If the pads will be exported for actual use show the Export for User option
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard'))
			{
				exportPads.$dialog.find('.helpExplanation .oneTimePads').show();
				exportPads.$dialog.find('.helpExplanation .randomData').hide();
				exportPads.$dialog.find('.serverDetails').show();
				exportPads.$dialog.find('.chatGroupDetails').show();
				exportPads.$dialog.find('.databaseEncryptionPassword').show();
				exportPads.$dialog.find('.buttonShowAdvancedOptions').show();
				exportPads.$dialog.find('.advancedOptions').hide();
				exportPads.$dialog.find('#btnExportPads').val('3. Export one-time pads');
			}
			else {
				// Otherwise export for testing so hide the one-time pad export options
				exportPads.$dialog.find('.helpExplanation .oneTimePads').hide();
				exportPads.$dialog.find('.helpExplanation .randomData').show();
				exportPads.$dialog.find('.serverDetails').hide();
				exportPads.$dialog.find('.chatGroupDetails').hide();
				exportPads.$dialog.find('.databaseEncryptionPassword').hide();
				exportPads.$dialog.find('.buttonShowAdvancedOptions').hide();
				exportPads.$dialog.find('.advancedOptions').hide();
				exportPads.$dialog.find('#btnExportPads').val('3. Export random data');
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
			if (exportPads.randomBitsExtractedHex.length < 128)
			{
				common.showStatus('error', 'Not enough bits remaining to create a full 512 bit key.', true);
			}
			else {
				// Take the first 512 bits of the extracted data and convert it to hexadecimal
				var serverKeyHex = exportPads.randomBitsExtractedHex.slice(0, 128);

				// After removing the first 512 bits, use the remainder of the bits for the one-time pads
				exportPads.randomBitsExtractedHex = exportPads.randomBitsExtractedHex.slice(128);

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
	 * Shows advanced options when they click to see more
	 */
	initShowAdvancedOptionsButton: function()
	{
		$('.buttonShowAdvancedOptions').click(function() {
			
			// Show the advanced options
			$('.advancedOptions').show();
			
			// Hide the button
			$(this).hide();
			
			// Reposition dialog to center after expanding the other options
			exportPads.repositionDialogToCenter();
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
					exportPads.preparePadsForExport(exportOptions, exportPads.randomBitsExtractedHex);
				}
			}
			else {
				// Otherwise export the random data for testing using external methods
				exportPads.prepareRandomDataForExternalTesting(exportMethod);
			}
		});
	},
	
	/**
	 * Exports the random data to the clipboard in various formats or to a binary file
	 * @param {String} exportMethod The value from the exportMethod select box which says how the data should be 
	 *                              exported e.g. 'testExportEntropyExtractedHexadecimal' will export the final 
	 *                              extracted random data to an ASCII text file with hexadecimal symbols in it.
	 */
	prepareRandomDataForExternalTesting: function(exportMethod)
	{		
		var entropyBinary = '';
		var entropyHex = '';
		var output = '';
		var filename = '';
		
		// Get the entropy relevant to which option they have chosen in the 'Export to' select box
		if (exportMethod.indexOf('EntropyFirstImage') !== -1)
		{
			// Get the least significant bits in the first image
			entropyBinary = exportPads.randomBitsFirstImageBinary;
			entropyHex = exportPads.randomBitsFirstImageHex;
		}
		else if (exportMethod.indexOf('EntropySecondImage') !== -1)
		{
			// Get the least significant bits in the second image
			entropyBinary = exportPads.randomBitsSecondImageBinary;
			entropyHex = exportPads.randomBitsSecondImageHex;
		}
		else if (exportMethod.indexOf('EntropyXored') !== -1)
		{
			// Get the least significant bits from both images XORed together
			entropyBinary = exportPads.randomBitsXoredBinary;
			entropyHex = exportPads.randomBitsXoredHex;
		}
		else if (exportMethod.indexOf('EntropyExtracted') !== -1)
		{
			// Get the final bits after randomness extraction
			entropyBinary = exportPads.randomBitsExtractedBinary;
			entropyHex = exportPads.randomBitsExtractedHex;
		}
		
		// Export to binary file. This format can be used by the NIST SP 800-22 tool.
		if (exportMethod.indexOf('BinaryFile') !== -1)
		{
			// Convert to hexadecimal then WordArray objects for CryptoJS to use
			var words = CryptoJS.enc.Hex.parse(entropyHex);
			var outputBase64 = CryptoJS.enc.Base64.stringify(words);
			
			// Output the binary file and prompt the user to save it
			location.href = 'data:application/octet-stream;base64,' + outputBase64;
			
			// Finished, exit early
			return true;
		}
		
		// Export to Base 64
		else if (exportMethod.indexOf('Base64') !== -1)
		{
			// Convert to WordArray objects for CryptoJS to use			
			var words = CryptoJS.enc.Hex.parse(entropyHex);
			
			// Set the filename and encode to Base64
			filename = 'ascii-base64.txt';
			output = CryptoJS.enc.Base64.stringify(words);
		}
		
		// Export to hexadecimal string
		else if (exportMethod.indexOf('Hexadecimal') !== -1)
		{
			filename = 'ascii-hexadecimal.txt';
			output = entropyHex;
		}
		
		// Export to ASCII binary string e.g. '01011100...'. This format can be used by the NIST SP 800-22 tool.
		else if (exportMethod.indexOf('Binary') !== -1)
		{
			filename = 'ascii-binary.txt';
			output = entropyBinary;			
		}
		
		// Create a Binary Large Object (BLOB)
		var blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
		
		// Pop up a save dialog for the user to save to a text file
		saveAs(blob, filename);
	},
	
	/**
	 * Gets the data from the export dialog and validates it
	 * @returns {Boolean|Object} Returns false if invalid, or the data entered into the dialog
	 */
	getAndValidateInputs: function()
	{
		// Get data from the dialog inputs
		var options = {
			exportMethod: exportPads.$dialog.find('#exportMethod').val(),
			
			// Server details
			serverAddressAndPort: exportPads.$dialog.find('#serverAddressAndPort').val(),
			serverKey: exportPads.$dialog.find('#serverKey').val().toLowerCase(),
			
			// Chat group details
			numOfUsers: parseInt(exportPads.$dialog.find('#numOfUsers').val()),
			userNicknames: {},
			
			// Database encryption password
			passphrase: exportPads.$dialog.find('#passphrase').val(),
			passphraseRepeat: exportPads.$dialog.find('#passphraseRepeat').val(),
						
			// Advanced options			
			createSeparateKeyfile: exportPads.$dialog.find('#storeKeyfileSeparately').is(':checked'),
			enterPbkdfIterationsOnDecrypt: exportPads.$dialog.find('#enterPbkdfIterationsOnDecrypt').is(':checked'),
			pbkdfKeccakIterations: exportPads.$dialog.find('#pbkdfKeccakIterations').val(),
			pbkdfSkeinIterations: exportPads.$dialog.find('#pbkdfSkeinIterations').val()
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
		else if (exportPads.randomBitsExtractedHex.length < (common.saltLengthHex + common.totalPadSizeHex))
		{
			common.showStatus('error', 'Not enough random data generated.', true);
			return false;
		}
		
		// Loop through the number of users
		for (var i = 0; i < options.numOfUsers; i++)
		{
			// Get the user, nickname, then filter the nickname field so only A-z and 0-9 characters allowed
			var user = common.userList[i];
			var nickname = exportPads.$dialog.find('#nickname-' + user).val();
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
			if ((currentUserIndex !== (numOfUsers - 1)) && (currentNumOfPadsPerUser === numOfPadsPerUser))
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
	 * Gets unique crypto keys from the random data created by the TRNG then returns the keys and unused random data.
	 * @param {Number} numOfUsers The total number of users using these one-time pads
	 * @param {String} extractedRandomDataHex The random data created by the TRNG
	 * @returns {Object|false} Returns an object with keys: 'salt', 'aesKey', 'salsaKey', 'keccakMacKey', 'skeinMacKey', 
	 *                         'userFailsafeRngKeys', 'extractedRandomDataHex'. Or returns false if not enough random data.
	 */
	getCryptoKeysFromExtractedRandomData: function(numOfUsers, extractedRandomDataHex)
	{		
		// The required database keys
		var databaseKeys = [
			{ name: 'salt', length: 384 },			// 1536 bits (384 hex symbols)
			{ name: 'aesKey', length: 64 },			// 256 bits (64 hex symbols)
			{ name: 'salsaKey', length: 64 },		// 256 bits (64 hex symbols)
			{ name: 'keccakMacKey', length: 128 },	// 512 bits (128 hex symbols)
			{ name: 'skeinMacKey', length: 128 }	// 512 bits (128 hex symbols)
		];
				
		var lengthOfDatabaseKeys = 0;
		
		// Add the length of the keys from the array above
		databaseKeys.map(function(key) {
			lengthOfDatabaseKeys += key.length;
		});
		
		// Get the length of all keys needed
		var failsafeRngKeyLength = 64;						// 256 bits (64 hex symbols)
		var lengthOfFailsafeKeysForAllUsers = failsafeRngKeyLength * numOfUsers;
		var lengthOfAllKeys = lengthOfDatabaseKeys + lengthOfFailsafeKeysForAllUsers;
		
		// If not enough random data available, exit out
		if (extractedRandomDataHex.length < lengthOfAllKeys)
		{
			return false;
		}
		
		var startIndex = 0;
		var endIndex = 0;
		var numOfDatabaseKeys = databaseKeys.length;
		var allKeys = {};
		var keyName = '';
		
		// Get the individual database keys from the random data
		for (var i = 0; i < numOfDatabaseKeys; i++)
		{
			// Get unused random bits for each key and store it under the key's name in the allKeys array
			endIndex = endIndex + databaseKeys[i].length;
			keyName = databaseKeys[i].name;
			allKeys[keyName] = extractedRandomDataHex.substring(startIndex, endIndex);
			startIndex = endIndex;
		}
		
		var userFailsafeRngKeys = {};
		var userCallsign = '';
				
		// Collect encryption keys for each user that will be used for the failsafe Salsa20 CSPRNG
		for (var i = 0; i < numOfUsers; i++)
		{
			// Get a fresh 256 bits and store it under the user's callsign
			endIndex = startIndex + failsafeRngKeyLength;
			userCallsign = common.userList[i];
			userFailsafeRngKeys[userCallsign] = extractedRandomDataHex.substring(startIndex, endIndex);
			startIndex = endIndex;
		}
		
		// Return keys to be used, including the unused random data
		allKeys.userFailsafeRngKeys = userFailsafeRngKeys;
		allKeys.extractedRandomDataHex = extractedRandomDataHex.substring(startIndex);
				
		return allKeys;
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
		var userFailsafeRngKeys = workerData.userFailsafeRngKeys;
		
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
			
			// Each user also gets a unique key which is used to seed the Salsa20 failsafe CSPRNG
			userPadData.info.failsafeRngKey = userFailsafeRngKeys[userCallSign];
			userPadData.info.failsafeRngNonce = 0;
			
			// Encrypt and authenticate the pad info for the user
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
		exportPads.$dialog.find('#passphrase, #pbkdfKeccakIterations, #pbkdfSkeinIterations').keyup(function()
		{
			// Get passphrase and number of iterations
			var passphrase = exportPads.$dialog.find('#passphrase').val();
			var pbkdfKeccakIterations = exportPads.$dialog.find('#pbkdfKeccakIterations').val();
			var pbkdfSkeinIterations = exportPads.$dialog.find('#pbkdfSkeinIterations').val();
			
			// Get the display fields in the dialog
			var $passphraseStrength = exportPads.$dialog.find('.passphraseStrength');
			var $passphraseText = exportPads.$dialog.find('.passphraseStrength .text');
			var $passphraseBits = exportPads.$dialog.find('.passphraseStrength .bits');
						
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