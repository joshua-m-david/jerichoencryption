/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2017  Joshua M. David
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */

/**
 * Web worker for the Export dialog
 */
var exportPadsWorker = {
	
	/**
	 * Creates and encrypts the one-time pads, encrypts the encryption and MAC keys by deriving keys from the salt 
	 * and passphrase, and also creates a MAC of the database indexes
	 * @param {Object} options An object containing the export options on the export dialog
	 * @param {String} extractedRandomDataHex The random data as a hexadecimal string
	 * @returns {Object} Returns an object with keys: salt, aesKey, salsaKey, keccakMacKey, skeinMacKey, 
	 *                   encryptedPads, encryptedDatabaseKeysAndMac, padIndexMacs
	 */
	createAndEncryptPads: function(options, extractedRandomDataHex)
	{
		// Get salt, two encryption keys, two MAC keys and a unique RNG key per user
		var keys = exportPads.getCryptoKeysFromExtractedRandomData(options.numOfUsers, extractedRandomDataHex);
		
		// Get data
		var salt = keys.salt;
		var aesKey = keys.aesKey;
		var salsaKey = keys.salsaKey;
		var keccakMacKey = keys.keccakMacKey;
		var skeinMacKey = keys.skeinMacKey;
		var userFailsafeRngKeys = keys.userFailsafeRngKeys;
		var remainingExtractedRandomDataHex = keys.extractedRandomDataHex;
		
		// Split up the random data into separate pads, then encrypt and authenticate each pad
		var pads = exportPads.createPads(options.numOfUsers, remainingExtractedRandomDataHex);
		var encryptedPads = dbCrypto.encryptAndAuthenticatePads(aesKey, salsaKey, keccakMacKey, skeinMacKey, pads);
		
		// Generate a master key from the passphrase and salt, then encrypt and authenticate the database keys
		var masterKey = dbCrypto.cascadePasswordDerivation(options.passphrase, salt, options.pbkdfKeccakIterations, options.pbkdfSkeinIterations);
		var encryptedDatabaseKeysAndMac = dbCrypto.encryptAndMacDatabaseKeys(aesKey, salsaKey, keccakMacKey, skeinMacKey, masterKey);
		
		// Create a MAC of the index for each user's one-time pads and clone the object storage schema
		var padIndexMacs = dbCrypto.createMacOfAllDatabaseIndexes(keccakMacKey, skeinMacKey, encryptedPads);
		
		return {
			salt: salt,
			aesKey: aesKey,
			salsaKey: salsaKey,
			keccakMacKey: keccakMacKey,
			skeinMacKey: skeinMacKey,
			userFailsafeRngKeys: userFailsafeRngKeys,
			encryptedPads: encryptedPads,
			encryptedDatabaseKeysAndMac: encryptedDatabaseKeysAndMac,
			padIndexMacs: padIndexMacs
		};
	}	
};