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
		// Get salt, two encryption keys and two MAC keys
		var salt = extractedRandomDataHex.substring(0, 384);				// 1536 bits (384 hex symbols)
		var aesKey = extractedRandomDataHex.substring(384, 448);			// 256 bits (64 hex symbols)
		var salsaKey = extractedRandomDataHex.substring(448, 512);			// 256 bits (64 hex symbols)
		var keccakMacKey = extractedRandomDataHex.substring(512, 640);		// 512 bits (128 hex symbols)
		var skeinMacKey = extractedRandomDataHex.substring(640, 768);		// 512 bits (128 hex symbols)
		
		// Use only the remaining bits for the one-time pads
		extractedRandomDataHex = extractedRandomDataHex.substring(768);
				
		// Split up the random data into separate pads, then encrypt and authenticate each pad
		var pads = exportPads.createPads(options.numOfUsers, extractedRandomDataHex);
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
			encryptedPads: encryptedPads,
			encryptedDatabaseKeysAndMac: encryptedDatabaseKeysAndMac,
			padIndexMacs: padIndexMacs
		};
	}	
};