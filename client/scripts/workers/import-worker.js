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
 * Web worker for the Export dialog
 */
var importPadsWorker = {
	
	/**
	 * Derives the master key from the passphrase, keyfile and number of iterations. Then uses the master key to 
	 * derive the 4 sub keys to validate and decrypt the actual database encryption and MAC keys.
	 * @param {String} passphrase A strong password as an ASCII string
	 * @param {String} keyfile A random salt/seed in hexadecimal
	 * @param {Number} pbkdfKeccakIterations The number of iterations to perform with the PBKDF2 Keccak function
	 * @param {Number} pbkdfSkeinIterations The number of iterations to perform with the Skein PBKDF function
	 * @returns {Object} Returns the derived keys 'aesKey', 'salsaKey', 'keccakMacKey', 'skeinMacKey'
	 */
	deriveSubKeys: function(passphrase, keyfile, pbkdfKeccakIterations, pbkdfSkeinIterations)
	{
		// Derive master key from the passphrase, keyfile and number of iterations
		var masterKey = dbCrypto.cascadePasswordDerivation(passphrase, keyfile, pbkdfKeccakIterations, pbkdfSkeinIterations);

		// Generate sub keys from the master key which will be used to verify and decrypt the real database keys
		var derivedKeys = dbCrypto.deriveKeysFromMasterKey(masterKey);
		
		return derivedKeys;
	},
	
	/**
	 * Verifies the database indexes for each user, also verifies each one-time pad row in the database
	 * and also decrypts the one-time pads as well so they are ready to be imported.
	 * @param {String} dbAesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} dbSalsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} dbKeccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} dbSkeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {Object} padData The full pad data object with pad index MACs and encrypted pads
	 * @returns {Object} Returns whether the pad indexes were valid and the decrypted pads if valid
	 */
	verifyAndDecryptPads: function(dbAesKey, dbSalsaKey, dbKeccakMacKey, dbSkeinMacKey, padData)
	{		
		// Verify all database indexes for each user's set of pads
		var encryptedPads = padData.pads;
		var padIndexMacs = padData.crypto.padIndexMacs;
		var validIndex = dbCrypto.verifyAllUserDatabaseIndexes(dbKeccakMacKey, dbSkeinMacKey, encryptedPads, padIndexMacs);
				
		// Verify and decrypt the one-time pads
		var decryptedPads = dbCrypto.verifyAndDecryptPads(dbAesKey, dbSalsaKey, dbKeccakMacKey, dbSkeinMacKey, encryptedPads);
		
		return {
			validIndex: validIndex,
			decryptedPads: decryptedPads
		};
	}
};