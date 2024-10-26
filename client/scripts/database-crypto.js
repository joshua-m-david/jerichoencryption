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
 * These methods encrypt and authenticate the database of one-time pads. Each one-time pad is encrypted and
 * authenticated at the row level. When a user sends a message, the pad authenticity and integrity is verified to
 * protect against tampering, then it is decrypted using a key in memory, then the decrypted one-time pad is used to
 * encrypt the message. Doing the encryption at the row level saves a long verification process when loading the
 * program to verify the integrity of the database. Each time the program loads or when a pad is removed from the
 * database, a quick integrity check is performed on the index of the pads to make sure pads have not been added,
 * reordered or swapped.
 */
var dbCrypto = {

	/**
	 * Loop through the user's array of pads, then combine the pad numbers for each pad and produce a MAC.
	 * This ensures that the index has not been added, swapped, reordered, removed or otherwise tampered with.
	 * The authenticity of each individual pad is protected by a MAC for each one-time pad.
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} userCallSign The user that these one-time pad belong to e.g. alpha, bravo etc
	 * @param {Array} userPads The user's pads
	 * @returns {String} Returns a 512 bit cascade MAC tag as a hexadecimal string
	 */
	createMacOfDatabaseIndex: function(keccakMacKey, skeinMacKey, userCallSign, userPads)
	{
		var userPadNumbersHex = '';

		// Loop through the user's one-time pads and put all the pad numbers (in the order they appear) into a single string
		for (var i = 0, numOfPads = userPads.length; i < numOfPads; i++)
		{
			// Get the pad number, convert it to hexadecimal
			userPadNumbersHex += userPads[i].padNum.toString(16);
		}

		// Make sure all the numbers are a multiple of 2 hex symbols to have complete bytes going into the hash function
		userPadNumbersHex = (userPadNumbersHex.length % 2 === 0) ? userPadNumbersHex : '0' + userPadNumbersHex;

		// Convert the user call sign to hexadecimal
		var userCallSignBinary = common.convertTextToBinary(userCallSign);
		var userCallSignHex = common.convertBinaryToHexadecimal(userCallSignBinary);

		// Create the MAC of the database index
		var dataToMac = userCallSignHex + userPadNumbersHex;
		var macOfDatabaseIndex = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, dataToMac);

		return macOfDatabaseIndex;
	},

	/**
	 * Loops through each user's one-time pads and creates a MAC of the database index for each one
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} pads The one-time pads for all users in the group e.g. { alpha: [], bravo: [], ... }
	 * @returns {Object} Returns the MAC of the database index for each user's pads e.g. { alpha: '', bravo: '', ... }
	 */
	createMacOfAllDatabaseIndexes: function(keccakMacKey, skeinMacKey, pads)
	{
		var padDatabaseMacs = {};

		// Loop through each user
		for (var userCallSign in pads)
		{
			// The current property is not a direct property so skip
			if (!pads.hasOwnProperty(userCallSign))
			{
				continue;
			}

			// Get the pads just for this user
			var userPads = pads[userCallSign];

			// Create a MAC of the database index for that user
			padDatabaseMacs[userCallSign] = dbCrypto.createMacOfDatabaseIndex(keccakMacKey, skeinMacKey, userCallSign, userPads);
		}

		return padDatabaseMacs;
	},

	/**
	 * Verify the database index to make sure it has not been added, swapped, reordered, removed or otherwise tampered with.
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} userCallSign The user that these one-time pad belong to e.g. alpha, bravo etc
	 * @param {Array} userPads The user's pads
	 * @param {String} macHex The existing computed MAC of the index
	 * @returns {String} Returns true if valid or false if not
	 */
	verifyDatabaseIndex: function(keccakMacKey, skeinMacKey, userCallSign, userPads, macHex)
	{
		// Recreate a MAC of the index
		var macToVerify = dbCrypto.createMacOfDatabaseIndex(keccakMacKey, skeinMacKey, userCallSign, userPads);

		// Check it against the existing MAC
		if (macToVerify === macHex)
		{
			return true;
		}

		return false;
	},

	/**
	 * Verify the database indexes for all users
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {Object} pads An object containing the encrypted pads for all users e.g. { alpha: [], bravo [] }
	 * @param {Object} padIndexMacs An object containing the MAC of the database indexes for each user e.g.
	 *                 { alpha: 'a1b2c3...', bravo: 'd4e5f6a7..' }
	 * @returns {Boolean} Returns true if all the database indexes validated or false if not
	 */
	verifyAllUserDatabaseIndexes: function(keccakMacKey, skeinMacKey, pads, padIndexMacs)
	{
		// If the pads or MACs are empty objects then immediately fail validation
		if ((Object.getOwnPropertyNames(pads).length === 0) || (Object.getOwnPropertyNames(padIndexMacs).length === 0))
		{
			return false;
		}

		try {
			// Loop through each user
			for (var userCallSign in pads)
			{
				// The current property is not a direct property so skip
				if (!pads.hasOwnProperty(userCallSign))
				{
					continue;
				}

				// Get the pads just for this user
				var userPads = pads[userCallSign];
				var macHex = padIndexMacs[userCallSign];

				// Verify the user's pad index against the stored MAC
				var verified = dbCrypto.verifyDatabaseIndex(keccakMacKey, skeinMacKey, userCallSign, userPads, macHex);

				// If invalid return false immediately
				if (verified === false)
				{
					return false;
				}
			}

			// If it reaches here it was successfully validated
			return true;
		}
		catch (exception)
		{
			// Catch any invalid format of the pads
			return false;
		}
	},

	/**
	 * Generates a keystream using AES in counter mode with a 256 bit key
	 * @param {String} keyHex A 256 bit key in hexadecimal
	 * @param {String} nonceHex A 96 bit nonce in hexadecimal, can be random or just unique for CTR mode
	 * @param {Number} length The number of random bytes required
	 * @returns {String} Returns a string of random bytes in hexadecimal
	 */
	generateAesKeystream: function(keyHex, nonceHex, length)
	{
		// Concatenate random 96 bit nonce and 32 bit counter starting at 0 to make the full 128 bit nonce
		var counterHex = '00000000';
		var nonceAndCounterHex = nonceHex + counterHex;

		// Convert Key and nonce to CryptoJS WordArray format
		var key = CryptoJS.enc.Hex.parse(keyHex);
		var nonce = CryptoJS.enc.Hex.parse(nonceAndCounterHex);
		var plaintextHex = '';

		// XORing the keystream with 0 bytes will be the same as the raw AES keystream, so set plaintext to all 0 bytes
		for (var i = 0; i < length; i++)
		{
			plaintextHex += '00';
		}

		// Convert plaintext to WordArray
		var plaintext = CryptoJS.enc.Hex.parse(plaintextHex);

		// Perform AES-CTR encryption and convert the result to hex
		var encryption = CryptoJS.AES.encrypt(plaintext, key, { iv: nonce, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
		var keystreamHex = encryption.ciphertext.toString(CryptoJS.enc.Hex);

		return keystreamHex;
	},

	/**
	 * Generates a keystream using Salsa20 with 20 rounds and a 256 bit key
	 * @param {String} keyHex A 256 bit key in hexadecimal
	 * @param {Number|String} nonce A nonce as an integer e.g. pad number or hexadecimal string
	 * @param {Number} length The number of random bytes required
	 * @returns {String} Returns a string of random bytes in hexadecimal
	 */
	generateSalsaKeystream: function(keyHex, nonce, length)
	{
		var counter = 0;
		var options = { returnType: 'hex' };

		// Generate the keystream
		var keystream = Salsa20.generateKeystream(keyHex, length, nonce, counter, options);
		var lengthInHex = length * 2;

		// Truncate the Salsa20 output to the correct length in case the input length is not a multiple of 64 bytes
		if (keystream.length > lengthInHex)
		{
			keystream = keystream.substr(0, lengthInHex);
		}

		return keystream;
	},

	/**
	 * Encrypts data using a cascade of two stream ciphers, AES-CTR and Salsa20.
	 * Each stream cipher encryption uses an independent IV/nonce and 256 bit key.
	 * @param {String} aesKey An independent 256 bit key for AES-CTR in hexadecimal
	 * @param {String} salsaKey A independent 256 bit key for Salsa20 in hexadecimal
	 * @param {String} aesNonce A 96 bit nonce for AES-CTR in hexadecimal
	 * @param {Number|String} salsaNonce A numeric nonce or hexadecimal nonce for Salsa20
	 * @param {String} data The data to be encrypted in hexadecimal
	 * @returns {String} Returns the encrypted data in hexadecimal
	 */
	cascadeEncrypt: function(aesKey, salsaKey, aesNonce, salsaNonce, data)
	{
		// Get the length of the data in bytes
		var length = data.length / 2;

		// Generate the AES-CTR and Salsa20 keystreams
		var aesKeystream = dbCrypto.generateAesKeystream(aesKey, aesNonce, length);
		var salsaKeystream = dbCrypto.generateSalsaKeystream(salsaKey, salsaNonce, length);

		// Convert the keystreams and data to binary
		var aesKeystreamBinary = common.convertHexadecimalToBinary(aesKeystream);
		var salsaKeystreamBinary = common.convertHexadecimalToBinary(salsaKeystream);
		var dataBinary = common.convertHexadecimalToBinary(data);

		// Combine the two keystreams by XORing them together, then XOR the combined keystream with the data
		var combinedKeystreamBinary = common.xorBits(aesKeystreamBinary, salsaKeystreamBinary);
		var encryptedDataBinary = common.xorBits(combinedKeystreamBinary, dataBinary);
		var encryptedDataHex = common.convertBinaryToHexadecimal(encryptedDataBinary);

		return encryptedDataHex;
	},

	/**
	 * Using the principles of Encrypt Then MAC, this function creates a MAC of the ciphertext using a cascade MAC of
	 * Keccak-512 and Skein-512. Each MAC digest is calculated independently by computing Hash(Key | Ciphertext) on the
	 * ciphertext with independent keys for each algorithm. The resulting digests are then XORed together to hide the
	 * independent MAC digests from an attacker to hinder cryptanalysis.
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} data The data to be authenticated in hexadecimal
	 * @returns {String} Returns the cascade MAC digest of 512 bits in hexadecimal
	 */
	cascadeMac: function(keccakMacKey, skeinMacKey, data)
	{
		// Perform MAC of the key and ciphertext using H(K | M) format
		var keccakMac = common.secureHash('keccak-512', keccakMacKey + data);
		var skeinMac = common.secureHash('skein-512', skeinMacKey + data);

		// Convert the digests to binary
		var keccakMacBinary = common.convertHexadecimalToBinary(keccakMac);
		var skeinMacBinary = common.convertHexadecimalToBinary(skeinMac);

		// XOR the Skein and Keccak digests together then convert back to hex
		var cascadeMacBinary = common.xorBits(keccakMacBinary, skeinMacBinary);
		var cascadeMacHex = common.convertBinaryToHexadecimal(cascadeMacBinary);

		return cascadeMacHex;
	},

	/**
	 * Wrapper function to encrypt the one-time pad and create a MAC. This will be used for secure storage of each
	 * one-time pad before use or secure export of the key before writing to removable media.
	 * @param {String} aesKey An independent 256 bit key for AES-CTR in hexadecimal
	 * @param {String} salsaKey A independent 256 bit key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} userCallSign The user that this one-time pad belongs to e.g. alpha, bravo etc
	 * @param {Number} padNumber The index of the one-time pad in the database as an integer (maximum 2^53 - 1)
	 * @param {String} padHex The full one-time pad in hexadecimal
	 * @returns {Object} Returns an object with the 'ciphertextHex' and 'macHex'
	 */
	cascadeEncryptAndMac: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, userCallSign, padNumber, padHex)
	{
		// Get the pad identifier and the one-time pad without the padIdentifier at the front
		var padIdentifierHex = common.getPadIdentifierFromCiphertext(padHex);
		var padWithoutPadIdentifierHex  = common.getPadWithoutPadIdentifier(padHex);

		// For the 96 bit AES-CTR nonce use the pad number converted to hex and left padded to 96 bits
		var aesNonceHex = padNumber.toString(16);
		aesNonceHex = common.leftPadding(aesNonceHex, '0', 24);

		// For the 64 bit Salsa20 nonce use the right most 64 bits of the AES nonce
		var salsaNonceHex = aesNonceHex.substring(8, 24);

		// Encrypt just the one-time pad without the pad identifier (encrypting the public pad identifier as well allows for a known plaintext attack)
		var padCiphertextHex = dbCrypto.cascadeEncrypt(aesKey, salsaKey, aesNonceHex, salsaNonceHex, padWithoutPadIdentifierHex);

		// Convert the user call sign to hexadecimal. The user call sign is used in the MAC so that an attacker can't copy
		// pads from one user's list to another, then the same users are reusing the same pad and allowing for cryptanalysis
		var userCallSignBinary = common.convertTextToBinary(userCallSign);
		var userCallSignHex = common.convertBinaryToHexadecimal(userCallSignBinary);

		// Create the cascade MAC of all data (do not need to MAC the padNumber because the AES and Salsa nonces are derived from it)
		var dataToMac = aesNonceHex + salsaNonceHex + userCallSignHex + padIdentifierHex + padCiphertextHex;
		var macHex = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, dataToMac);

		return {
			ciphertextHex: padCiphertextHex,
			macHex: macHex
		};
	},

	/**
	 * The MAC will be verified, then if authentic the OTP will be decrypted
	 * @param {String} aesKey An independent 256 bit key for AES-CTR in hexadecimal
	 * @param {String} salsaKey A independent 256 bit key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey An independent 512 bit key for Keccak in hexadecimal
	 * @param {String} skeinMacKey An independent 512 bit key for Skein in hexadecimal
	 * @param {String} userCallSign The user that this one-time pad belongs to e.g. alpha, bravo etc
	 * @param {Number} padNumber The index of the one-time pad in the database as an integer (maximum 2^53 - 1)
	 * @param {String} padIdentifier The pad identifier in hexadecimal
	 * @param {String} padCiphertext The encrypted pad without pad identifier in hexadecimal
	 * @param {String} mac The MAC of the ciphertext pad and data in hexadecimal
	 * @returns {String|Boolean} Returns the decrypted pad without the pad identifier, or false if tampering has occurred
	 */
	cascadeVerifyMacAndDecrypt: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, userCallSign, padNumber, padIdentifier, padCiphertext, mac)
	{
		// For the 96 bit AES-CTR nonce use the pad number converted to hex and left padded to 96 bits e.g. 137 = 000000000000000000000089
		var aesNonceHex = padNumber.toString(16);
		aesNonceHex = common.leftPadding(aesNonceHex, '0', 24);

		// For the 64 bit Salsa20 nonce use the right most 64 bits of the AES nonce e.g. 0000000000000089
		var salsaNonceHex = aesNonceHex.substring(8, 24);

		// Convert the user call sign to hexadecimal. The user call sign is used in the MAC so that an attacker can't copy
		// pads from one user's list to another, then the same users are reusing the same pad and allowing for cryptanalysis
		var userCallSignBinary = common.convertTextToBinary(userCallSign);
		var userCallSignHex = common.convertBinaryToHexadecimal(userCallSignBinary);

		// Create the cascade MAC of all data (do not need to MAC the padNumber because the AES and Salsa nonces are derived from it)
		var dataToMac = aesNonceHex + salsaNonceHex + userCallSignHex + padIdentifier + padCiphertext;
		var macToVerify = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, dataToMac);

		// If valid MAC, perform the decryption
		if (macToVerify === mac)
		{
			// Decrypt the one-time pad which will return the one-time pad without the pad identifier
			return dbCrypto.cascadeEncrypt(aesKey, salsaKey, aesNonceHex, salsaNonceHex, padCiphertext);
		}
		else {
			// Invalid MAC / database tampering occurred
			return false;
		}
	},

	/**
	 * Generate a key derived from a password using PBKDF2 with the Keccak hash function instead of SHA2
	 * @param {String} passwordHex A strong password as a hexadecimal string
	 * @param {String} saltHex A random salt in hexadecimal
	 * @param {Number} numOfIterations The number of iterations to perform
	 * @returns {String} Returns a derived key of length 512 bits in hexadecimal
	 */
	keccakPasswordDerivation: function(passwordHex, saltHex, numOfIterations)
	{
		// Set the input parameters
		var passwordWords = CryptoJS.enc.Hex.parse(passwordHex);
		var salt = CryptoJS.enc.Hex.parse(saltHex);
		var options = { keySize: 512/32, hasher: CryptoJS.algo.SHA3, iterations: numOfIterations };

		// Generate the derived key using PBKDF2
		var derivedKey = CryptoJS.PBKDF2(passwordWords, salt, options);
		var derivedKeyHex = derivedKey.toString(CryptoJS.enc.Hex);

		return derivedKeyHex;
	},

	/**
	 * Generate a key derived from a password using a PBKDF with the Skein hash function. The method is described in
	 * section 4.8 of The Skein Hash Function Family specification document (v1.3) - Skein as a Password-Based
	 * Key Derivation Function (PBKDF). "A Password-Based Key Derivation Function is used to derive cryptographic keys
	 * from relatively low-entropy passwords. The application stores a random seed S, asks the user for a password P,
	 * and then performs a long computation to combine S and P." ... "An even simpler PBKDF is to simply create a very
	 * long repetition of S and P; e.g., S||P||S||P||S..., and hash that using Skein. (Any other optional data can
	 * also be included in the repetition.) This approach is not ideal with a normal hash function, as the computation
	 * could fall into a loop. But in Skein, every block has a different tweak and is thus processed differently."
	 * @param {String} passwordHex A strong password in hexadecimal
	 * @param {String} saltHex A random salt/seed in hexadecimal
	 * @param {Number} numOfIterations The number of iterations to perform
	 * @returns {String} Returns a derived key of length 512 bits in hexadecimal
	 */
	skeinPasswordDerivation: function(passwordHex, saltHex, numOfIterations)
	{
		var hashInput = '';

		// Create a long string of salt || password || salt || password || salt...
		for (var i = 0; i < numOfIterations; i++)
		{
			hashInput += saltHex + passwordHex;
		}

		// Create the derived key
		var derivedKey = common.secureHash('skein-512', hashInput);

		return derivedKey;
	},

	/**
	 * Perform a cascaded Password Based Key Derivation Function using the following construction:
	 *
	 * FunctionA = PBKDF2-Keccak-512
	 * FunctionB = PBKDF-Skein-512
	 * KeccakSalt = Salt || Keccak iterations
	 * SkeinSalt = Salt || Skein iterations
	 * KeyA = FunctionA(Password, KeccakSalt)
	 * KeyB = FunctionB(Password || KeyA, SkeinSalt)
	 * FinalDerivedKey = KeyA XOR KeyB
	 *
	 * The reason for this construction is:
	 * - An adversary can't parallelize an attack because KeyB depends on the result of KeyA.
	 * - The entropy in the FinalDerivedKey is not lowered if FunctionA is weak because the Password is also included
	 *   in FunctionB.
	 * - The entropy in the FinalDerivedKey is not lowered if FunctionB is weak because it is XORed with KeyA.
	 * - The FinalDerivedKey is at least as strong as the strongest function and retains the entropy in the Password
	 *   and Salt even if one of the functions is weak.
	 * - It is hard to perform cryptanalysis on the output of each function individually because the output is XORed by
	 *   random data from the other function.
	 * - For added security an option exists in the UI to use custom iteration counts. The user can also choose not to
	 *   store the number of Keccak or Skein iterations with the rest of the database. The user would remember the
	 *   iterations or write them down separately. This forces an attacker with only the database to try every iteration
	 *   count for every password permutation. To counter an attacker simply caching the results of previous iteration
	 *   counts and running the PBKDF on one password at a time, the iterations are appended to the end of the salt at
	 *   runtime. This forces the attacker to do the full PBKDF iterations for every reasonable iteration count the user
	 *   could have chosen e.g. 1 - 100,000 then repeat that for all possible password permutations.
	 *
	 * @param {String} password A strong password as an ASCII string
	 * @param {String} saltHex A random salt/seed in hexadecimal
	 * @param {Number} keccakNumOfIterations The number of iterations to perform with the PBKDF2 Keccak function
	 * @param {Number} skeinNumOfIterations The number of iterations to perform with the Skein PBKDF function
	 * @returns {String} Returns a derived master key of length 512 bits in hexadecimal
	 */
	cascadePasswordDerivation: function(password, saltHex, keccakNumOfIterations, skeinNumOfIterations)
	{
		// Convert the ASCII/UTF-8 password to hexadecimal so it can be input into both functions
		var passwordBytes = Salsa20.core.util.utf8StringToBytes(password);
		var passwordHex = Salsa20.core.util.bytesToHex(passwordBytes);

		// Add the number of iterations to the end of the salt
		var keccakSaltHex = saltHex + common.convertIntegerToHex(keccakNumOfIterations);
		var skeinSaltHex = saltHex + common.convertIntegerToHex(skeinNumOfIterations);

		// Compute both derived keys and XOR them together
		var keccakDerivedKeyHex = dbCrypto.keccakPasswordDerivation(passwordHex, keccakSaltHex, keccakNumOfIterations);
		var skeinDerivedKeyHex = dbCrypto.skeinPasswordDerivation(passwordHex + keccakDerivedKeyHex, skeinSaltHex, skeinNumOfIterations);
		var finalDerivedKeyHex = common.xorHex(keccakDerivedKeyHex, skeinDerivedKeyHex);

		return finalDerivedKeyHex;
	},

	/**
	 * Derives 4 keys from a 512 bit master key. Creates two 256 bit keys for AES-CTR and Salsa20 encryption.
	 * It also derives two 512 bit keys for Keccak and Skein. The method it uses is similar to KDF1 and KDF2 where
	 * the master key is hashed with a counter e.g. Hash(Master key || 32 bit counter).
	 * However to make each derived key stronger, it generates each key using two independant algorithms (Keccak and
	 * Skein) then XORs the digests together to produce the final key.
	 * @param {String} masterKey A 512 bit key in hexadecimal
	 * @returns {Object} Returns an object with 4 derived keys, 'aesKey', 'salsaKey', 'keccakMacKey', 'skeinMacKey'
	 */
	deriveKeysFromMasterKey: function(masterKey)
	{
		var derivedKeys = [];

		// Create 4 keys of length 512 bits (128 hex symbols)
		for (var i = 1; i <= 4; i++)
		{
			// Derive two 512 bit keys, the first using Keccak and the second with Skein, using H(K || i),
			var keyA = common.secureHash('keccak-512', masterKey + '0000000' + i);
			var keyB = common.secureHash('skein-512', masterKey + '0000000' + i);

			// Convert both keys to binary
			var keyBinaryA = common.convertHexadecimalToBinary(keyA);
			var keyBinaryB = common.convertHexadecimalToBinary(keyB);

			// XOR the two keys together and convert back to hexadecimal
			var xoredKeyBinary = common.xorBits(keyBinaryA, keyBinaryB);
			var xoredKeyHex = common.convertBinaryToHexadecimal(xoredKeyBinary);

			// Add derived key to array
			derivedKeys.push(xoredKeyHex);
		}

		// Return 256 bit encryption keys for AES-CTR and Salsa20
		// Return 512 bit MAC keys for Keccak and Skein
		return {
			aesKey: derivedKeys[0].substring(0, 64),
			salsaKey: derivedKeys[1].substring(0, 64),
			keccakMacKey: derivedKeys[2],
			skeinMacKey: derivedKeys[3]
		};
	},

	/**
	 * This encrypts and authenticates the real database encryption and MAC keys. It does this by getting the master key
	 * which was derived from the user's passphrase and salt, then deriving 4 sub keys. These 4 sub keys are used to
	 * encrypt and authenticate the real database encryption keys. The advantage of this is that for a passphrase change
	 * you do not need to re-encrypt the entire database. You can simply derive a new master key and sub keys, then
	 * re-encrypt the real keys.
	 * @param {String} aesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} salsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} skeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {String} masterKey The 512 bit master key which was derived from the passphrase and salt
	 * @returns {Object} Returns properties 'keysHex' and 'macHex'
	 */
	encryptAndMacDatabaseKeys: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, masterKey)
	{
		// Generate sub keys from the master key which will be used to encrypt the real database encryption and MAC keys
		var derivedKeys = dbCrypto.deriveKeysFromMasterKey(masterKey);

		// Concatenate the keys before encryption
		var databaseKeysToEncrypt = aesKey + salsaKey + keccakMacKey + skeinMacKey;

		// For the 96 bit AES-CTR nonce use the number 0 converted to hex and left padded to 96 bits (24 hex symbols)
		// For the 64 bit Salsa20 nonce use the number 0 converted to hex and left padded to 64 bits (16 hex symbols)
		var aesNonce = '000000000000000000000000';
		var salsaNonce = '0000000000000000';

		// Encrypt the database keys
		var encryptedDatabaseKeys = dbCrypto.cascadeEncrypt(derivedKeys.aesKey, derivedKeys.salsaKey, aesNonce, salsaNonce, databaseKeysToEncrypt);

		// Create the cascade MAC of the encrypted database keys
		var macHex = dbCrypto.cascadeMac(derivedKeys.keccakMacKey, derivedKeys.skeinMacKey, encryptedDatabaseKeys);

		return {
			keysHex: encryptedDatabaseKeys,
			macHex: macHex
		};
	},

	/**
	 * After the PBKDF is run using the passphrase, keyfile and number of iterations, this produces a master key which
	 * is then used to derive 2 encryption keys and 2 MAC keys. The derived MAC keys are then used to authenticate the
	 * stored encrypted database keys. If the MAC is a match for the MAC that was stored with the encrypted database
	 * keys then the passphrase, keyfile and number of iterations are correct. This will then produce a successful
	 * decryption of the database keys, and thus a successful decryption of the pad database.
	 * @param {String} keccakMacKey The derived 512 bit Keccak MAC key in hexadecimal
	 * @param {String} skeinMacKey The derived 512 bit Skein MAC key in hexadecimal
	 * @param {String} encryptedKeys The stored encrypted database keys in hexadecimal
	 * @param {String} encryptedKeysMac The stored cascade MAC of the database keys in hexadecimal
	 * @returns {Boolean}
	 */
	verifyMacOfDatabaseKeys: function(keccakMacKey, skeinMacKey, encryptedKeys, encryptedKeysMac)
	{
		// Create the cascade MAC of the encrypted database keys
		var macHex = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, encryptedKeys);

		// If it's a match, then the derived keys are correct and the encrypted keys authentic
		if (macHex === encryptedKeysMac)
		{
			return true;
		}

		return false;
	},

	/**
	 * Decrypts the database encryption and MAC keys
	 * @param {String} derivedAesKey The derived 256 bit AES-CTR key in hexadecimal
	 * @param {String} derivedSalsaKey The derived 256 bit Salsa20 key in hexadecimal
	 * @param {String} encryptedKeys The encrypted database and MAC keys concatenated together as a string
	 * @returns {Object} Returns the four database keys for encryption and MAC
	 */
	decryptDatabaseKeys: function(derivedAesKey, derivedSalsaKey, encryptedKeys)
	{
		// For the 96 bit AES-CTR nonce use the number 0 converted to hex and left padded to 96 bits (24 hex symbols)
		// For the 64 bit Salsa20 nonce use the number 0 converted to hex and left padded to 64 bits (16 hex symbols)
		var aesNonce = '000000000000000000000000';
		var salsaNonce = '0000000000000000';

		// Decrypt the database keys (can use the same function for encryption and decryption because it is XOR)
		var decryptedDatabaseKeys = dbCrypto.cascadeEncrypt(derivedAesKey, derivedSalsaKey, aesNonce, salsaNonce, encryptedKeys);

		// Return the separate keys which were concatenated together at encryption time
		return {
			dbAesKey: decryptedDatabaseKeys.substring(0, 64),			// 256 bit key (64 hex symbols)
			dbSalsaKey: decryptedDatabaseKeys.substring(64, 128),		// 256 bit key (64 hex symbols)
			dbKeccakMacKey: decryptedDatabaseKeys.substring(128, 256),	// 512 bit key (128 hex symbols)
			dbSkeinMacKey: decryptedDatabaseKeys.substring(256, 384)	// 512 bit key (128 hex symbols)
		};
	},

	/**
	 * Encrypts the one-time pads for each user and creates a MAC for each pad
	 * @param {String} aesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} salsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} skeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {Object} pads An object containing a key for each user, then under that key an array of pads
	 * @returns {Object} Returns the encrypted one-time pads
	 */
	encryptAndAuthenticatePads: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, pads)
	{
		var encryptedPads = {};

		// Loop through each user
		for (var userCallSign in pads)
		{
			// The current property is not a direct property so skip
			if (!pads.hasOwnProperty(userCallSign))
			{
				continue;
			}

			// Set blank array for this user's pads
			encryptedPads[userCallSign] = [];

			// Loop through the pads for this user
			for (var i = 0, numOfPads = pads[userCallSign].length;  i < numOfPads;  i++)
			{
				var padData = pads[userCallSign][i];
				var padNum = padData.padNum;
				var padIdentifier = padData.padIdentifier;
				var padHex = padData.pad;

				// Encrypt and MAC the one-time pad
				var padCiphertextAndMac = dbCrypto.cascadeEncryptAndMac(aesKey, salsaKey, keccakMacKey, skeinMacKey, userCallSign, padNum, padHex);

				// Construct new format for storage
				var encryptedPadData = {
					padNum: padNum,
					padIdentifier: padIdentifier,
					pad: padCiphertextAndMac.ciphertextHex,		// This now contains the encrypted pad without the pad identifier
					mac: padCiphertextAndMac.macHex
				};

				// Add the encrypted pad data to the array
				encryptedPads[userCallSign].push(encryptedPadData);
			}
		}

		return encryptedPads;
	},

	/**
	 * Verifies and decrypts the one-time pads
	 * @param {String} aesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} salsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} skeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {Object} encryptedPads An object containing arrays of the encrypted pads for each user
	 * @returns {Object|false} Returns the decrypted one-time pads or false if they were invalid
	 */
	verifyAndDecryptPads: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, encryptedPads)
	{
		var decryptedPads = {};

		try {
			// Loop through each user
			for (var userCallSign in encryptedPads)
			{
				// The current property is not a direct property so skip
				if (!encryptedPads.hasOwnProperty(userCallSign))
				{
					continue;
				}

				// Set blank array for this user's pads
				decryptedPads[userCallSign] = [];

				// Loop through the pads for this user
				for (var i = 0, numOfPads = encryptedPads[userCallSign].length;  i < numOfPads;  i++)
				{
					var padData = encryptedPads[userCallSign][i];
					var padNum = padData.padNum;
					var padIdentifier = padData.padIdentifier;
					var padCiphertext = padData.pad;
					var padMac = padData.mac;

					// Verify and decrypt the pad
					var decryptedPad = dbCrypto.cascadeVerifyMacAndDecrypt(aesKey, salsaKey, keccakMacKey, skeinMacKey, userCallSign, padNum, padIdentifier, padCiphertext, padMac);

					// If an invalid MAC was detected quit early and don't process the remaining pads
					if (decryptedPad === false)
					{
						return false;
					}

					// Add the decrypted pad data
					decryptedPads[userCallSign].push({
						padNum: padNum,
						padIdentifier: padIdentifier,
						pad: padIdentifier + decryptedPad	// Now the full one-time pad including pad ID
					});
				}
			}

			return decryptedPads;
		}
		catch (exception)
		{
			// Catch any failure in validation or decryption e.g. missing object properties etc
			return false;
		}
	},

	/**
	 * Encrypts and MACs the extra information e.g. the server address and port, server key, user and user nicknames.
	 * @param {String} aesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} salsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} skeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {Object} padInfo The pad data info e.g. server address and port, server key, user and user nicknames
	 * @returns {Object} Returns the encrypted pad data info and mac with keys 'info' and 'mac'
	 */
	encryptAndMacPadInfo: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, padInfo)
	{
		// Convert the pad data to a JSON string
		var padInfoJson = JSON.stringify(padInfo);
		var padInfoBinary = common.convertTextToBinary(padInfoJson);
		var padInfoHex = common.convertBinaryToHexadecimal(padInfoBinary);

		// Set the 96 bit AES-CTR nonce. Because each pad number is converted to a nonce which is used to encrypt each
		// pad, and JavaScript integers cannot be larger than 2^53 - 1, this nonce cannot be accidentally be re-used for
		// encrypting a pad, therefore it is used it to encrypt the pad data info.
		var aesNonceHex = 'ffffffffffffffffffffffff';

		// For the 64 bit Salsa20 nonce use 64 bits of the AES nonce
		var salsaNonceHex = 'ffffffffffffffff';

		// Encrypt the pad data info
		var padInfoCiphertextHex = dbCrypto.cascadeEncrypt(aesKey, salsaKey, aesNonceHex, salsaNonceHex, padInfoHex);

		// Create the cascade MAC of all data
		var dataToMac = aesNonceHex + salsaNonceHex + padInfoCiphertextHex;
		var macHex = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, dataToMac);

		return {
			info: padInfoCiphertextHex,
			mac: macHex
		};
	},

	/**
	 * Verifies and decrypts the pad data info e.g. the server address and port, server key, user and user nicknames.
	 * @param {String} aesKey The 256 bit database encryption key for AES-CTR in hexadecimal
	 * @param {String} salsaKey The 256 bit database encryption key for Salsa20 in hexadecimal
	 * @param {String} keccakMacKey The 512 bit database MAC key for Keccak in hexadecimal
	 * @param {String} skeinMacKey The 512 bit database MAC key for Skein in hexadecimal
	 * @param {String} encryptedPadInfo The encrypted pad data info in hexadecimal e.g. server address and port,
	 *                                  server key, user and user nicknames
	 * @returns {Object|false} Returns an object containing the pad data if successfully decrypted, or false if invalid
	 */
	verifyAndDecryptPadInfo: function(aesKey, salsaKey, keccakMacKey, skeinMacKey, encryptedPadInfo)
	{
		// The 96 bit AES-CTR nonce and 64 bit Salsa20 static nonces in hexadecimal (same nonce used for encryption)
		var aesNonce = 'ffffffffffffffffffffffff';
		var salsaNonce = 'ffffffffffffffff';

		// Calculate the MAC of the encrypted pad info
		var dataToMac = aesNonce + salsaNonce + encryptedPadInfo.info;
		var mac = dbCrypto.cascadeMac(keccakMacKey, skeinMacKey, dataToMac);

		// If the calculated MAC does not match the stored MAC then the data has been tampered with
		if (encryptedPadInfo.mac !== mac)
		{
			return false;
		}

		// Encrypt the pad data info
		var decryptedPadInfo = dbCrypto.cascadeEncrypt(aesKey, salsaKey, aesNonce, salsaNonce, encryptedPadInfo.info);

		// Convert the hexadecimal pad data back to a JavaScript object
		var padInfoBinary = common.convertHexadecimalToBinary(decryptedPadInfo);
		var padInfoJson = common.convertBinaryToText(padInfoBinary);
		var padInfo = JSON.parse(padInfoJson);

		return padInfo;
	},

	/**
	 * Calculate a rough estimate of passphrase strength in bits. Passphrase characters are assumed to be drawn
	 * uniformly randomly among the most commonly used characters on a standard US keyboard. This is calculated as
	 * uppercase A-Z (26 characters) plus lowercase a-z (26 characters) plus numbers 0-9 (10 characters) for a total of
	 * 62 characters. This will produce a more conservative estimate than if special characters were included as well
	 * (e.g. the full 95 ASCII printable characters).
	 * The formula will also take into account the PBKDF iterations which roughly increases security (in bits) by
	 * log2(iterations). The full formula for calculating the bit strength of the passphrase is as follows:
	 * (number of passphrase characters * log2(total possible passphrase characters)) + log2(number of PBKDF iterations).
	 * @param {String} passphrase The passphrase which is ideally 41 characters in length for approximately 256 bit strength
	 * @param {Number} numOfIterationsKeccak The number of PBKDF iterations for Keccak e.g. 10000
	 * @param {Number} numOfIterationsSkein The number of PBKDF iterations for Skein e.g. 10000
	 * @returns {Number} Returns the number of bits e.g. 143 (which is 143 bit strength)
	 */
	calculatePassphraseStrengthInBits: function(passphrase, numOfIterationsKeccak, numOfIterationsSkein)
	{
		// Get the passphrase length and number of possible keyboard chars
		var passphraseLength = passphrase.length;
		var numOfPossibleChars = 62;

		// Convert number of iterations to an integer in case they were passed in as a string e.g. from the export
		// dialog. This prevents an erroneous result where two strings added together would be concatenated together
		// instead of added e.g. '10000' + '10000' = '1000010000' and would inflate the estimated number of bits.
		var numOfIterations = parseInt(numOfIterationsKeccak) + parseInt(numOfIterationsSkein);

		// Calculate the bit strength and round down to nearest integer
		var bitStrength = (passphraseLength * Math.log2(numOfPossibleChars)) + Math.log2(numOfIterations);
		var bitStrength = Math.floor(bitStrength);

		return bitStrength;
	}
};