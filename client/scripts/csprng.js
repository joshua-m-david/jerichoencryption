/**
 * A CSPRNG for the failsafe RNG. This uses the Salsa20 and the Fast Key Erasure RNG described at:
 * https://blog.cr.yp.to/20170723-random.html).
 */

var csprng = {

	/**
	 * A wrapper function to get the required number of random bits.
	 * @param {Number} numOfBits The desired number of random bits as an integer.
	 * @param {String} returnFormat Pass in 'binary' or 'hexadecimal' to return the random bits in that format.
	 * @returns {String} Returns the random bits as a string of 1s and 0s. If the returnFormat is 'hexadecimal', then the
	 *                   requiredNumOfBits should be a multiple of 4 bits, otherwise it can't convert the remaining few
	 *                   bits to a hexadecimal symbol and will truncate the output to the nearest multiple of 4 bits.
	 */
	getRandomBits: function(numOfBits, returnFormat)
	{
		// Get random bits
		var failsafeRngKey = db.padData.info.failsafeRngKey;
		var randomBits = csprng.getEncryptedRandomBits(numOfBits, failsafeRngKey, returnFormat);

		// Update the nonce after use so it is ready for use next time, then persist the change in localStorage
		db.padData.info.failsafeRngNonce += 1;
		db.savePadDataToDatabase();

		// Return the bits in binary or hexadecimal depending on what was requested
		return randomBits;
	},

	/**
	 * Private function to get the required number of bits from the HTML5 Web Crypto API which uses the operating
	 * system's random source. If the browser's implementation of this CSPRNG is compromised then there is a failsafe.
	 * The HTML5 Web Crypto API could be compromised by the user running a closed source OS (e.g. Windows or MacOS), or
	 * there is a flaw in the browser or underlying OS such as it uses Intel's questionable on-chip RNG. The program
	 * will use a 256 bit key, which will be unique to each user running the program, to create a keystream of random
	 * bits using the failsafe CSPRNG Salsa20. This is XORed with the random bytes returned from the Web Crypto API.
	 * The failsafe nonce for Salsa20 should be incremented after each request by the code calling this function to
	 * prevent re-use.
	 * @param {Number} numOfBits The desired number of random bits as an integer.
	 * @param {String} failsafeRngKey A key for the Salsa20 CSPRNG which should be a hexadecimal string consisting of 256 bits.
	 * @param {String} returnFormat Pass in 'binary' or 'hexadecimal' to return the random bits in that format.
	 * @returns {String} Returns the random bits as a string of 1s and 0s. If the returnFormat is 'hexadecimal', then the
	 *                   requiredNumOfBits should be a multiple of 4 bits, otherwise it can't convert the remaining few
	 *                   bits to a hexadecimal symbol and will truncate the output to the nearest multiple of 4 bits.
	 */
	getEncryptedRandomBits: function(numOfBits, failsafeRngKey, returnFormat)
	{
		// If the failsafe Salsa20 RNG has not been initialised with a key then throw a hard error which will halt
		// program execution. This should not happen during normal program operation. It is a protection against
		// programming error and the code logic requesting random bits before the key has been loaded.
		if ((failsafeRngKey === null) || (typeof failsafeRngKey === 'undefined'))
		{
			throw new Error('Failsafe Salsa20 RNG has not been initialised with a key.\n' + new Error().stack);
		}

		// Get at least one byte from the Web Crypto API if less than 8 bits is required
		var requiredNumOfBytes = 1;

		// If more than 8 bits is required
		if (numOfBits > 8)
		{
			// Find out how many bytes to get. If not cleanly divisible by 8 bits, get the next whole number of bytes
			// so at least that many bits is collected from the Web Crypto API e.g. 17 bits will get 24 bits (3 bytes)
			requiredNumOfBytes = Math.ceil(numOfBits / 8);
		}

		// Initialise a typed array and fill it with 0 bytes
		var webCryptoRandomBytes = new Uint8Array(requiredNumOfBytes);

		try {
			// Fill array with required number of random bytes from the Web Crypto API
			window.crypto.getRandomValues(webCryptoRandomBytes);
		}
		catch (exception)
		{
			// If there is a failure getting random bytes from the Web Crypto API then halt program execution
			throw new Error('Failed to get ' + requiredNumOfBytes + ' random values from Web Crypto API.\n' + exception + '\n' + new Error().stack);
		}

		// Encrypt the bytes from the Web Crypto API with a key only the user knows. This prevents flaws in the
		// Web Crypto API or underlying operating system's RNG from compromising the security of the program.
		var encryptedRandomBytesHex = Salsa20.encrypt(failsafeRngKey, webCryptoRandomBytes, 0, 0, { returnType: 'hex' });

		// If hexadecimal format is needed
		if (returnFormat === 'hexadecimal')
		{
			// Determine how many hexadecimal symbols to return and truncate the output to desired length
			var numOfHexSymbols = Math.floor(numOfBits / 4);
			var randomBitsHexadecimal = encryptedRandomBytesHex.substr(0, numOfHexSymbols);

			return randomBitsHexadecimal;
		}
		else {
			// Convert to binary string e.g. '101001010...' then truncate the output to exact length required
			var randomBitsBinary = common.convertHexadecimalToBinary(encryptedRandomBytesHex);
			randomBitsBinary = randomBitsBinary.substr(0, numOfBits);

			return randomBitsBinary;
		}
	}
};
