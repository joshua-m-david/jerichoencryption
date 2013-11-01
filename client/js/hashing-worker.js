/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
*/

/**
 * Cryptographic hash functions take data which isn't necessarily uniformly distributed but still contain entropy, and 
 * convert them into a uniformly distributed bitstring with entropy approximately equal to the input (up to the hash 
 * function's output size). This script is called by a HTML5 Web Worker to do the hashing asynchronously and not block the UI.
 */

// Import scripts to be used
importScripts('common.js');
importScripts('lib/jscrypto-core.js');
importScripts('lib/jscrypto-x64core.js');
importScripts('lib/jscrypto-sha3.js');
importScripts('lib/whirlpool.js');

// Get data from the process which started the worker thread (rng.combineAllEntropyPools function)
self.addEventListener('message', function(e)
{
	// Hash the entropy
	var data = e.data;
	var hashedEntropyStringHexadecimal = hasher.hashEntropy(data.combinedEntropyString, data.numBitsToFeedIntoHash);
	
	// Send the hashed entropy back to the main thread
	self.postMessage(hashedEntropyStringHexadecimal);
	
}, false);


/**
 * This will take the collected entropy and process them into a form fit for use as one-time pad key material. It uses 
 * the latest revisions of either Whirlpool and Keccak hash algorithms in case there is a bias or pattern that becomes 
 * known later in one of the hashes. This program uses the 512 bit versions of these algorithms for security and 
 * for consistency with the other algorithms. The original Keccak algorithm which won the SHA-3 competition is used 
 * rather than the final SHA-3 standard which NIST has been modifying/weakening.
 * 
 * See these pages for more details:
 * http://en.wikipedia.org/wiki/SHA-3
 * http://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29
 */ 
var hasher = {
	
	/**
	 * Hashes the entropy
	 * @param {string} combinedEntropyString All raw entropy
	 * @param {number} numBitsToFeedIntoHash The number of entropy bits to feed into the hash each time
	 * @return {string} Returns a string containing the entropy hashed
	 */
	hashEntropy: function(combinedEntropyString, numBitsToFeedIntoHash)
	{
		var hashedEntropyStringHexadecimal = '';
		
		// Get an array containing groups of entropy to feed into the hash
		var allEntropyInputToHash = hasher.getBytesToHash(combinedEntropyString, numBitsToFeedIntoHash);
				
		// Loop through, grab x bytes of entropy then hash with one of the 512 bit hash functions
		for (var i=0; i < allEntropyInputToHash.length; i++)
		{
			// Hash the entropy separately with Keccak and then hash the same entropy separately with Whirlpool
			var firstHash = common.secureHash('sha3-512', allEntropyInputToHash[i]);			
			var secondHash = common.secureHash('whirlpool-512', allEntropyInputToHash[i]);
						
			// Convert the hash outputs to binary
			var firstHashBinary = common.convertHexadecimalToBinary(firstHash);
			var secondHashBinary = common.convertHexadecimalToBinary(secondHash);
						
			// XOR the hash outputs together using the same XOR function used for encryption/decryption, then convert to hexadecimal
			var xoredHash = common.encryptOrDecrypt(firstHashBinary, secondHashBinary);
			var xoredHashHexadecimal = common.convertBinaryToHexadecimal(xoredHash);
						
			// Build up the hashed entropy to return
			hashedEntropyStringHexadecimal += xoredHashHexadecimal;
		}		
		
		return hashedEntropyStringHexadecimal;
	},
	
	/**
	 * Extracts the entropy into groups of approximately x bits worth of entropy to be hashed
	 * @param {string} combinedEntropyString
	 * @param {number} numBitsToFeedIntoHash
	 * @returns {array}
	 */
	getBytesToHash: function(combinedEntropyString, numBitsToFeedIntoHash)
	{
		// Initialisations
		var entropyLength = combinedEntropyString.length;		// Length of combined entropy
		var allEntropyInputToHash = [];							// Array of separate groups of entropy to feed into the hash
		var currentEntropyForHash = '';							// Current accumulation of entropy to input into the hash
		var currentEntropyBitCount = 0;							// Current count of the entropy in bits
		
		// Loop through the entropy one number/byte at a time
		for (var i=0; i < entropyLength; i++)
		{
			// Get number at this index
			var num = combinedEntropyString.charAt(i);
						
			// Each number from 0-7 in ASCII has 3 bits of entropy at the end. The last 3 binary 
			// digits of 8 & 9 are a repeat of 0 and 1 in binary so we exclude them from the estimate
			if ((num != '8') && (num != '9'))
			{
				currentEntropyBitCount += 3;
			}
			
			// Append the number to the entropy to be input to the hash
			currentEntropyForHash += num.toString();
						
			// If there is enough entropy for a hash store that group of entropy.
			// If there is not enough entropy for another hash the remainder won't be used.
			if (currentEntropyBitCount >= numBitsToFeedIntoHash)
			{				
				// Store that in an array and reset the counters
				allEntropyInputToHash.push(currentEntropyForHash);
				currentEntropyForHash = '';
				currentEntropyBitCount = 0;
			}
		}
				
		// Return the separate groups of entropy to feed into the hash
		return allEntropyInputToHash;
	}
};