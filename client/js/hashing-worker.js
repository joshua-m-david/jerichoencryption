/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software, design and associated documentation files (the "Software"), 
	to deal in the Software including without limitation the rights to use, copy, 
	modify, merge, publish, distribute, and to permit persons to whom the Software 
	is furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies of the Software and any other software that utilises part or all
	   of the Software (the "Derived Software").
	2) Neither the Software nor any Derived Software may be sold, published, 
	   distributed or otherwise dealt with for financial gain without the express
	   consent of the copyright holder.
	3) Derived Software must not use the same name as the Software.
	4) The Software and Derived Software must not be used for evil purposes.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
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
importScripts('lib/jscrypto-sha2-512.js');
importScripts('lib/jscrypto-sha3.js');
importScripts('lib/whirlpool.js');

// Get data from the process which started the worker thread (rng.combineAllEntropyPools function)
self.addEventListener('message', function(e)
{
	// Hash the entropy
	var data = e.data;
	var hashedEntropyPoolString = hasher.hashEntropy(data.combinedEntropyPoolString, data.hashAlgorithms, data.numBytesToFeedIntoHash);
	
	// Send the hashed entropy back to the main thread
	self.postMessage(hashedEntropyPoolString);
	
}, false);


/**
 * This will take the collected entropy and process them into a form fit for use as one-time pad key material. It uses 
 * the latest revisions of either SHA-2, SHA-3 Keccak or Whirlpool in case there is a bias, pattern or a pre-image attack 
 * becomes known later in one of the hashes. This program uses the 512 bit versions of these algorithms for security and 
 * for consistency with the other algorithms. For SHA-3 the original Keccak algorithm is used.
 * 
 * See these pages for more details:
 * http://en.wikipedia.org/wiki/Sha2
 * http://en.wikipedia.org/wiki/SHA-3
 * http://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29
 */ 
var hasher = {
	
	/**
	 * Hashes the entropy
	 * @param {string} combinedEntropyPoolString All raw entropy that has been shuffled
	 * @param {array} hashAlgorithms List of hash algorithms to use to hash the entropy
	 * @param {number} numBytesToFeedIntoHash The number of raw entropy bytes to feed into the hash each time
	 * @return {string} Returns a string containing the entropy hashed
	 */
	hashEntropy: function(combinedEntropyPoolString, hashAlgorithms, numBytesToFeedIntoHash)
	{
		// Initialisations
		var lastAlgorithmIndex = hashAlgorithms.length - 1;					// Index of last algorithm in array
		var inputLength = numBytesToFeedIntoHash;							// Number of bytes to feed into the hash
		var entropyLength = combinedEntropyPoolString.length;				// Length of combined entropy		
		var hashedEntropyPoolString = '';
		var currentAlgorithmIndex = 0;
		
		// Loop through, grab x bytes of entropy then hash with one of the 512 bit hash functions
		for (var startPosition=0; startPosition < entropyLength; startPosition += inputLength)
		{
			// Reset counter back
			currentAlgorithmIndex = (currentAlgorithmIndex > lastAlgorithmIndex) ? 0 : currentAlgorithmIndex;
			
			// Get x bytes of input to be hashed, if the input is less than x bytes i.e. near the 
			// end of the entropy, then break out and don't hash any more entropy
			var entropy = combinedEntropyPoolString.substr(startPosition, inputLength);			
			if (entropy.length < inputLength)
			{
				break;
			}
			
			// Hash the entropy using an alternate algorithm each loop
			hashedEntropyPoolString += common.secureHash(hashAlgorithms[currentAlgorithmIndex], entropy);
			
			// Increment to use next hash algorithm
			currentAlgorithmIndex++;
		}
		
		return hashedEntropyPoolString;
	}
}