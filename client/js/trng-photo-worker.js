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
 * Web worker for the Photo TRNG
 */
var trngImgWorker = {

	hashAlgorithm: null,
	entropyInputEstimatePerPixel: null,
	dataset: null,
	currentDatasetStartIndex: 0,
	
	/**
	 * Hashes the entropy in the photo
	 * @param {String} hashAlgorithm
	 * @param {Number} entropyInputEstimatePerPixel
	 * @param {Array} dataset
	 * @returns {String}
	 */
	init: function(hashAlgorithm, entropyInputEstimatePerPixel, dataset)
	{
		// Store so only one copy of the large array
		trngImgWorker.hashAlgorithm = hashAlgorithm;
		trngImgWorker.entropyInputEstimatePerPixel = entropyInputEstimatePerPixel;
		trngImgWorker.dataset = dataset;
				
		// Get 512 bits worth of input entropy and hash it to get 512 bits for the initial seed
		var inputEntropy = trngImgWorker.getRandomBits();
		
		// If there is not enough entropy to create the seed, exit early
		if (inputEntropy === false)
		{
			return {
				extractedRandomDataBinary: '',
				extractedRandomDataHexadecimal: ''			
			};
		}
		
		// Create the initial seed by hashing the entropy
		var seed = common.secureHash(trngImgWorker.hashAlgorithm, inputEntropy);
		
		// Loop initialisations
		var moreEntropyToHash = true;
		var extractedRandomDataHexadecimal = '';
		
		// Loop through and process the entropy in the photo
		while (moreEntropyToHash)
		{
			// Get 512 bits worth of entropy
			inputEntropy = trngImgWorker.getRandomBits();
									
			// Break the loop if there is not enough entropy left
			if (inputEntropy === false)
			{
				moreEntropyToHash = false;
			}
			else {
				// Hash the previous seed and new input entropy to get a random output of 512 bits (128 hexadecimal symbols)
				var hashedEntropy = common.secureHash(trngImgWorker.hashAlgorithm, seed + inputEntropy);
				
				// Append the first 256 bits of hash output to the overall output (256 bits = 64 hexadecimal symbols)
				extractedRandomDataHexadecimal += hashedEntropy.substr(0, 64);
				
				// Update the seed to be the last 256 bits of the hash output
				seed = hashedEntropy.substr(64);
			}			
		}
		
		// Convert the hexadecimal to binary which is later used in the randomness tests and display output
		var extractedRandomDataBinary = common.convertHexadecimalToBinary(extractedRandomDataHexadecimal);
		
		// Return the binary and hexadecimal representations of the data
		return {
			extractedRandomDataBinary: extractedRandomDataBinary,
			extractedRandomDataHexadecimal: extractedRandomDataHexadecimal			
		};
	},
	
	/**
	 * Get random bits from the photo's RGB values
	 * @returns {String|false} Return the random bits as a hexadecimal string or false if not enough
	 */
	getRandomBits: function()
	{
		// The total of RGB values required to make x bits of entropy
		var rgbValuesPerPixel = 3;
		var bitsRequired = 512;
		var numOfPixelsRequired = bitsRequired / trngImgWorker.entropyInputEstimatePerPixel;
		var totalRequiredRgbValues = Math.round(numOfPixelsRequired * rgbValuesPerPixel);

		// Get the RGB values required to make up x bits of entropy
		var start = trngImgWorker.currentDatasetStartIndex;
		var end = trngImgWorker.currentDatasetStartIndex + totalRequiredRgbValues;
		var rgbValues = trngImgWorker.dataset.slice(start, end);
		var rgbValuesLength = rgbValues.length;
		
		// Check to make sure enough length has been retrieved
		if (rgbValuesLength < totalRequiredRgbValues)
		{
			return false;
		}
		
		var entropyHexadecimal = '';

		// Build up the x bits of entropy
		for (var i = 0; i < rgbValuesLength; i++)
		{
			// Convert each integer value to hexadecimal and concatenate to the seed
			entropyHexadecimal += common.convertSingleByteIntegerToHex(rgbValues[i]);						
		}
		
		// Update the new start index to the start of new entropy, so next call to this function will get new entropy
		trngImgWorker.currentDatasetStartIndex = end;

		return entropyHexadecimal;
	}
};