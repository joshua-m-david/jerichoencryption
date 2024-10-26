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
 * Web worker for the TRNG
 */
var trngWorker = {

	/**
	 * For each image, get the least significant bits of each pixel colour and XOR them together, then XOR the results
	 * of both images together, then run the Basic Von Neumann Extractor on the data to get a final output
	 * @param {Uint8ClampedArray} dataImageA The RGBA values for each pixel in the first image
	 * @param {Uint8ClampedArray} dataImageB The RGBA values for each pixel in the second image
	 * @returns {Object} Returns an object with the processed results
	 */
	process: function(dataImageA, dataImageB)
	{
        // Check for repeating/stuck pixels in both images
		var repeatingPixelIndexes = trngWorker.checkForRepeatingPixels(dataImageA, dataImageB);
		var repeatingPixelDataImage = trngWorker.replaceRepeatingPixelsWithRed(dataImageA, repeatingPixelIndexes);

		// Get the least significant bits of each pixel colour and XOR them together
		var randomBitsFirstImageBinary = trngWorker.getLeastSigBitsFromArray(dataImageA);
		var randomBitsSecondImageBinary = trngWorker.getLeastSigBitsFromArray(dataImageB);

		// XOR the random bits from the two images together then run the basic Von Neumann extractor
		var randomBitsXoredBinary = trngWorker.getXoredLeastSigBits(randomBitsFirstImageBinary, randomBitsSecondImageBinary);
		var randomBitsExtractedBinary = trngWorker.vonNeumannExtractor(randomBitsXoredBinary);

		// Convert to hexadecimal format as well which is needed for export
		var randomBitsFirstImageHex = common.convertBinaryToHexadecimal(randomBitsFirstImageBinary);
		var randomBitsSecondImageHex = common.convertBinaryToHexadecimal(randomBitsSecondImageBinary);
		var randomBitsXoredHex = common.convertBinaryToHexadecimal(randomBitsXoredBinary);
		var randomBitsExtractedHex = common.convertBinaryToHexadecimal(randomBitsExtractedBinary);

		return {
			// The repeating pixels to be rendered
			repeatingPixelIndexes: repeatingPixelIndexes,
			repeatingPixelDataImage: repeatingPixelDataImage,

			// The data as binary
			randomBitsFirstImageBinary: randomBitsFirstImageBinary,
			randomBitsSecondImageBinary: randomBitsSecondImageBinary,
			randomBitsXoredBinary: randomBitsXoredBinary,
			randomBitsExtractedBinary: randomBitsExtractedBinary,

			// The data as hexadecimal
			randomBitsFirstImageHex: randomBitsFirstImageHex,
			randomBitsSecondImageHex: randomBitsSecondImageHex,
			randomBitsXoredHex: randomBitsXoredHex,
			randomBitsExtractedHex: randomBitsExtractedHex
		};
	},

	/**
	 * Check the images to see if they have the same colour (all same RGB values) at the same pixel location. If found
	 * this could be indicative of a bad camera sensor (if they used images from the same camera), or the images
	 * contained overexposure (e.g. from direct sunlight) in the same places.
	 * @param {Uint8ClampedArray} dataImageA The pixel data from the first image
	 * @param {Uint8ClampedArray} dataImageB The pixel data from the second image
	 * @returns {Array} Returns the indexes of all the stuck pixels or an empty array if there were none
	 */
	checkForRepeatingPixels: function(dataImageA, dataImageB)
	{
		// Initialisations
		var repeatingPixelIndexes = [];
		var dataMaxLength = dataImageA.length;

		// Set the maximum data length to the length of the shortest image
		if (dataImageA.length >= dataImageB.length) {
			dataMaxLength = dataImageB.length;
		}

		// Enumerate all RGBA values for each pixel which are stored in a sequential array
		for (var i = 0; i < dataMaxLength; i += 4)
		{
			// Get the array indexes for each RGB value
			var redIndex = i;
			var greenIndex = i + 1;
			var blueIndex = i + 2;

			// Get the separate red, green and blue pixel values for the first image
			var redA = dataImageA[redIndex];
			var greenA = dataImageA[greenIndex];
			var blueA = dataImageA[blueIndex];

			// Get the separate red, green and blue pixel values for the second image
			var redB = dataImageB[redIndex];
			var greenB = dataImageB[greenIndex];
			var blueB = dataImageB[blueIndex];

			// If all the colours are the same in both images then the pixel is the same in both images
			if ((redA === redB) && (greenA === greenB) && (blueA === blueB))
			{
				// At the starting index for the pixel's RGBA value
				repeatingPixelIndexes.push(redIndex);
			}
		}

		return repeatingPixelIndexes;
	},

	/**
	 * Replaces the repeating images on the first image with red pixels
	 * so the problem areas can be identified visually by the user.
	 * @param {Uint8ClampedArray} dataImageA The first image data as RGBA values
	 * @param {Array} repeatingPixelIndexes The indexes of the repeating/stuck pixels
	 * @returns {Uint8ClampedArray} Returns a new array with red pixels where there were repeating/stuck pixels
	 */
	replaceRepeatingPixelsWithRed: function(dataImageA, repeatingPixelIndexes)
	{
		// If there are no repeating/stuck pixels just return an empty array
		if (repeatingPixelIndexes.length === 0) {
			return new Uint8ClampedArray(0);
		}

		// Make a clone of the original array so we don't modify the original image data as it is used later!
		var overlayedDataImage = dataImageA.slice(0);

		// Loop through all the pixels
		for (var i = 0; i < repeatingPixelIndexes.length; i++)
		{
			// Get the start index of the pixel to be modified (the start is the red value)
			var pixelIndex = repeatingPixelIndexes[i];

			// Colour the pixel as pure red (#ff0000)
			overlayedDataImage[pixelIndex] = 255;
			overlayedDataImage[pixelIndex + 1] = 0;
			overlayedDataImage[pixelIndex + 2] = 0;
		}

		return overlayedDataImage;
	},

	/**
	 * Get the least significant bits (https://en.wikipedia.org/wiki/Least_significant_bit) from the image data. It
	 * does this by taking the least significant bit from each colour in each pixel. Each pixel will produce 3 bits
	 * from the red, green and blue colours. These bits are then XORed together and that bit is appended to the output.
	 * @param {Array} imgDataArr The sequential array of red, green blue, alpha (RGBA) values from the image
	 * @returns {String} The random bits
	 */
	getLeastSigBitsFromArray: function(imgDataArr)
	{
		var randomBits = '';

		// Enumerate all RGBA values for each pixel which are stored in a sequential array
		for (var i = 0, length = imgDataArr.length; i < length; i += 4)
		{
			// Get the separate red, green and blue pixels per colour
			var red = imgDataArr[i];
			var green = imgDataArr[i + 1];
			var blue = imgDataArr[i + 2];

			// Convert each colour from an integer (0 - 255) to an 8 bit binary string
			var redBinary = common.convertIntegerToBinary(red, 8);
			var greenBinary = common.convertIntegerToBinary(green, 8);
			var blueBinary = common.convertIntegerToBinary(blue, 8);

			// Get the least significant bit from each colour e.g. 00000001 returns 1
			var redLeastSignificantBit = redBinary.substr(7, 1);
			var greenLeastSignificantBit = greenBinary.substr(7, 1);
			var blueLeastSignificantBit = blueBinary.substr(7, 1);

			// XOR the least significant bits and append to the previous output
			randomBits += (redLeastSignificantBit ^ greenLeastSignificantBit ^ blueLeastSignificantBit);
		}

		return randomBits;
	},

	/**
	 * Get the least significant bits from two images and XOR them together. If one image has more bits than the other
	 * then the final result will only have the same number of bits as the image with the least amount of bits.
	 * @param {String} entropyBitsImageA The least significant bits from the first image
	 * @param {String} entropyBitsImageB The least significant bits from the second image
	 * @returns {String} Returns the XORed least significant bits from both images
	 */
	getXoredLeastSigBits: function(entropyBitsImageA, entropyBitsImageB)
	{
		// Get the number of returned bits for each image
		var numOfBitsImageA = entropyBitsImageA.length;
		var numOfBitsImageB = entropyBitsImageB.length;

		// Detect which image has more bits
		if (numOfBitsImageA > numOfBitsImageB)
		{
			// Truncate image A to the size of image B
			entropyBitsImageA = entropyBitsImageA.substr(0, numOfBitsImageB);
		}
		else {
			// Otherwise truncate image B to the size of image A
			entropyBitsImageB = entropyBitsImageB.substr(0, numOfBitsImageA);
		}

		// XOR the entropy bits from the two images together
		var xoredEntropyBits = common.xorBits(entropyBitsImageA, entropyBitsImageB);

		return xoredEntropyBits;
	},

	/**
	 * The Basic Von Neumann extractor works for any exchangeable sequence of bits and produces a uniform output even if
	 * the distribution of input bits is not uniform. This function works by comparing pairs of bits. For each pair, if
	 * the bits are equal they are discarded. If the pair of bits are not equal, then the first bit is output. E.g.
	 * 00 -> discard
	 * 01 -> output 0
	 * 10 -> output 1
	 * 11 -> discard
	 * See: https://en.wikipedia.org/wiki/Randomness_extractor#Von_Neumann_extractor
	 * Also: https://en.wikipedia.org/wiki/Bernoulli_process#Basic_Von_Neumann_extractor
	 * @param {String} rawBits The raw binary data to extract from
	 * @returns {String} Returns the whitened binary data
	 */
	vonNeumannExtractor: function(rawBits)
	{
		var output = '';

		// Loop through the bits and compare two bits at a time
		for (var i = 0, numOfBits = rawBits.length;  i < numOfBits;  i += 2)
		{
			var bitA = rawBits.charAt(i);
			var bitB = rawBits.charAt(i + 1);

			// No output if bits are the same
			if (bitA !== bitB)
			{
				// If bits are different, output the first bit
				output += bitA;
			}
		}

		return output;
	}
};
