/*! Whirlpool Hashing Function v3.0 ~ Sean Catchpole - Copyright 2009 Public Domain */
/*
  Whirlpool was created by Paulo S.L.M. Barreto and Vincent Rijmen in 2000
  This javascript implimentation of whirlpool could probably use a lot of
  impovement, please feel free to make it better in any way you can.
  Please note that javascript only supports 32bit bitwise operations so all
  the long(64) were converted into [int(32),int(32)]
*/

;(function(){
  var WP, R=10, C=[], rc=[], t, x, c, r, i,
      v1, v2, v4, v5, v8, v9, sbox=
  "\u1823\uc6E8\u87B8\u014F\u36A6\ud2F5\u796F\u9152"+
  "\u60Bc\u9B8E\uA30c\u7B35\u1dE0\ud7c2\u2E4B\uFE57"+
  "\u1577\u37E5\u9FF0\u4AdA\u58c9\u290A\uB1A0\u6B85"+
  "\uBd5d\u10F4\ucB3E\u0567\uE427\u418B\uA77d\u95d8"+
  "\uFBEE\u7c66\udd17\u479E\ucA2d\uBF07\uAd5A\u8333"+
  "\u6302\uAA71\uc819\u49d9\uF2E3\u5B88\u9A26\u32B0"+
  "\uE90F\ud580\uBEcd\u3448\uFF7A\u905F\u2068\u1AAE"+
  "\uB454\u9322\u64F1\u7312\u4008\uc3Ec\udBA1\u8d3d"+
  "\u9700\ucF2B\u7682\ud61B\uB5AF\u6A50\u45F3\u30EF"+
  "\u3F55\uA2EA\u65BA\u2Fc0\udE1c\uFd4d\u9275\u068A"+
  "\uB2E6\u0E1F\u62d4\uA896\uF9c5\u2559\u8472\u394c"+
  "\u5E78\u388c\ud1A5\uE261\uB321\u9c1E\u43c7\uFc04"+
  "\u5199\u6d0d\uFAdF\u7E24\u3BAB\ucE11\u8F4E\uB7EB"+
  "\u3c81\u94F7\uB913\u2cd3\uE76E\uc403\u5644\u7FA9"+
  "\u2ABB\uc153\udc0B\u9d6c\u3174\uF646\uAc89\u14E1"+
  "\u163A\u6909\u70B6\ud0Ed\ucc42\u98A4\u285c\uF886";

  for(t=8; t-->0;) C[t]=[];
  for(x=0; x<256; x++) {
      c = sbox.charCodeAt(x/2);
      v1 = ((x & 1) == 0) ? c >>> 8 : c & 0xff;
      v2 = v1 << 1;
      if (v2 >= 0x100)
          v2 ^= 0x11d;
      v4 = v2 << 1;
      if (v4 >= 0x100)
          v4 ^= 0x11d;
      v5 = v4 ^ v1;
      v8 = v4 << 1;
      if (v8 >= 0x100)
          v8 ^= 0x11d;
      v9 = v8 ^ v1;

      // Build the circulant table C[0][x] = S[x].[1, 1, 4, 1, 8, 5, 2, 9]:
      C[0][x]=[0,0];
      C[0][x][0] = (v1 << 24) | (v1 << 16) | (v4 <<  8) | (v1);
      C[0][x][1] = (v8 << 24) | (v5 << 16) | (v2 <<  8) | (v9);

      // Build the remaining circulant tables C[t][x] = C[0][x] rotr t
      for (var t=1; t<8; t++) {
        C[t][x]=[0,0];
        C[t][x][0] = (C[t - 1][x][0] >>> 8) | ((C[t - 1][x][1] << 24));
        C[t][x][1] = (C[t - 1][x][1] >>> 8) | ((C[t - 1][x][0] << 24));
      }
  }

  // Build the round constants:
  rc[0] = [0,0];
  for (r=1; r<=R; r++) {
    i = 8*(r - 1);
    rc[r]=[0,0];
    rc[r][0] = (C[0][i    ][0] & 0xff000000)^
               (C[1][i + 1][0] & 0x00ff0000)^
               (C[2][i + 2][0] & 0x0000ff00)^
               (C[3][i + 3][0] & 0x000000ff);
    rc[r][1] = (C[4][i + 4][1] & 0xff000000)^
               (C[5][i + 5][1] & 0x00ff0000)^
               (C[6][i + 6][1] & 0x0000ff00)^
               (C[7][i + 7][1] & 0x000000ff);
  }

  var bitLength=[], // [32] Global number of hashed bits (256-bit counter).
      buffer=[],    // [64] Buffer of data to hash.
      bufferBits=0, // Current number of bits on the buffer.
      bufferPos=0,  // Current (possibly incomplete) byte slot on the buffer.
      // The following longs are split into [int,int]
      hash=[],      // [8] the hashing state
      K=[],         // [8] the round key
      L=[],         // [8] temp key?
      block=[],     // [8] mu(buffer)
      state=[];     // [8] the chipher state

  // The core Whirlpool transform.
  var processBuffer = function(){
    var i,j,r,s,t;
    // map the buffer to a block:
    for(i=0,j=0; i<8; i++,j+=8) {
      block[i]=[0,0];
      block[i][0] = ((buffer[j    ] & 0xff) << 24)^
                    ((buffer[j + 1] & 0xff) << 16)^
                    ((buffer[j + 2] & 0xff) <<  8)^
                    ((buffer[j + 3] & 0xff)      );
      block[i][1] = ((buffer[j + 4] & 0xff) << 24)^
                    ((buffer[j + 5] & 0xff) << 16)^
                    ((buffer[j + 6] & 0xff) <<  8)^
                    ((buffer[j + 7] & 0xff)      );
    }
    // compute and apply K^0 to the cipher state:
    for (i=0; i<8; i++) {
      state[i]=[0,0]; K[i]=[0,0];
      state[i][0] = block[i][0] ^ (K[i][0] = hash[i][0]);
      state[i][1] = block[i][1] ^ (K[i][1] = hash[i][1]);
    }
    // iterate over all rounds:
    for (r=1; r<=R; r++) {
      // compute K^r from K^{r-1}:
      for (i=0; i<8; i++) {
        L[i]=[0,0];
        for (t=0,s=56,j=0; t<8; t++,s-=8,j=s<32?1:0) {
          L[i][0] ^= C[t][(K[(i - t) & 7][j] >>> (s%32)) & 0xff][0];
          L[i][1] ^= C[t][(K[(i - t) & 7][j] >>> (s%32)) & 0xff][1];
        }
      }
      for (i=0; i<8; i++) {
        K[i][0] = L[i][0];
        K[i][1] = L[i][1];
      }
      K[0][0] ^= rc[r][0];
      K[0][1] ^= rc[r][1];
      // apply the r-th round transformation:
      for (i=0; i<8; i++) {
        L[i][0] = K[i][0];
        L[i][1] = K[i][1];
        for (t=0,s=56,j=0; t<8; t++,s-=8,j=s<32?1:0) {
          L[i][0] ^= C[t][(state[(i - t) & 7][j] >>> (s%32)) & 0xff][0];
          L[i][1] ^= C[t][(state[(i - t) & 7][j] >>> (s%32)) & 0xff][1];
        }
      }
      for (i=0; i<8; i++) {
        state[i][0] = L[i][0];
        state[i][1] = L[i][1];
      }
    }
    // apply the Miyaguchi-Preneel compression function:
    for (i=0; i<8; i++) {
      hash[i][0] ^= state[i][0] ^ block[i][0];
      hash[i][1] ^= state[i][1] ^ block[i][1];
    }
  };

  WP = Whirlpool = function(str){ return WP.init().add(str).finalize(); };
  WP.version = "3.0";

  // Initialize the hashing state.
  WP.init = function(){
    for(var i=32; i-->0;) bitLength[i]=0;
    bufferBits = bufferPos = 0;
    buffer = [0]; // it's only necessary to cleanup buffer[bufferPos].
    for(i=8; i-->0;) hash[i]=[0,0];
    return WP;
  };

  // Convert string into byte array
  var convert = function(source){
    var i,n,str=source.toString(); source=[];
    for(i=0; i<str.length; i++) {
      n = str.charCodeAt(i);
      if(n>=256) source.push(n>>>8 & 0xFF);
      source.push(n & 0xFF);
    }
    return source;
  };
  
  // Delivers input data to the hashing algorithm. Assumes bufferBits < 512
  WP.add = function(source,sourceBits){
    /*
                       sourcePos
                       |
                       +-------+-------+-------
                          ||||||||||||||||||||| source
                       +-------+-------+-------
    +-------+-------+-------+-------+-------+-------
    ||||||||||||||||||||||                           buffer
    +-------+-------+-------+-------+-------+-------
                    |
                    bufferPos
    */
    if(!source) return WP;
    if(!sourceBits) {
      source = convert(source);
      sourceBits = source.length*8;
    }
    var sourcePos = 0, // index of leftmost source byte containing data (1 to 8 bits).
        sourceGap = (8 - (sourceBits & 7)) & 7, // space on source[sourcePos].
        bufferRem = bufferBits & 7, // occupied bits on buffer[bufferPos].
        i, b, carry, value = sourceBits;
    for (i=31, carry=0; i>=0; i--) { // tally the length of the added data
      carry += (bitLength[i] & 0xff) + (value % 256);
      bitLength[i] = carry & 0xff;
      carry >>>= 8;
      value = Math.floor(value/256);
    }
    // process data in chunks of 8 bits:
    while (sourceBits > 8) { // at least source[sourcePos] and source[sourcePos+1] contain data.
      // take a byte from the source:
      b = ((source[sourcePos] << sourceGap) & 0xff) |
        ((source[sourcePos + 1] & 0xff) >>> (8 - sourceGap));
      if (b < 0 || b >= 256) return "Whirlpool requires a byte array";
      // process this byte:
      buffer[bufferPos++] |= b >>> bufferRem;
      bufferBits += 8 - bufferRem; // bufferBits = 8*bufferPos;
      if (bufferBits == 512) {
        processBuffer(); // process data block
        bufferBits = bufferPos = 0; buffer=[]; // reset buffer
      }
      buffer[bufferPos] = ((b << (8 - bufferRem)) & 0xff);
      bufferBits += bufferRem;
      // proceed to remaining data
      sourceBits -= 8;
      sourcePos++;
    }
    // now 0 <= sourceBits <= 8;
    // furthermore, all data (if any is left) is in source[sourcePos].
    if (sourceBits > 0) {
      b = (source[sourcePos] << sourceGap) & 0xff; // bits are left-justified on b.
      buffer[bufferPos] |= b >>> bufferRem; // process the remaining bits
    } else { b = 0; }
    if (bufferRem + sourceBits < 8) {
      // all remaining data fits on buffer[bufferPos], and there still remains some space.
      bufferBits += sourceBits;
    } else {
      bufferPos++; // buffer[bufferPos] is full
      bufferBits += 8 - bufferRem; // bufferBits = 8*bufferPos;
      sourceBits -= 8 - bufferRem;
      // now 0 <= sourceBits < 8; furthermore, all data is in source[sourcePos].
      if (bufferBits == 512) {
        processBuffer(); // process data block
        bufferBits = bufferPos = 0; buffer=[]; // reset buffer
      }
      buffer[bufferPos] = ((b << (8 - bufferRem)) & 0xff);
      bufferBits += sourceBits;
    }
    return WP;
  };

  // Get the hash value from the hashing state. Assumes bufferBits < 512
  WP.finalize = function(){
    var i,j,h, str="", digest=[], hex="0123456789ABCDEF".split('');
    buffer[bufferPos] |= 0x80 >>> (bufferBits & 7); // append a '1'-bit:
    bufferPos++; // all remaining bits on the current byte are set to zero.
    if(bufferPos > 32) { // pad with zero bits to complete 512N + 256 bits:
      while (bufferPos < 64) buffer[bufferPos++] = 0;
      processBuffer(); // process data block
      bufferPos = 0; buffer=[]; // reset buffer
    }
    while(bufferPos < 32) buffer[bufferPos++] = 0;
    buffer.push.apply(buffer,bitLength); // append bit length of hashed data
    processBuffer(); // process data block
    for(i=0,j=0; i<8; i++,j+=8) { // return the completed message digest
      h = hash[i][0];
      digest[j    ] = h >>> 24 & 0xFF;
      digest[j + 1] = h >>> 16 & 0xFF;
      digest[j + 2] = h >>>  8 & 0xFF;
      digest[j + 3] = h        & 0xFF;
      h = hash[i][1];
      digest[j + 4] = h >>> 24 & 0xFF;
      digest[j + 5] = h >>> 16 & 0xFF;
      digest[j + 6] = h >>>  8 & 0xFF;
      digest[j + 7] = h        & 0xFF;
    }
    for(i=0; i<digest.length; i++) {
      str+=hex[digest[i] >>> 4];
      str+=hex[digest[i] & 0xF];
    }
    return str;
  };

})();
