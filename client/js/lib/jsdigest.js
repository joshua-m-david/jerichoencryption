/**!
 *  jsDigest v2.0.1 (2012-01-01 11:28:39 UTC)
 *  http://github.com/coiscir/jsdigest/
 *
 *  Copyright (c) 2009-2011 Jonathan Lonowski
 *  Released and distributed under the MIT License.
**/

(function () { "use strict";

var self = { Version: '2.0.1' };


function factorMAC( MAC, FN, DIGEST, BLOCK ) {
  return function ( size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = DIGEST;
    }
    
    size = Math.max( 0, Math.min( DIGEST, size ) );
    
    var result;

    if ( null == key ) {
      result = FN( toBuffer(data) );
    } else {
      result = MAC( FN, BLOCK, toBuffer(data), toBuffer(key) );
    }
    
    return Encoder( crop( size, result, false ) );
  };
}

function isBuffer( obj ) {
  return '[object Array]' === Object.prototype.toString.call( obj );
}

function toBuffer( input ) {
  if ( isBuffer( input ) )
    return input.slice();
  else
    return utf8( input );
}

function utf8( input ) {
  var i, code,
    length = input.length,
    result = [];
  
  for ( i = 0; i < length; i++ ) {
    code = input.charCodeAt(i);
    
    if ( code < 0x80 ) {
      result.push( code );
    } else if ( code < 0x800 ) {
      result.push( 0xc0 + ( ( code >> 6 ) & 0x1f ) );
      result.push( 0x80 + ( ( code >> 0 ) & 0x3f ) );
    } else {
      result.push( 0xe0 + ( ( code >> 12 ) & 0x0f ) );
      result.push( 0x80 + ( ( code >>  6 ) & 0x3f ) );
      result.push( 0x80 + ( ( code >>  0 ) & 0x3f ) );
    }
  }
  
  return result;
}

function hmac( fn, block, data, key ) {
  var i,
      ipad = [],
      opad = [];
  
  if ( key.length > block )
    key = fn( key );
  
  for ( i = 0; i < block; i++ ) {
    ipad[i] = ( key[i] || 0x00 ) ^ 0x36;
    opad[i] = ( key[i] || 0x00 ) ^ 0x5c;
  }
  
  return fn( opad.concat( fn( ipad.concat( data ) ) ) );
}

function crop( size, hash, righty ) {
  var length = Math.floor( ( size + 7 ) / 8 ),
      remain = size % 8;
  
  if ( righty ) {
    hash = hash.slice( hash.length - length );
  } else {
    hash = hash.slice( 0, length );
  }
  
  if ( remain > 0 ) {
    hash[ length - 1 ] &= ( 0xff << ( 8 - remain ) ) & 0xff;
  }
  
  return hash;
}

self.toBuffer = toBuffer;

self.toArray = function ( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i++ ) {
    output.push( input.charCodeAt(i) & 0xff );
  }
  
  return output;
};


function Encoder( buffer ) {
  
  // Encoder as a function
  if ( !( this instanceof Encoder ) ) {
    return new Encoder( buffer );
  }
  
  
  // raw output
  this.raw = function () {
    return buffer.slice();
  };
  
  
  // RFC-4648 - Base-16
  function encodeBase16( chars ) {
    var i,
        length = buffer.length,
        out = '';
    
    for ( i = 0; i < length; i++ ) {
      out += chars[ ( buffer[i] >> 4 ) & 0xf ] || '?';
      out += chars[ ( buffer[i] >> 0 ) & 0xf ] || '?';
    }
    
    return out;
  }
  
  // 0-9 a-f (lower)
  this.hex = function () {
    return encodeBase16( '0123456789abcdef'.split('') );
  };
  
  // 0-9 A-F (upper)
  this.base16 = function () {
    return encodeBase16( '0123456789ABCDEF'.split('') );
  };
  
  
  // RFC-4648 - Base-32
  function encodeBase32( chars ) {
    var i,
        length = buffer.length,
        out = '',
        rem = null;
    
    for ( i = 0; i < length; i++ ) {
      switch ( i % 5 ) {
        case 0:
          // 00000000 xxxxx000
          out += chars[ ( ( buffer[i] >> 3 ) & 0x1f ) | 0x0 ] || '?';
          rem = ( buffer[i] & 0x07 ) << 2;
          break;
        case 1:
          // 00000rrr xxyyyyy0
          out += chars[ ( ( buffer[i] >> 6 ) & 0x03 ) | rem ] || '?';
          out += chars[ ( ( buffer[i] >> 1 ) & 0x1f ) | 0x0 ] || '?';
          rem = ( buffer[i] & 0x01 ) << 4;
          break;
        case 2:
          // 0000000r xxxx0000
          out += chars[ ( ( buffer[i] >> 4 ) & 0x0f ) | rem ] || '?';
          rem = ( buffer[i] & 0x0f ) << 1;
          break;
        case 3:
          // 0000rrrr xyyyyy00
          out += chars[ ( ( buffer[i] >> 7 ) & 0x01 ) | rem ] || '?';
          out += chars[ ( ( buffer[i] >> 2 ) & 0x1f ) | 0x0 ] || '?';
          rem = ( buffer[i] & 0x03 ) << 3;
          break;
        case 4:
          // 000000rr xxxyyyyy
          out += chars[ ( ( buffer[i] >> 5 ) & 0x07 ) | rem ] || '?';
          out += chars[ ( ( buffer[i] >> 0 ) & 0x1f ) | 0x0 ] || '?';
          rem = null;
      }
    }
    
    // append remainder
    if ( null != rem ) {
      out += chars[ rem ] || '?';
    }
    
    // append padding
    while ( ( out.length % 8 ) > 0 ) {
      out += '=';
    }
    
    return out;
  }
  
  // A-Z 2-7 (upper)
  this.base32 = function () {
    return encodeBase32( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.split('') );
  };
  
  // 0-9 a-v (lower)
  this.base32hex = function () {
    return encodeBase32( '0123456789abcdefghijklmnopqrstuv'.split('') );
  };
  
  
  // RFC-4648 - Base-64
  function encodeBase64( chars ) {
    var i,
        length = buffer.length,
        out = '',
        rem = null;
    
    for ( i = 0; i < length; i++ ) {
      switch (i % 3) {
        case 0:
          // 00000000 xxxxxx00
          out += chars[ ( ( buffer[i] >> 2 ) & 0x3f ) | 0x0 ] || '?';
          rem = ( buffer[i] & 0x03 ) << 4;
          break;
        case 1:
          // 000000rr xxxx0000
          out += chars[ (  (buffer[i] >> 4 ) & 0x0f ) | rem ] || '?';
          rem = ( buffer[i] & 0x0f ) << 2;
          break;
        case 2:
          // 0000rrrr xxyyyyyy
          out += chars[ ( ( buffer[i] >> 6 ) & 0x03 ) | rem ] || '?';
          out += chars[ ( ( buffer[i] >> 0 ) & 0x3f ) | 0x0 ] || '?';
          rem = null;
          break;
      }
    }
    
    // append remainder
    
    // append remainder
    if ( null != rem ) {
      out += chars[ rem ] || '?';
    }
    
    // append padding
    while ( ( out.length % 4 ) > 0 ) {
      out += '=';
    }
    
    return out;
  }
  
  // A-Z a-z 0-9 + /
  this.base64 = function () {
    return encodeBase64(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('')
    );
  };
  
  // A-Z a-z 0-9 - _ (url/filename safe)
  this.base64url = function () {
    return encodeBase64(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('')
    );
  };
}

self.Encoder = Encoder;


// UInt Operations
function gt_32( x, y ) {
  var a = ( x >> 16 ) & 0xffff,
      b = ( y >> 16 ) & 0xffff;
  
  return ( a > b ) || ( (a === b ) && ( ( x & 0xffff ) > ( y & 0xffff ) ) );
}

function lt_32( x, y ) {
  var a = ( x >> 16 ) & 0xffff,
      b = ( y >> 16 ) & 0xffff;
  
  return ( a < b ) || ( ( a === b ) && ( ( x & 0xffff ) < ( y & 0xffff ) ) );
}

function rotl_32( x, n ) {
  return ( x >>> ( 32 - n ) ) | ( x << n );
}

function rotr_32( x, n ) {
  return ( x >>> n ) | ( x << ( 32 - n ) );
}

// ULong Operations
function ulong( x ) {
  return [ ( x[0] | 0x0 ), ( x[1] | 0x0 ) ];
}

function and( x, y ) {
  return [ x[0] & y[0], x[1] & y[1] ];
}

function or( x, y ) {
  return [ x[0] | y[0], x[1] | y[1] ];
}

function xor( x, y ) {
  return [ x[0] ^ y[0], x[1] ^ y[1] ];
}

function not( x ) {
  return [ ~x[0], ~x[1] ];
}

function shl( x, n ) {
  var a = x[0] | 0x0,
      b = x[1] | 0x0;
  
  if ( n >= 32 ) {
    return [ ( b << ( n - 32 ) ), 0x0 ];
  } else {
    return [ ( ( a << n ) | ( b >>> ( 32 - n ) ) ), ( b << n ) ];
  }
}

function shr( x, n ) {
  var a = x[0] | 0x0,
      b = x[1] | 0x0;
    
  if ( n >= 32 ) {
    return [ 0x0, ( a >>> ( n - 32 ) ) ];
  } else {
    return [ ( a >>> n ), ( ( a << ( 32 - n ) ) | ( b >>> n ) ) ];
  }
}

function rotl( x, n ) {
  return or( shr( x, ( 64 - n ) ), shl( x, n ) );
}

function rotr( x, n ) {
  return or( shr( x, n ), shl( x, ( 64 - n ) ) );
}

function add( x, y ) {
  var b = ( x[1] | 0x0 ) + ( y[1] | 0x0 ),
      a = ( x[0] | 0x0 ) + ( y[0] | 0x0 ) + ( lt_32( b, x[1] ) ? 0x1 : 0x0 );
  
  return [ a, b ];
}

function subt( x, y ) {
  var b = ( x[1] | 0x0 ) - ( y[1] | 0x0 ),
      a = ( x[0] | 0x0 ) - ( y[0] | 0x0 ) - ( gt_32( b, x[1] ) ? 0x1 : 0x0 );
  
  return [ a, b ];
}

function mult( x, y ) {
  var i, a = [ 0x0, 0x0 ];
  
  for ( i = 0; i < 64; i += 1 ) {
    if ( shr( y, i )[1] & 0x1 ) {
      a = add( a, shl( x, i ) );
    }
  }
  
  return a;
}


// Least Significant Byte, 32-bit
function mergeLeast_32( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 4 ) {
    output.push(
      ( ( input[ i + 0 ] & 0xff ) <<  0 ) |
      ( ( input[ i + 1 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 2 ] & 0xff ) << 16 ) |
      ( ( input[ i + 3 ] & 0xff ) << 24 )
    );
  }

  return output;
}

function splitLeast_32( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 1 ) {
    output.push( ( input[i] >>  0 ) & 0xff );
    output.push( ( input[i] >>  8 ) & 0xff );
    output.push( ( input[i] >> 16 ) & 0xff );
    output.push( ( input[i] >> 24 ) & 0xff );
  }

  return output;
}

// Most Significant Byte, 32-bit
function mergeMost_32( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 4 ) {
    output.push(
      ( ( input[ i + 0 ] & 0xff ) << 24 ) |
      ( ( input[ i + 1 ] & 0xff ) << 16 ) |
      ( ( input[ i + 2 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 3 ] & 0xff ) <<  0 )
    );
  }

  return output;
}

function splitMost_32( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 1 ) {
    output.push( ( input[i] >> 24 ) & 0xff );
    output.push( ( input[i] >> 16 ) & 0xff );
    output.push( ( input[i] >>  8 ) & 0xff );
    output.push( ( input[i] >>  0 ) & 0xff );
  }

  return output;
}

// Least Significant Byte, 64-bit
function mergeLeast_64( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 8 ) {
    output.push([
      ( ( input[ i + 4 ] & 0xff ) <<  0 ) |
      ( ( input[ i + 5 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 6 ] & 0xff ) << 16 ) |
      ( ( input[ i + 7 ] & 0xff ) << 24 ),
      ( ( input[ i + 0 ] & 0xff ) <<  0 ) |
      ( ( input[ i + 1 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 2 ] & 0xff ) << 16 ) |
      ( ( input[ i + 3 ] & 0xff ) << 24 )
    ]);
  }

  return output;
}

function splitLeast_64( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 1 ) {
    output.push( ( input[i][1] >>  0 ) & 0xff );
    output.push( ( input[i][1] >>  8 ) & 0xff );
    output.push( ( input[i][1] >> 16 ) & 0xff );
    output.push( ( input[i][1] >> 24 ) & 0xff );
    output.push( ( input[i][0] >>  0 ) & 0xff );
    output.push( ( input[i][0] >>  8 ) & 0xff );
    output.push( ( input[i][0] >> 16 ) & 0xff );
    output.push( ( input[i][0] >> 24 ) & 0xff );
  }

  return output;
}

// Most Significant Byte, 64-bit
function mergeMost_64( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 8 ) {
    output.push([
      ( ( input[ i + 0 ] & 0xff ) << 24 ) |
      ( ( input[ i + 1 ] & 0xff ) << 16 ) |
      ( ( input[ i + 2 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 3 ] & 0xff ) <<  0 ),
      ( ( input[ i + 4 ] & 0xff ) << 24 ) |
      ( ( input[ i + 5 ] & 0xff ) << 16 ) |
      ( ( input[ i + 6 ] & 0xff ) <<  8 ) |
      ( ( input[ i + 7 ] & 0xff ) <<  0 )
    ]);
  }
  
  return output;
}

function splitMost_64( input ) {
  var i,
      length = input.length,
      output = [];

  for ( i = 0; i < length; i += 1 ) {
    output.push( ( input[i][0] >> 24 ) & 0xff );
    output.push( ( input[i][0] >> 16 ) & 0xff );
    output.push( ( input[i][0] >>  8 ) & 0xff );
    output.push( ( input[i][0] >>  0 ) & 0xff );
    output.push( ( input[i][1] >> 24 ) & 0xff );
    output.push( ( input[i][1] >> 16 ) & 0xff );
    output.push( ( input[i][1] >>  8 ) & 0xff );
    output.push( ( input[i][1] >>  0 ) & 0xff );
  }

  return output;
}


(function () {

  self.ripemd = function ( size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = 160;
    }
    
    if ( size <= 128 ) {
      return self.ripemd128( size, data, key );
    } else {
      return self.ripemd160( size, data, key );
    }
  };

  self.sha = function ( size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = 512;
    }
    
    if ( size <= 160 ) {
      return self.sha1( size, data, key );
    } else {
      return self.sha2( size, data, key );
    }
  };

  self.sha2 = function ( size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = 512;
    }
    
    if ( size <= 224 ) {
      return self.sha224( size, data, key );
    } else if ( size <= 256 ) {
      return self.sha256( size, data, key );
    } else if ( size <= 384 ) {
      return self.sha384( size, data, key );
    } else {
      return self.sha512( size, data, key );
    }
  };

  self.skein = function ( size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = 1024;
    }
    
    if ( size <= 256 ) {
      return self.skein256( size, data, key );
    } else if ( size <= 512 ) {
      return self.skein512( size, data, key );
    } else {
      return self.skein1024( size, data, key );
    }
  };

})();


// MD4 (c) 1990 Ronald L. Rivest
(function () {
  var merge = mergeLeast_32,
      split = splitLeast_32,
      rotl = rotl_32,
      
      DIGEST = 128,
      BLOCK = 64,
      K = [ 0x00000000, 0x5a827999, 0x6ed9eba1 ],
      S = [
        [ 3, 7, 11, 19 ],
        [ 3, 5,  9, 13 ],
        [ 3, 9, 11, 15 ]
      ],
      X = [
        0, 1, 2,  3, 4,  5, 6,  7, 8, 9, 10, 11, 12, 13, 14, 15, // Round 1
        0, 4, 8, 12, 1,  5, 9, 13, 2, 6, 10, 14,  3,  7, 11, 15, // Round 2
        0, 8, 4, 12, 2, 10, 6, 14, 1, 9,  5, 13,  3, 11,  7, 15  // Round 3
      ],
      F = [
        function ( x, y, z ) {
          return ( x & y ) | ( (~x) & z);
        },
        function ( x, y, z ) {
          return ( x & y) | (x & z) | (y & z);
        },
        function ( x, y, z ) {
          return ( x ^ y ^ z);
        }
      ];

  function md4( data ) {
    var a, b, c, d, i, l, r, t, x, tmp,
        bytes = data.length,
        padding = [ 0x80 ],
        hash = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 ) | 0x0,
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0
    ]);
    
    for ( i = 0, l = x.length; i < l; i += 16 ) {
      a = hash[0];
      b = hash[1];
      c = hash[2];
      d = hash[3];
      
      for ( t = 0; t < 48; t++ ) {
        r = Math.floor( t / 16 );
        a = rotl_32(
          a + F[r]( b, c, d ) + x[ i + X[t] ] + K[r],
          S[r][ t % 4 ]
        );
        
        tmp = d;
        d = c;
        c = b;
        b = a;
        a = tmp;
      }
      
      hash[0] += a;
      hash[1] += b;
      hash[2] += c;
      hash[3] += d;
    }
    
    return split( hash );
  }
  
  self.md4 = factorMAC( hmac, md4, DIGEST, BLOCK );
}());


// MD5 (c) 1992 Ronald L. Rivest
(function () {
  var merge = mergeLeast_32,
      split = splitLeast_32,
      rotl = rotl_32,
      
      DIGEST = 128,
      BLOCK = 64,
      S = [
        [ 7, 12, 17, 22 ],
        [ 5,  9, 14, 20 ],
        [ 4, 11, 16, 23 ],
        [ 6, 10, 15, 21 ]
      ],
      X = [
        0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, // Round 1
        1, 6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12, // Round 2
        5, 8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2, // Round 3
        0, 7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9  // Round 4
      ],
      AC = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, // Round 1
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, // Round 2
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, // Round 3
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, // Round 4
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
      ],
      F = [
        function ( x, y, z ) {
          return ( x & y ) | ( ( ~x ) & z );
        },
        function ( x, y, z) {
          return ( x & z ) | ( y & ( ~z ));
        },
        function ( x, y, z) {
          return ( x ^ y ^ z );
        },
        function ( x, y, z) {
          return ( y ^ ( x | ( ~z ) ) );
        }
      ];

  function md5( data ) {
    var a, b, c, d, i, l, r, t, x, tmp,
        bytes = data.length,
        padding = [ 0x80 ],
        hash = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 ) | 0x0,
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0
    ]);
    
    for ( i = 0, l = x.length; i < l; i += 16 ) {
      a = hash[0];
      b = hash[1];
      c = hash[2];
      d = hash[3];
      
      for ( t = 0; t < 64; t++ ) {
        r = Math.floor( t / 16 );
        a = rotl(
          a + F[r]( b, c, d ) + x[ i + X[t] ] + AC[t],
          S[r][ t % 4 ]
        ) + b;
        
        tmp = d;
        d = c;
        c = b;
        b = a;
        a = tmp;
      }
      
      hash[0] += a;
      hash[1] += b;
      hash[2] += c;
      hash[3] += d;
    }
    
    return split( hash );
  }
  
  self.md5 = factorMAC( hmac, md5, DIGEST, BLOCK );
})();


// RIPEMD-128 (c) 1996 Hans Dobbertin, Antoon Bosselaers, and Bart Preneel
(function () {
  var merge = mergeLeast_32,
      split = splitLeast_32,
      rotl = rotl_32,
      
      DIGEST = 128,
      BLOCK = 64,
      S = [
        [ 11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8 ], // round 1
        [  7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12 ], // round 2
        [ 11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5 ], // round 3
        [ 11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12 ], // round 4
        [  8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6 ], // parallel round 1
        [  9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11 ], // parallel round 2
        [  9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5 ], // parallel round 3
        [ 15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8 ]  // parallel round 4
      ],
      X = [
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], // round 1
        [  7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8 ], // round 2
        [  3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12 ], // round 3
        [  1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2 ], // round 4
        [  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12 ], // parallel round 1
        [  6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2 ], // parallel round 2
        [ 15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13 ], // parallel round 3
        [  8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14 ]  // parallel round 4
      ],
      K = [
        0x00000000, // FF
        0x5a827999, // GG
        0x6ed9eba1, // HH
        0x8f1bbcdc, // II
        0x50a28be6, // III
        0x5c4dd124, // HHH
        0x6d703ef3, // GGG
        0x00000000  // FFF
      ],
      F = [
        function ( x, y, z ) {
          return ( x ^ y ^ z );
        },
        function ( x, y, z ) {
          return ( x & y ) | ( ( ~x ) & z );
        },
        function ( x, y, z ) {
          return ( x | ( ~y ) ) ^ z;
        },
        function ( x, y, z ) {
          return ( x & z ) | ( y & ( ~z ) );
        }
      ];

  function ripemd128( data ) {
    var aa, bb, cc, dd, aaa, bbb, ccc, ddd, i, l, r, rr, t, tmp, x,
        bytes = data.length,
        padding = [ 0x80 ],
        hash = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 ) | 0x0,
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0
    ]);
    
    // update hash
    for ( i = 0, t = 0, l = x.length; i < l; i += 16, t = 0 ) {
      aa = aaa = hash[0];
      bb = bbb = hash[1];
      cc = ccc = hash[2];
      dd = ddd = hash[3];
      
      for ( ; t < 64; t += 1 ) {
        r = Math.floor( t / 16 );
        aa = rotl(
          aa + F[r]( bb, cc, dd ) + x[ i + X[r][ t % 16 ] ] + K[r],
          S[r][ t % 16 ]
        );
        
        tmp = dd;
        dd = cc;
        cc = bb;
        bb = aa;
        aa = tmp;
      }
      
      for ( ; t < 128; t += 1 ) {
        r = Math.floor( t / 16 );
        rr = Math.floor( ( 63 - ( t % 64 ) ) / 16 );
        aaa = rotl(
          aaa + F[rr]( bbb, ccc, ddd ) + x[ i + X[r][ t % 16 ] ] + K[r],
          S[r][ t % 16 ]
        );
        
        tmp = ddd;
        ddd = ccc;
        ccc = bbb;
        bbb = aaa;
        aaa = tmp;
      }
      
      ddd     = hash[1] + cc + ddd;
      hash[1] = hash[2] + dd + aaa;
      hash[2] = hash[3] + aa + bbb;
      hash[3] = hash[0] + bb + ccc;
      hash[0] = ddd;
    }
    
    return split( hash );
  }
  
  self.ripemd128 = factorMAC( hmac, ripemd128, DIGEST, BLOCK );
}());


// RIPEMD-160 (c) 1996 Hans Dobbertin, Antoon Bosselaers, and Bart Preneel
(function () {
  var merge = mergeLeast_32,
      split = splitLeast_32,
      rotl = rotl_32,
      
      DIGEST = 160,
      BLOCK = 64,
      S = [
        [ 11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8 ], // round 1
        [  7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12 ], // round 2
        [ 11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5 ], // round 3
        [ 11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12 ], // round 4
        [  9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ], // round 5
        [  8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6 ], // parallel round 1
        [  9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11 ], // parallel round 2
        [  9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5 ], // parallel round 3
        [ 15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8 ], // parallel round 4
        [  8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]  // parallel round 5
      ],
      X = [
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], // round 1
        [  7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8 ], // round 2
        [  3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12 ], // round 3
        [  1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2 ], // round 4
        [  4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13 ], // round 5
        [  5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12 ], // parallel round 1
        [  6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2 ], // parallel round 2
        [ 15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13 ], // parallel round 3
        [  8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14 ], // parallel round 4
        [ 12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11 ]  // parallel round 5
      ],
      K = [
        0x00000000, // FF
        0x5a827999, // GG
        0x6ed9eba1, // HH
        0x8f1bbcdc, // II
        0xa953fd4e, // JJ
        0x50a28be6, // JJJ
        0x5c4dd124, // III
        0x6d703ef3, // HHH
        0x7a6d76e9, // GGG
        0x00000000  // FFF
      ],
      F = [
        function ( x, y, z ) {
          return ( x ^ y ^ z );
        },
        function ( x, y, z ) {
          return ( x & y ) | ( ( ~x ) & z );
        },
        function ( x, y, z ) {
          return ( x | ( ~y ) ) ^ z;
        },
        function ( x, y, z ) {
          return ( x & z ) | ( y & ( ~z ) );
        },
        function ( x, y, z ) {
          return ( x ^ ( y | ( ~z ) ) );
        }
      ];

  function ripemd160( data ) {
    var aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee, i, l, r, rr, t, tmp, x,
        bytes = data.length,
        padding = [ 0x80 ],
        hash = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 ) | 0x0,
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0
    ]);
    
    // update hash
    for ( i = 0, t = 0, l = x.length; i < l; i += 16, t = 0 ) {
      aa = aaa = hash[0];
      bb = bbb = hash[1];
      cc = ccc = hash[2];
      dd = ddd = hash[3];
      ee = eee = hash[4];
      
      for ( ; t < 80; t += 1 ) {
        r = Math.floor( t / 16 );
        aa = rotl(
          aa + F[r]( bb, cc, dd ) + x[ i + X[r][ t % 16 ] ] + K[r],
          S[r][ t % 16 ]
        ) + ee;
        
        tmp = ee;
        ee = dd;
        dd = rotl( cc, 10 );
        cc = bb;
        bb = aa;
        aa = tmp;
      }
      
      for ( ; t < 160; t += 1 ) {
        r = Math.floor( t / 16 );
        rr = Math.floor( ( 79 - ( t % 80 ) ) / 16 );
        aaa = rotl(
          aaa + F[rr]( bbb, ccc, ddd ) + x[ i + X[r][ t % 16 ] ] + K[r],
          S[r][ t % 16 ]
        ) + eee;
        
        tmp = eee;
        eee = ddd;
        ddd = rotl( ccc, 10 );
        ccc = bbb;
        bbb = aaa;
        aaa = tmp;
      }
      
      ddd     = hash[1] + cc + ddd;
      hash[1] = hash[2] + dd + eee;
      hash[2] = hash[3] + ee + aaa;
      hash[3] = hash[4] + aa + bbb;
      hash[4] = hash[0] + bb + ccc;
      hash[0] = ddd;
    }
    
    return split( hash );
  }
  
  self.ripemd160 = factorMAC( hmac, ripemd160, DIGEST, BLOCK );
}());


// SHA-1 (c) 2006 The Internet Society
(function () {
  var merge = mergeMost_32,
      split = splitMost_32,
      rotl = rotl_32,
      
      DIGEST = 160,
      BLOCK = 64,
      K = [ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 ],
      F = [
        function (b, c, d) {
          return (b & c) | ((~b) & d);
        },
        function (b, c, d) {
          return (b ^ c ^ d);
        },
        function (b, c, d) {
          return (b & c) | (b & d) | (c & d);
        },
        function (b, c, d) {
          return (b ^ c ^ d);
        }
      ];
      
  function sha1( data ) {
    var a, b, c, d, e, i, l, r, t, tmp, w, x,
        bytes = data.length,
        padding = [ 0x80 ],
        hash = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 ];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0,
      ( bytes * 8 ) | 0x0
    ]);
    
    // update hash
    for ( i = 0, w = [], l = x.length; i < l; i += 16 ) {
      a = hash[0];
      b = hash[1];
      c = hash[2];
      d = hash[3];
      e = hash[4];
      
      for ( t = 0; t < 80; t += 1 ) {
        if ( t < 16 ) {
          w[t] = x[ i + t ];
        } else {
          w[t] = rotl( w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1 );
        }
        
        r = Math.floor( t / 20 );
        tmp = rotl( a, 5 ) + F[r]( b, c, d ) + e + w[t] + K[r];
        e = d;
        d = c;
        c = rotl( b, 30 );
        b = a;
        a = tmp;
      }
      
      hash[0] += a;
      hash[1] += b;
      hash[2] += c;
      hash[3] += d;
      hash[4] += e;
    }
    
    return split( hash );
  }
  
  self.sha1 = factorMAC( hmac, sha1, DIGEST, BLOCK );
  
}());


// SHA-2 256 (c) 2006 The Internet Society
(function () {
  var merge = mergeMost_32,
      split = splitMost_32,
      rotr = rotr_32,
      
      K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
      ];
    
  function bSig0( x ) {
    return rotr( x,  2 ) ^ rotr( x, 13 ) ^ rotr( x, 22 );
  }
  function bSig1( x ) {
    return rotr( x,  6 ) ^ rotr( x, 11 ) ^ rotr( x, 25 );
  }
  function sSig0( x ) {
    return rotr( x,  7 ) ^ rotr( x, 18 ) ^ ( x >>> 3 );
  }
  function sSig1( x ) {
    return rotr( x, 17 ) ^ rotr( x, 19 ) ^ ( x >>> 10 );
  }
  
  function ch( x, y, z ) {
    return ( x & y ) ^ ( ( ~x ) & z );
  }
  function maj( x, y, z ) {
    return ( x & y ) ^ ( x & z ) ^ ( y & z );
  }
  
  function sha2_32( digest, data ) {
    var a, b, c, d, e, f, g, h, i, l, t, tmp1, tmp2, w, x,
        bytes = data.length,
        padding = [ 0x80 ],
        part = Math.ceil( digest / 32 ),
        hash = {
          224: [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
          ],
          256: [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
          ]
        }[digest];
    
    padding.length = ( ( bytes % 64 ) < 56 ? 56 : 120 ) - ( bytes % 64 );
    
    x = merge( data.concat( padding ) ).concat([
      ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0,
      ( bytes * 8 ) | 0x0
    ]);
    
    // update hash
    for ( i = 0, w = [], l = x.length; i < l; i += 16 ) {
      a = hash[0] | 0x0;
      b = hash[1] | 0x0;
      c = hash[2] | 0x0;
      d = hash[3] | 0x0;
      e = hash[4] | 0x0;
      f = hash[5] | 0x0;
      g = hash[6] | 0x0;
      h = hash[7] | 0x0;
      
      for ( t = 0; t < 64; t += 1 ) {
        if ( t < 16 ) {
          w[t] = x[ i + t ];
        } else {
          w[t] = sSig1( w[t - 2] ) + w[t - 7] + sSig0( w[t - 15] ) + w[t - 16];
        }
        
        tmp1 = h + bSig1( e ) + ch( e, f, g ) + K[t] + w[t];
        tmp2 = bSig0( a ) + maj( a, b, c );
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
      }
      
      hash[0] += a;
      hash[1] += b;
      hash[2] += c;
      hash[3] += d;
      hash[4] += e;
      hash[5] += f;
      hash[6] += g;
      hash[7] += h;
    }
    
    return split( hash.slice( 0, part ) );
  }
  
  function sha224( data ) {
    return sha2_32( 224, data );
  }
  
  function sha256( data ) {
    return sha2_32( 256, data );
  }
  
  self.sha224 = factorMAC( hmac, sha224, 224, 64 );
  
  self.sha256 = factorMAC( hmac, sha256, 256, 64 );
  
}());


// SHA-2 512 (c) 2006 The Internet Society
(function () {
  var merge = mergeMost_64,
      split = splitMost_64,
      
      K = [
        [0x428a2f98, 0xd728ae22], [0x71374491, 0x23ef65cd],
        [0xb5c0fbcf, 0xec4d3b2f], [0xe9b5dba5, 0x8189dbbc],
        [0x3956c25b, 0xf348b538], [0x59f111f1, 0xb605d019],
        [0x923f82a4, 0xaf194f9b], [0xab1c5ed5, 0xda6d8118],
        [0xd807aa98, 0xa3030242], [0x12835b01, 0x45706fbe],
        [0x243185be, 0x4ee4b28c], [0x550c7dc3, 0xd5ffb4e2],
        [0x72be5d74, 0xf27b896f], [0x80deb1fe, 0x3b1696b1],
        [0x9bdc06a7, 0x25c71235], [0xc19bf174, 0xcf692694],
        [0xe49b69c1, 0x9ef14ad2], [0xefbe4786, 0x384f25e3],
        [0x0fc19dc6, 0x8b8cd5b5], [0x240ca1cc, 0x77ac9c65],
        [0x2de92c6f, 0x592b0275], [0x4a7484aa, 0x6ea6e483],
        [0x5cb0a9dc, 0xbd41fbd4], [0x76f988da, 0x831153b5],
        [0x983e5152, 0xee66dfab], [0xa831c66d, 0x2db43210],
        [0xb00327c8, 0x98fb213f], [0xbf597fc7, 0xbeef0ee4],
        [0xc6e00bf3, 0x3da88fc2], [0xd5a79147, 0x930aa725],
        [0x06ca6351, 0xe003826f], [0x14292967, 0x0a0e6e70],
        [0x27b70a85, 0x46d22ffc], [0x2e1b2138, 0x5c26c926],
        [0x4d2c6dfc, 0x5ac42aed], [0x53380d13, 0x9d95b3df],
        [0x650a7354, 0x8baf63de], [0x766a0abb, 0x3c77b2a8],
        [0x81c2c92e, 0x47edaee6], [0x92722c85, 0x1482353b],
        [0xa2bfe8a1, 0x4cf10364], [0xa81a664b, 0xbc423001],
        [0xc24b8b70, 0xd0f89791], [0xc76c51a3, 0x0654be30],
        [0xd192e819, 0xd6ef5218], [0xd6990624, 0x5565a910],
        [0xf40e3585, 0x5771202a], [0x106aa070, 0x32bbd1b8],
        [0x19a4c116, 0xb8d2d0c8], [0x1e376c08, 0x5141ab53],
        [0x2748774c, 0xdf8eeb99], [0x34b0bcb5, 0xe19b48a8],
        [0x391c0cb3, 0xc5c95a63], [0x4ed8aa4a, 0xe3418acb],
        [0x5b9cca4f, 0x7763e373], [0x682e6ff3, 0xd6b2b8a3],
        [0x748f82ee, 0x5defb2fc], [0x78a5636f, 0x43172f60],
        [0x84c87814, 0xa1f0ab72], [0x8cc70208, 0x1a6439ec],
        [0x90befffa, 0x23631e28], [0xa4506ceb, 0xde82bde9],
        [0xbef9a3f7, 0xb2c67915], [0xc67178f2, 0xe372532b],
        [0xca273ece, 0xea26619c], [0xd186b8c7, 0x21c0c207],
        [0xeada7dd6, 0xcde0eb1e], [0xf57d4f7f, 0xee6ed178],
        [0x06f067aa, 0x72176fba], [0x0a637dc5, 0xa2c898a6],
        [0x113f9804, 0xbef90dae], [0x1b710b35, 0x131c471b],
        [0x28db77f5, 0x23047d84], [0x32caab7b, 0x40c72493],
        [0x3c9ebe0a, 0x15c9bebc], [0x431d67c4, 0x9c100d4c],
        [0x4cc5d4be, 0xcb3e42b6], [0x597f299c, 0xfc657e2a],
        [0x5fcb6fab, 0x3ad6faec], [0x6c44198c, 0x4a475817]
      ];
    
  function bSig0( x ) {
    return xor( xor( rotr( x, 28 ), rotr( x, 34 ) ), rotr( x, 39 ) );
  }
  function bSig1( x ) {
    return xor( xor( rotr( x, 14 ), rotr( x, 18 ) ), rotr( x, 41) );
  }
  function sSig0( x ) {
    return xor( xor( rotr( x,  1 ), rotr( x,  8 ) ), shr( x, 7 ) );
  }
  function sSig1( x ) {
    return xor( xor( rotr( x, 19 ), rotr( x, 61 ) ), shr( x, 6 ) );
  }
  
  function ch( x, y, z ) {
    return xor( and( x, y ), and( not( x ), z ) );
  }
  function maj( x, y, z ) {
    return xor( xor( and( x, y ), and( x, z ) ), and( y, z ) );
  }

  function sha2_64( digest, data ) {
    var a, b, c, d, e, f, g, h, i, l, t, tmp1, tmp2, w, x,
        bytes = data.length,
        padding = [ 0x80 ],
        part = Math.ceil( digest / 64 ),
        hash = {
          384: [
            [0xcbbb9d5d, 0xc1059ed8], [0x629a292a, 0x367cd507],
            [0x9159015a, 0x3070dd17], [0x152fecd8, 0xf70e5939],
            [0x67332667, 0xffc00b31], [0x8eb44a87, 0x68581511],
            [0xdb0c2e0d, 0x64f98fa7], [0x47b5481d, 0xbefa4fa4]
          ],
          512: [
            [0x6a09e667, 0xf3bcc908], [0xbb67ae85, 0x84caa73b],
            [0x3c6ef372, 0xfe94f82b], [0xa54ff53a, 0x5f1d36f1],
            [0x510e527f, 0xade682d1], [0x9b05688c, 0x2b3e6c1f],
            [0x1f83d9ab, 0xfb41bd6b], [0x5be0cd19, 0x137e2179]
          ]
        }[digest];
    
    padding.length = ( ( bytes % 128 ) < 112 ? 112 : 240 ) - ( bytes % 128 );
    
    x = merge( data.concat( padding ) ).concat([
      [
        ( bytes * 8 / Math.pow( 2, 96 ) ) | 0x0,
        ( bytes * 8 / Math.pow( 2, 64 ) ) | 0x0
      ],
      [
        ( bytes * 8 / Math.pow( 2, 32 ) ) | 0x0,
        ( bytes * 8 ) | 0x0
      ]
    ]);
    
    // update hash
    for ( i = 0, l = x.length; i < l; i += 16 ) {
      a = hash[0].slice();
      b = hash[1].slice();
      c = hash[2].slice();
      d = hash[3].slice();
      e = hash[4].slice();
      f = hash[5].slice();
      g = hash[6].slice();
      h = hash[7].slice();
      
      for ( w = [], t = 0; t < 80; t += 1 ) {
        if ( t < 16 ) {
          w[t] = [].concat( x[ i + t ] );
        } else {
          w[t] = add(
            add( sSig1( w[ t -  2 ] ), w[ t -  7 ] ),
            add( sSig0( w[ t - 15 ] ), w[ t - 16 ] )
          ).slice();
        }
        
        tmp1 = add(
          add( add( h, bSig1(e) ), ch( e, f, g ) ),
          add( K[t], w[t] )
        );
        tmp2 = add( bSig0(a), maj( a, b, c ) );
        
        h = g.slice();
        g = f.slice();
        f = e.slice();
        e = add( d, tmp1 );
        d = c.slice();
        c = b.slice();
        b = a.slice();
        a = add( tmp1, tmp2 );
      }
      
      hash[0] = add( hash[0], a );
      hash[1] = add( hash[1], b );
      hash[2] = add( hash[2], c );
      hash[3] = add( hash[3], d );
      hash[4] = add( hash[4], e );
      hash[5] = add( hash[5], f );
      hash[6] = add( hash[6], g );
      hash[7] = add( hash[7], h );
    }
    
    return split( hash.slice( 0, part ) );
  }
  
  function sha384( data ) {
    return sha2_64( 384, data );
  }
  
  function sha512( data ) {
    return sha2_64( 512, data );
  }
  
  self.sha384 = factorMAC( hmac, sha384, 384, 128 );
  
  self.sha512 = factorMAC( hmac, sha512, 512, 128 );
  
}());


// Skein 1.3 (c) 2010 Bruce Schneier, et al.
(function () {
  var merge = mergeLeast_64,
      split = splitLeast_64,
      
      PARITY = [ 0x1BD11BDA, 0xA9FC1A22 ],
      
      TWEAK = {
        KEY:         0x00,
        CONFIG:      0x04,
        PERSONALIZE: 0x08,
        PUBLICKEY:   0x10,
        NONCE:       0x14,
        MESSAGE:     0x30,
        OUT:         0x3F
      },
      
      VARS = {
        256: {
          bytes: 32,
          words: 4,
          rounds: 72,
          permute: [ 0, 3, 2, 1 ],
          rotate: [
            [ 14, 16 ],
            [ 52, 57 ],
            [ 23, 40 ],
            [  5, 37 ],
            [ 25, 33 ],
            [ 46, 12 ],
            [ 58, 22 ],
            [ 32, 32 ]
          ]
        },
        
        512: {
          bytes: 64,
          words: 8,
          rounds: 72,
          permute: [ 2, 1, 4, 7, 6, 5, 0, 3 ],
          rotate: [
            [ 46, 36, 19, 37 ],
            [ 33, 27, 14, 42 ],
            [ 17, 49, 36, 39 ],
            [ 44,  9, 54, 56 ],
            [ 39, 30, 34, 24 ],
            [ 13, 50, 10, 17 ],
            [ 25, 29, 39, 43 ],
            [  8, 35, 56, 22 ]
          ]
        },
        
        1024: {
          bytes: 128,
          words: 16,
          rounds: 80,
          permute: [ 0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1 ],
          rotate: [
            [ 24, 13,  8, 47,  8, 17, 22, 37 ],
            [ 38, 19, 10, 55, 49, 18, 23, 52 ],
            [ 33,  4, 51, 13, 34, 41, 59, 17 ],
            [  5, 20, 48, 41, 47, 28, 16, 25 ],
            [ 41,  9, 37, 31, 12, 47, 44, 30 ],
            [ 16, 34, 56, 51,  4, 53, 42, 41 ],
            [ 31, 44, 47, 46, 19, 42, 44, 25 ],
            [  9, 48, 35, 52, 23, 31, 37, 20 ]
          ]
        }
      };
  
  function tweaker( pos, type, first, finish ) {
    var a = pos | 0x0,
        b = ( pos / Math.pow( 2, 32 ) ) | 0x0,
        c = ( pos / Math.pow( 2, 64 ) ) | 0x0,
        d = ( ( finish && 0x80 ) | ( first && 0x40 ) | type ) << 24;
    
    return split( [ [b, a], [d, c] ] );
  }
  
  function mix0( x, y ) {
    return add( x, y );
  }
  
  function mix1( x, y, r ) {
    return xor( rotl( y, r ), x );
  }
  
  function threefish( key, tweak, plain, vars ) {
    var i, j, r, s, mixer, sched, chain,
        words   = +vars.words,
        rounds  = +vars.rounds,
        rotate  = vars.rotate,
        permute = vars.permute;
    
    key   = merge( key );
    tweak = merge( tweak );
    plain = merge( plain );
    
    key[ words ] = ulong( PARITY );
    for ( i = 0; i < words; i++ ) {
      key[ words ] = xor( key[ words ], key[ i ] );
    }
    
    tweak[ 2 ] = xor( tweak[ 0 ], tweak[ 1 ] );
    
    for ( r = 0, s = 0; r < rounds; r++ ) {
      mixer = plain.slice();
      
      if ( 0 == ( r % 4 ) ) {
        sched = [];
        
        for ( i = 0; i <= words; i++ ) {
          sched[ i ] = key[ (s + i) % (words + 1) ];
        }
        
        sched[ words - 3 ] = add( sched[ words - 3 ], tweak[ s % 3 ] );
        sched[ words - 2 ] = add( sched[ words - 2 ], tweak[ (s + 1) % 3 ] );
        sched[ words - 1 ] = add( sched[ words - 1 ], [ 0, s ] );
        
        for ( i = 0; i < words; i++ ) {
          mixer[ i ] = add( mixer[ i ], sched[ i ] );
        }
        
        s++;
      }
      
      for ( i = 0; i < ( words / 2 ); i++ ) {
        j = 2 * i;
        mixer[ j + 0 ] = mix0( mixer[ j + 0 ], mixer[ j + 1 ] );
        mixer[ j + 1 ] = mix1( mixer[ j + 0 ], mixer[ j + 1 ], rotate[ r % 8 ][ i ] );
      }
      
      for ( i = 0; i < words; i++ ) {
        plain[ i ] = mixer[ permute[ i ] ];
      }
    }
    
    for ( chain = [], i = 0; i < words; i++ ) {
      chain[ i ] = add( plain[ i ], key[ (s + i) % (words + 1) ] );
    }
    chain[ words - 3 ] = add( chain[ words - 3 ], tweak[ s % 3 ] );
    chain[ words - 2 ] = add( chain[ words - 2 ], tweak[ (s + 1) % 3 ] );
    chain[ words - 1 ] = add( chain[ words - 1 ], [ 0, s ] );
    
    return split( chain );
  }
  
  function ubi( chain, message, type, vars ) {
    var i, k, l, pos, tweak, first, finish,
        bytes   = vars.bytes,
        count   = message.length,
        blocks  = [];
    
    message.length += count == 0 ? bytes :
      bytes - ( ( count % bytes ) || bytes );
    
    while ( message.length > 0 ) {
      blocks.push( message.slice( 0, bytes ) );
      message = message.slice( bytes );
    }
    
    for ( k = 0, l = blocks.length; k < l; k++ ) {
      pos = bytes * ( k + 1 );
      first = k === 0;
      finish = k === ( l - 1 );
      
      tweak = tweaker( Math.min( count, pos ), type, first, finish );
      chain = threefish( chain, tweak, blocks[k], vars );
      
      for ( i = 0; i < chain.length; i++ ) {
        chain[i] ^= blocks[k][i];
      }
    }
    
    return chain.slice( 0, bytes );
  }

  function skein( digest, size, data, key ) {
    var config, chain,
        out     = [ 0, 0, 0, 0, 0, 0, 0, 0 ],
        output  = +size || digest,
        vars    = VARS[digest],
        bytes   = vars.bytes;
    
    chain = [];
    chain.length = bytes;
    
    config = [];
    config.push( 0x53, 0x48, 0x41, 0x33 ); // Schema: "SHA3"
    config.push( 0x01, 0x00, 0x00, 0x00 ); // Version / Reserved
    config = config.concat( split( [ [ 0, output ] ] ) );
    config.length = 32;
    
    if ( key )
      chain = ubi( chain, key, TWEAK.KEY, vars );
    chain = ubi( chain, config, TWEAK.CONFIG, vars );
    chain = ubi( chain, data, TWEAK.MESSAGE, vars );
    return ubi( chain, out, TWEAK.OUT, vars );
  }
  
  function calculate( digest, size, data, key ) {
    if ( 'number' !== typeof size ) {
      key = data;
      data = size;
      size = digest;
    }
    
    var result = skein( digest, size, toBuffer(data),
      key == null ? null : toBuffer(key)
    );
    
    return Encoder( crop( size, result, false ) );
  };
  
  self.skein256 = function ( size, data, key ) {
    return calculate( 256, size, data, key );
  };
  
  self.skein512 = function ( size, data, key ) {
    return calculate( 512, size, data, key );
  };
  
  self.skein1024 = function ( size, data, key ) {
    return calculate( 1024, size, data, key );
  };
}());


/* Export */

if ( 'undefined' === typeof exports )
  window.Digest = self;
else
  module.exports = self;

})();
