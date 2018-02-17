import 'dart:convert';
import 'dart:typed_data';
// import 'package:crypto/crypto.dart';
// import 'package:crypto/src/digest.dart';
// import 'hash_sink64.dart';
// import 'helpers.dart';
import 'package:pointycastle/api.dart';

import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

// abstract class _SHA384_512Base extends _Hash64Base {
//   _SHA384_512Base(int resultLengthInWords)
//       : _w = new List(16 * _BYTES_PER_WORD_64),
//         super(16, 8, resultLengthInWords);

//   // Table of round constants. First 64 bits of the fractional
//   // parts of the cube roots of the first 80 prime numbers.
//   static const List<int> _K = const [
//     0x428a2f98d728ae22,
//     0x7137449123ef65cd,
//     0xb5c0fbcfec4d3b2f,
//     0xe9b5dba58189dbbc,
//     0x3956c25bf348b538,
//     0x59f111f1b605d019,
//     0x923f82a4af194f9b,
//     0xab1c5ed5da6d8118,
//     0xd807aa98a3030242,
//     0x12835b0145706fbe,
//     0x243185be4ee4b28c,
//     0x550c7dc3d5ffb4e2,
//     0x72be5d74f27b896f,
//     0x80deb1fe3b1696b1,
//     0x9bdc06a725c71235,
//     0xc19bf174cf692694,
//     0xe49b69c19ef14ad2,
//     0xefbe4786384f25e3,
//     0x0fc19dc68b8cd5b5,
//     0x240ca1cc77ac9c65,
//     0x2de92c6f592b0275,
//     0x4a7484aa6ea6e483,
//     0x5cb0a9dcbd41fbd4,
//     0x76f988da831153b5,
//     0x983e5152ee66dfab,
//     0xa831c66d2db43210,
//     0xb00327c898fb213f,
//     0xbf597fc7beef0ee4,
//     0xc6e00bf33da88fc2,
//     0xd5a79147930aa725,
//     0x06ca6351e003826f,
//     0x142929670a0e6e70,
//     0x27b70a8546d22ffc,
//     0x2e1b21385c26c926,
//     0x4d2c6dfc5ac42aed,
//     0x53380d139d95b3df,
//     0x650a73548baf63de,
//     0x766a0abb3c77b2a8,
//     0x81c2c92e47edaee6,
//     0x92722c851482353b,
//     0xa2bfe8a14cf10364,
//     0xa81a664bbc423001,
//     0xc24b8b70d0f89791,
//     0xc76c51a30654be30,
//     0xd192e819d6ef5218,
//     0xd69906245565a910,
//     0xf40e35855771202a,
//     0x106aa07032bbd1b8,
//     0x19a4c116b8d2d0c8,
//     0x1e376c085141ab53,
//     0x2748774cdf8eeb99,
//     0x34b0bcb5e19b48a8,
//     0x391c0cb3c5c95a63,
//     0x4ed8aa4ae3418acb,
//     0x5b9cca4f7763e373,
//     0x682e6ff3d6b2b8a3,
//     0x748f82ee5defb2fc,
//     0x78a5636f43172f60,
//     0x84c87814a1f0ab72,
//     0x8cc702081a6439ec,
//     0x90befffa23631e28,
//     0xa4506cebde82bde9,
//     0xbef9a3f7b2c67915,
//     0xc67178f2e372532b,
//     0xca273eceea26619c,
//     0xd186b8c721c0c207,
//     0xeada7dd6cde0eb1e,
//     0xf57d4f7fee6ed178,
//     0x06f067aa72176fba,
//     0x0a637dc5a2c898a6,
//     0x113f9804bef90dae,
//     0x1b710b35131c471b,
//     0x28db77f523047d84,
//     0x32caab7b40c72493,
//     0x3c9ebe0a15c9bebc,
//     0x431d67c49c100d4c,
//     0x4cc5d4becb3e42b6,
//     0x597f299cfc657e2a,
//     0x5fcb6fab3ad6faec,
//     0x6c44198c4a475817
//   ];

//   // Helper functions as defined in http://tools.ietf.org/html/rfc6234
//   _rotr64(n, x) => (x >> n) | ((x << (64 - n)) & _MASK_64);
//   _ch(x, y, z) => (x & y) ^ ((~x & _MASK_64) & z);
//   _maj(x, y, z) => (x & y) ^ (x & z) ^ (y & z);
//   _bsig0(x) => _rotr64(28, x) ^ _rotr64(34, x) ^ _rotr64(39, x);
//   _bsig1(x) => _rotr64(14, x) ^ _rotr64(18, x) ^ _rotr64(41, x);
//   _ssig0(x) => _rotr64(1, x) ^ _rotr64(8, x) ^ (x >> 7);
//   _ssig1(x) => _rotr64(19, x) ^ _rotr64(61, x) ^ (x >> 6);

//   // Compute one iteration of the SHA256 algorithm with a chunk of
//   // 16 32-bit pieces.
//   void _updateHash(List<int> M) {
//     assert(M.length == 16);

//     // Prepare message schedule.
//     var i = 0;
//     for (; i < 16; i++) {
//       _w[i] = M[i];
//     }
//     for (; i < 80; i++) {
//       _w[i] = _add64(_add64(_ssig1(_w[i - 2]), _w[i - 7]), _add64(_ssig0(_w[i - 15]), _w[i - 16]));
//     }

//     // Shuffle around the bits.
//     var a = _h[0];
//     var b = _h[1];
//     var c = _h[2];
//     var d = _h[3];
//     var e = _h[4];
//     var f = _h[5];
//     var g = _h[6];
//     var h = _h[7];

//     for (var t = 0; t < 80; t++) {
//       var t1 = _add64(_add64(h, _bsig1(e)), _add64(_ch(e, f, g), _add64(_K[t], _w[t])));
//       var t2 = _add64(_bsig0(a), _maj(a, b, c));
//       h = g;
//       g = f;
//       f = e;
//       e = _add64(d, t1);
//       d = c;
//       c = b;
//       b = a;
//       a = _add64(t1, t2);
//     }

//     // Update hash values after iteration.
//     _h[0] = _add64(a, _h[0]);
//     _h[1] = _add64(b, _h[1]);
//     _h[2] = _add64(c, _h[2]);
//     _h[3] = _add64(d, _h[3]);
//     _h[4] = _add64(e, _h[4]);
//     _h[5] = _add64(f, _h[5]);
//     _h[6] = _add64(g, _h[6]);
//     _h[7] = _add64(h, _h[7]);
//   }

//   List<int> _w;
// }

// class _SHA512 extends _SHA384_512Base implements SHA512 {
//   _SHA512() : super(8) {
//     // Initial value of the hash parts. First 32 bits of the fractional parts
//     // of the square roots of the first 8 prime numbers.
//     _h[0] = 0x6a09e667f3bcc908;
//     _h[1] = 0xbb67ae8584caa73b;
//     _h[2] = 0x3c6ef372fe94f82b;
//     _h[3] = 0xa54ff53a5f1d36f1;
//     _h[4] = 0x510e527fade682d1;
//     _h[5] = 0x9b05688c2b3e6c1f;
//     _h[6] = 0x1f83d9abfb41bd6b;
//     _h[7] = 0x5be0cd19137e2179;
//   }

//   // Returns a new instance of this Hash.
//   SHA512 newInstance() {
//     return new SHA512();
//   }
// }

/// <============================Implementation of SHA-512====================>

/// An instance of [Sha512].
///
/// This instance provides convenient access to the [Sha512][rfc] hash function.
///
/// [rfc]: http://tools.ietf.org/html/rfc6234
final Sha512 sha512 = new Sha512._();

/// An implementation of the [SHA-512][rfc] hash function.
///
/// Note that it's almost always easier to use [sha512] rather than creating a
/// new instance.
/// [rfc]: http://tools.ietf.org/html/rfc6234
class Sha512 extends Hash {
  Sha512._();

  /// sixteen 64-bit words
  @override
  int get blockSize => 16 * bytesPerWord64;

  ///
  Sha512 newInstance() => new Sha512._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) => new ByteConversionSink.from(new _Sha512Sink(sink));
}

/// Data from a non-linear function that functions as reproducible noise.
/// Eighty constant 64-bit words
/// These words represent the first 64 bits of the fractional parts of
/// the cube roots of the first eighty prime numbers.
const List<int> _noise = const <int>[
  0x428a2f98d728ae22,
  0x7137449123ef65cd,
  0xb5c0fbcfec4d3b2f,
  0xe9b5dba58189dbbc,
  0x3956c25bf348b538,
  0x59f111f1b605d019,
  0x923f82a4af194f9b,
  0xab1c5ed5da6d8118,
  0xd807aa98a3030242,
  0x12835b0145706fbe,
  0x243185be4ee4b28c,
  0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f,
  0x80deb1fe3b1696b1,
  0x9bdc06a725c71235,
  0xc19bf174cf692694,
  0xe49b69c19ef14ad2,
  0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5,
  0x240ca1cc77ac9c65,
  0x2de92c6f592b0275,
  0x4a7484aa6ea6e483,
  0x5cb0a9dcbd41fbd4,
  0x76f988da831153b5,
  0x983e5152ee66dfab,
  0xa831c66d2db43210,
  0xb00327c898fb213f,
  0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2,
  0xd5a79147930aa725,
  0x06ca6351e003826f,
  0x142929670a0e6e70,
  0x27b70a8546d22ffc,
  0x2e1b21385c26c926,
  0x4d2c6dfc5ac42aed,
  0x53380d139d95b3df,
  0x650a73548baf63de,
  0x766a0abb3c77b2a8,
  0x81c2c92e47edaee6,
  0x92722c851482353b,
  0xa2bfe8a14cf10364,
  0xa81a664bbc423001,
  0xc24b8b70d0f89791,
  0xc76c51a30654be30,
  0xd192e819d6ef5218,
  0xd69906245565a910,
  0xf40e35855771202a,
  0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8,
  0x1e376c085141ab53,
  0x2748774cdf8eeb99,
  0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63,
  0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373,
  0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc,
  0x78a5636f43172f60,
  0x84c87814a1f0ab72,
  0x8cc702081a6439ec,
  0x90befffa23631e28,
  0xa4506cebde82bde9,
  0xbef9a3f7b2c67915,
  0xc67178f2e372532b,
  0xca273eceea26619c,
  0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e,
  0xf57d4f7fee6ed178,
  0x06f067aa72176fba,
  0x0a637dc5a2c898a6,
  0x113f9804bef90dae,
  0x1b710b35131c471b,
  0x28db77f523047d84,
  0x32caab7b40c72493,
  0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6,
  0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec,
  0x6c44198c4a475817
];

class _Sha512Sink extends HashSink64 {
  /*
  The output of each of the secure hash functions, after being applied
   to a message of N blocks, is the hash quantity H(N). For SHA-512, 
   it can be considered to be eight 64-bit words, H(i)0, H(i)1, ..., H(i)7.
  */
  @override
  final Uint64List digest = new Uint64List(8);

  /// The sixteen words from the original chunk, extended to 64 words.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [updateHash].
  final Uint64List _extended;

  _Sha512Sink(Sink<Digest> sink)
      : _extended = new Uint64List(80),
        super(sink, 16) {
    /*
   For SHA-512, the initial hash value, digest[0], consists of the following
   eight 64-bit words, in hex.  These words were obtained by taking the
   first 64 bits of the fractional parts of the square roots of the
   first eight prime numbers.
  */
    digest[0] = 0x6a09e667f3bcc908;
    digest[1] = 0xbb67ae8584caa73b;
    digest[2] = 0x3c6ef372fe94f82b;
    digest[3] = 0xa54ff53a5f1d36f1;
    digest[4] = 0x510e527fade682d1;
    digest[5] = 0x9b05688c2b3e6c1f;
    digest[6] = 0x1f83d9abfb41bd6b;
    digest[7] = 0x5be0cd19137e2179;
  }

  /// Helper functions as defined in http://tools.ietf.org/html/rfc6234
  /// The result of each function is a new 64-bit word
  int _rotr64(int n, int x) => (x >> n) | ((x << (64 - n)) & mask64);
  int _ch(int x, int y, int z) => (x & y) ^ ((~x & mask64) & z);
  int _maj(int x, int y, int z) => (x & y) ^ (x & z) ^ (y & z);
  int _bsig0(int x) => _rotr64(28, x) ^ _rotr64(34, x) ^ _rotr64(39, x);
  int _bsig1(int x) => _rotr64(14, x) ^ _rotr64(18, x) ^ _rotr64(41, x);
  int _ssig0(int x) => _rotr64(1, x) ^ _rotr64(8, x) ^ (x >> 7);
  int _ssig1(int x) => _rotr64(19, x) ^ _rotr64(61, x) ^ (x >> 6);

  // @override
  // Uint64List get digest => new Uint64List(8);

  @override
  void updateHash(Uint64List chunk) {
    assert(chunk.length == 16);
    // Prepare message schedule [_extended]:
    for (int i = 0; i < 16; i++) {
      _extended[i] = chunk[i];
    }
    for (int i = 16; i < 80; i++) {
      add64(add64(_ssig1(_extended[i - 2]), _extended[i - 7]), add64(_ssig0(_extended[i - 15]), _extended[i - 16]));
    }
    // Initialize the working variables:
    int a = digest[0];
    int b = digest[1];
    int c = digest[2];
    int d = digest[3];
    int e = digest[4];
    int f = digest[5];
    int g = digest[6];
    int h = digest[7];

    // Perform the main hash computation:
    for (int i = 0; i < 80; i++) {
      final int temp1 = add64(add64(h, _bsig1(e)), add64(_ch(e, f, g), add64(_noise[i], _extended[i])));
      final int temp2 = add64(_bsig0(a), _maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = add64(d, temp1);
      d = c;
      c = b;
      b = a;
      a = add64(temp1, temp2);
    }
    // Compute the intermediate hash value digest[i]:
    digest[0] = add64(a, digest[0]);
    digest[1] = add64(b, digest[1]);
    digest[2] = add64(c, digest[2]);
    digest[3] = add64(d, digest[3]);
    digest[4] = add64(e, digest[4]);
    digest[5] = add64(f, digest[5]);
    digest[6] = add64(g, digest[6]);
    digest[7] = add64(h, digest[7]);
  }
}

/// Adds [x] and [y] with 64-bit overflow semantics.
int add64(int x, int y) => (x + y) & mask64;

void main() {
  String test = 'abc';
  // print(formatBytesAsHexString(createUint8ListFromString(test)));
  // print(sha512.convert(createUint8ListFromString(test).toList()).bytes.length);
new HMac(new SHA512Digest(), _blockLength)
  print(formatBytesAsHexString(new SHA512Digest().process(createUint8ListFromString(test))));
}
