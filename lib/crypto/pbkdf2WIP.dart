import 'dart:convert';
// import 'package:crypto/crypto.dart';
// import 'package:crypto/src/digest.dart';
// import 'package:crypto/src/hmac.dart';
// import 'package:crypto/src/hash.dart';
import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'helpers.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/key_derivators/api.dart';

/// Password Based Key Derivation Function 2
/// Reference https://tools.ietf.org/html/rfc2898#page-9
class PBKDF2 {
  /// Digest to use in psuedorandom function
  Digest _hash;
  final List<int> _blockList = new List<int>(4);
  int _prfLengthInBytes;

  /// Initialize PBKDF2 with the given hashing algo.
  PBKDF2(this._hash);

  ///
  List<int> deriveKey(String password, String salt, int iterations, int desiredKeyLength) {
    /// Step 1
    ///     If dkLen > (2^32 - 1) * hLen, output "derived key too long"
    /// and stop.
    if (desiredKeyLength > (2 ^ 32 - 1) * prfLengthInBytes) {
      throw new RangeError('derived key too long');
    }

    /// Step 2
    /// Let l be the number of hLen-octet blocks in the derived key,
    /// rounding up, and let r be the number of octets in the last
    ///  block:
    ///     l = CEIL (dkLen / hLen) ,
    ///     r = dkLen - (l - 1) * hLen .
    ///   Here, CEIL (x) is the "ceiling" function, i.e. the smallest
    ///   integer greater than, or equal to, x.
    final int numberOfBlocks = (desiredKeyLength / prfLengthInBytes).ceil();
    final int sizeOfLastBlock = desiredKeyLength - (numberOfBlocks - 1) * prfLengthInBytes;

    /// Step 3
    /// For each block of the derived key apply the function F defined
    /// below to the password P, the salt S, the iteration count c, and
    /// the block index to compute the block:
    ///
    ///     T_1 = F (P, S, c, 1) ,
    ///     T_2 = F (P, S, c, 2) ,
    ///     ...
    ///     T_l = F (P, S, c, l) ,
    /// where the function F is defined as the exclusive-or sum of the
    /// first c iterates of the underlying pseudorandom function PRF
    /// applied to the password P and the concatenation of the salt S
    /// and the block index i:
    ///     F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    ///
    /// where
    ///
    ///     U_1 = PRF (P, S || INT (i)) ,
    ///     U_2 = PRF (P, U_1) ,
    ///     ...
    ///     U_c = PRF (P, U_{c-1}) .
    ///  Here, INT (i) is a four-octet encoding of the integer i, most
    ///    significant octet first.
    final List<int> blocks = <int>[];
    for (int i = 0; i <= numberOfBlocks; i++) {
      final List<int> block = _computeBlock(password, salt, iterations, i);
      if (i < numberOfBlocks) {
        blocks.addAll(block);
      } else {
        blocks.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return blocks;
  }

  /// Get psuedorandom function lenght in bytes
  int get prfLengthInBytes {
    if (_prfLengthInBytes != null) {
      return _prfLengthInBytes;
    }

    final Uint8List digest = _hash.process(new Uint8List.fromList(<int>[1, 2, 3]));
    final int digestLength = digest.lengthInBytes;
    return digestLength;
  }

  List<int> _computeBlock(String password, String salt, int iterations, int blockNumber) {
    /// password P and the concatenation of the salt S and the block index i:

    final List<int> inputForPrf = password.codeUnits;
    inputForPrf.addAll(salt.codeUnits);
    final Uint8List key = new Uint8List.fromList(inputForPrf);
    final KeyParameter keyParam = new KeyParameter(key);
    final HMac hmac = new HMac(_hash, password.codeUnits.length);
    hmac.init(keyParam);
    return null;
  }
}

void main() {
  final String password = '';
  final String salt = 'mnemonic$password';
  final List<int> inputForPrf = password.codeUnits;
  inputForPrf.addAll(salt.codeUnits);
  final Uint8List key = new Uint8List.fromList(inputForPrf);
  final KeyParameter keyParam = new KeyParameter(key);
  final HMac hmac = new HMac(new SHA256Digest(), password.codeUnits.length);
  hmac.init(keyParam);
  // final PBKDF2 p = new PBKDF2(new SHA256Digest());
  // print(formatBytesAsHexString(new Uint8List.fromList(p.deriveKey(password, salt, 2048, 512))));

  PBKDF2KeyDerivator pp = new PBKDF2KeyDerivator(hmac);
  pp.init(params)
}
