import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'helpers.dart';

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
    for (int i = 1; i <= numberOfBlocks; ++i) {
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
    /// PRF is applied to thepassword P and the concatenation of
    /// the salt S and the block index i:
    /// Key is the password and Message is salt
    final Uint8List saltBytes = new Uint8List.fromList(createUint8ListFromString(salt));
    final Uint8List key = new Uint8List.fromList(createUint8ListFromString(password));
    final KeyParameter keyParam = new KeyParameter(key);

    ///     U_1 = PRF (P, S || INT (i))
    /// Apply PRF on password and (salt and index i)
    /// here either the length is 64(bytes) or 512(bits)
    HMac hmac = new HMac(_hash, 64)..init(keyParam);

    /// Concatenate salt and INT (i)
    /// Here, INT (i) is a four-octet encoding of the integer i, most
    /// significant octet first
    /// FIXME:
    Uint8List message = saltBytes;
    message = _writeBlockNumber(message, blockNumber);

    /// firstBlock represents :
    ///     U_1
    final List<int> firstBlock = hmac.process(message).toList();
    Uint8List lastDigest = new Uint8List.fromList(firstBlock);
    final List<int> result = new List<int>.from(firstBlock);

    ///       U_2 = PRF (P, U_1) ,
    ///       ...
    ///       U_c = PRF (P, U_{c-1}) .
    for (int i = 0; i < iterations; i++) {
      hmac = new HMac(_hash, 64)..init(keyParam);
      final List<int> newDigest = hmac.process(lastDigest).toList();

      ///     U_1 \xor U_2 \xor ... \xor U_c
      _xorLists(result, newDigest);

      lastDigest = new Uint8List.fromList(newDigest);
    }

    return result;
  }

  void _xorLists(List<int> list1, List<int> list2) {
    for (int i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }

  Uint8List _writeBlockNumber(Uint8List message, int blockNumber) {
    final List<int> newMessage = message.toList();
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    newMessage.addAll(_blockList);
    return new Uint8List.fromList(newMessage);
  }
}

void main() {
  final String password = '';
  final String salt = 'mnemonic$password';
  final int iterations = 2048;
  final int dLen = 64;
  final PBKDF2 gen = new PBKDF2(new SHA256Digest());
  final List<int> out = gen.deriveKey(password, salt, iterations, dLen);
  print(formatBytesAsHexString(new Uint8List.fromList(out)));

  // pp.init(params)
}
