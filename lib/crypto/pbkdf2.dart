/// Reference https://github.com/jamesots/pbkdf2
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:crypto/src/digest.dart';
import 'package:crypto/src/hmac.dart';
import 'package:crypto/src/hash.dart';
import 'package:pointycastle/export.dart' as pc;
import 'helpers.dart';
import 'sha512.dart';

/// Reference https://tools.ietf.org/html/rfc2898#page-9
class PBKDF2 {
  Hash _hash;
  final List<int> _blockList = new List<int>(4);
  int _prfLengthInBytes;

  /// Initialize with the given [_hash]
  PBKDF2(this._hash);

  ///
  List<int> generateKey(String password, String salt, int c, int dkLen) {
    if (dkLen > (2 << 31 - 1) * prfLengthInBytes) {
      throw new RangeError('derived key too long');
    }

    final int numberOfBlocks = (dkLen / prfLengthInBytes).ceil();
    final int sizeOfLastBlock = dkLen - (numberOfBlocks - 1) * prfLengthInBytes;

    final List<int> key = <int>[];
    for (int i = 1; i <= numberOfBlocks; ++i) {
      final List<int> block = _computeBlock(password, salt, c, i);
      if (i < numberOfBlocks) {
        key.addAll(block);
      } else {
        key.addAll(block.sublist(0, sizeOfLastBlock));
      }
    }
    return key;
  }

  /// Get psuedorandom function lenght in bytes
  int get prfLengthInBytes {
    if (_prfLengthInBytes != null) {
      return _prfLengthInBytes;
    }

    final Digest digest = _hash.convert(<int>[1, 2, 3]);
    final int digestLength = digest.bytes.length;
    return digestLength;
  }

  List<int> _computeBlock(String password, String salt, int iterations, int blockNumber) {
    Hmac hmac = new Hmac(_hash, password.codeUnits);
    final SyncChunkedConversionSink sink = new SyncChunkedConversionSink();
    final ByteConversionSink outsink = hmac.startChunkedConversion(sink)..add(salt.codeUnits);

    _writeBlockNumber(outsink, blockNumber);

    outsink.close();
    sink.close();

    final List<int> bytes = sink.getAll();
    List<int> lastDigest = bytes;
    final List<int> result = new List<int>.from(bytes);

    for (int i = 1; i < iterations; i++) {
      hmac = new Hmac(_hash, password.codeUnits);
      final Digest newDigest = hmac.convert(lastDigest);

      _xorLists(result, newDigest.bytes);

      lastDigest = newDigest.bytes;
    }

    return result;
  }

  void _writeBlockNumber(ByteConversionSink hmac, int blockNumber) {
    _blockList[0] = blockNumber >> 24;
    _blockList[1] = blockNumber >> 16;
    _blockList[2] = blockNumber >> 8;
    _blockList[3] = blockNumber;
    hmac.add(_blockList);
  }

  void _xorLists(List<int> list1, List<int> list2) {
    for (int i = 0; i < list1.length; i++) {
      list1[i] = list1[i] ^ list2[i];
    }
  }
}

///
class SyncChunkedConversionSink extends ChunkedConversionSink<Digest> {
  ///
  final List<Digest> accumulated = <Digest>[];

  @override
  void add(Digest chunk) {
    accumulated.add(chunk);
  }

  @override
  void close() {}

  ///
  List<int> getAll() => accumulated.fold(<int>[], (List<int> acc, Digest current) => acc..addAll(current.bytes));
}

void main() {
  final String password = '';
  final String salt = 'mnemonic$password';
  final int iterations = 2048;
  final int dLen = 64;

  /// Needs sha512
  final PBKDF2 gen = new PBKDF2(sha256.newInstance());
  final List<int> out = gen.generateKey(password, salt, iterations, dLen);

  print(formatBytesAsHexString(new Uint8List.fromList(out)));
}
