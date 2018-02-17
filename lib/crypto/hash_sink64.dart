// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

// Constants.

import 'dart:typed_data';
import 'package:crypto/src/utils.dart';
import 'package:crypto/src/digest.dart';
import 'package:typed_data/typed_buffers.dart';

/// A bitmask that limits an integer to 32 bits.
const int mask8 = 0xff;

/// A bitmask that limits an integer to 64 bits.
const int mask64 = 0xffffffffffffffff;

/// The number of bytes in a 64-bit word.
const int bytesPerWord64 = 8;

/// A base class for [Sink] implementations for hash algorithms.
///
/// Subclasses should override [updateHash] and [digest].
abstract class HashSink64 implements Sink<List<int>> {
  /// The inner sink that this should forward to.
  final Sink<Digest> _sink;

  /// Whether the hash function operates on big-endian words.
  final Endian _endian;

  /// The words in the current chunk.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [_iterate].
  final Uint64List _currentChunk;

  /// Messages with more than 2^64-1 bits are not supported.
  /// So the maximum length in bytes is (2^64-1)/8.
  static const int _maxMessageLengthInBytes = 0x1fffffffffffffff;

  /// The length of the input data so far, in bytes.
  int _lengthInBytes = 0;

  /// Data that has yet to be processed by the hash function.
  final Uint8Buffer _pendingData = new Uint8Buffer();

  /// Whether [close] has been called.
  bool _isClosed = false;

  int _chunkSizeInWords;

  /// Creates a new hash.
  ///
  /// [chunkSizeInWords] represents the size of the input chunks processed by
  /// the algorithm, in terms of 64-bit words.
  HashSink64(this._sink, int chunkSizeInWords, {Endian endian: Endianness.BIG_ENDIAN})
      : _endian = endian,
        _currentChunk = new Uint64List(chunkSizeInWords),
        _chunkSizeInWords = chunkSizeInWords;

  /// The words in the current digest.
  ///
  /// This should be updated each time [updateHash] is called.
  Uint64List get digest;

  /// Runs a single iteration of the hash computation, updating [digest] with
  /// the result.
  ///
  /// [chunk] is the current chunk, whose size is given by the
  /// `chunkSizeInWords` parameter passed to the constructor.
  void updateHash(Uint64List chunk);

  @override
  void add(List<int> data) {
    if (_isClosed) {
      throw new StateError('Hash.add() called after close().');
    }
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  @override
  void close() {
    if (_isClosed) {
      return;
    }
    _isClosed = true;

    _finalizeData();
    _iterate();
    assert(_pendingData.isEmpty);
    _sink
      ..add(new Digest(_byteDigest()))
      ..close();
  }

  Uint8List _byteDigest() {
    if (_endian == Endianness.HOST_ENDIAN) {
      return digest.buffer.asUint8List();
    }

    final Uint8List byteDigest = new Uint8List(digest.lengthInBytes);
    final ByteData byteData = byteDigest.buffer.asByteData();
    for (int i = 0; i < digest.length; i++) {
      byteData.setUint64(i * bytesPerWord64, digest[i]);
    }
    return byteDigest;
  }

  /// Iterates through [_pendingData], updating the hash computation for each
  /// chunk.
  void _iterate() {
    final ByteData pendingDataBytes = _pendingData.buffer.asByteData();
    final int pendingDataChunks = _pendingData.length ~/ _currentChunk.lengthInBytes;
    for (int i = 0; i < pendingDataChunks; i++) {
      // Copy words from the pending data buffer into the current chunk buffer.
      for (int j = 0; j < _currentChunk.length; j++) {
        _currentChunk[j] = pendingDataBytes.getUint64(i * _currentChunk.lengthInBytes + j * bytesPerWord64, _endian);
      }

      // Run the hash function on the current chunk.
      updateHash(_currentChunk);
    }

    // Remove all pending data up to the last clean chunk break.
    _pendingData.removeRange(0, pendingDataChunks * _currentChunk.lengthInBytes);
  }

  /// Finalizes [_pendingData].
  ///
  /// This adds a 1 bit to the end of the message, and expands it with 0 bits to
  /// pad it out.
  // void _finalizeData() {
  //   // Pad out the data with 0x80, eight 0s, and as many more 0s as we need to
  //   // land cleanly on a chunk boundary.
  //   _pendingData.add(0x80);
  //   final int contentsLength = _lengthInBytes + 9;
  //   final int finalizedLength = _roundUp(contentsLength, _currentChunk.lengthInBytes);
  //   for (int i = 0; i < finalizedLength - contentsLength; i++) {
  //     _pendingData.add(0);
  //   }

  //   if (_lengthInBytes > _maxMessageLengthInBytes) {
  //     throw new UnsupportedError('Hashing is unsupported for messages with more than 2^64 bits.');
  //   }

  //   final int lengthInBits = _lengthInBytes * bitsPerByte;

  //   // Add the full length of the input data as a 64-bit value at the end of the
  //   // hash.
  //   final int offset = _pendingData.length;
  //   _pendingData.addAll(new Uint8List(8));
  //   final ByteData byteData = _pendingData.buffer.asByteData();

  //   // We're essentially doing byteData.setUint64(offset, lengthInBits, _endian)
  //   // here, but that method isn't supported on dart2js so we implement it
  //   // manually instead.
  //   final int highBits = lengthInBits >> 32;
  //   final int lowBits = lengthInBits & mask32;
  //   if (_endian == Endianness.BIG_ENDIAN) {
  //     byteData..setUint32(offset, highBits, _endian)..setUint32(offset + bytesPerWord, lowBits, _endian);
  //   } else {
  //     byteData..setUint32(offset, lowBits, _endian)..setUint32(offset + bytesPerWord, highBits, _endian);
  //   }
  //   _pendingData..clear();
  //   for (int i = 0; i < byteData.lengthInBytes; i++) {
  //     _pendingData.add(byteData.getUint8(i));
  //   }
  // }

  void _finalizeData() {
    _pendingData.add(0x80);
    final int contentsLength = _lengthInBytes + 17;
    final int chunkSizeInBytes = _chunkSizeInWords * bytesPerWord64;
    final int finalizedLength = _roundUp(contentsLength, chunkSizeInBytes);
    final int zeroPadding = finalizedLength - contentsLength;
    for (int i = 0; i < zeroPadding; i++) {
      _pendingData.add(0);
    }
    final int lengthInBits = _lengthInBytes * bitsPerByte;
    assert(lengthInBits < 2 ^ 64);
    _pendingData..addAll(_wordToBytes(0))..addAll(_wordToBytes(lengthInBits & mask64));
  }

  // Convert a 64-bit word to eight bytes.
  List<int> _wordToBytes(int word) {
    final List<int> bytes = new List<int>(bytesPerWord64);
    bytes[0] = (word >> (56)) & mask8;
    bytes[1] = (word >> (48)) & mask8;
    bytes[2] = (word >> (40)) & mask8;
    bytes[3] = (word >> (32)) & mask8;
    bytes[4] = (word >> (24)) & mask8;
    bytes[5] = (word >> (16)) & mask8;
    bytes[6] = (word >> (8)) & mask8;
    bytes[7] = (word >> (0)) & mask8;
    return bytes;
  }

  /// Rounds [val] up to the next multiple of [n], as long as [n] is a power of
  /// two.
  int _roundUp(int val, int n) => (val + n - 1) & -n;
}
