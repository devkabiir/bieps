import 'dart:typed_data';

import 'package:crypto/src/digest.dart';
import 'package:test/test.dart';
import '../lib/crypto/helpers.dart';
import '../lib/crypto/sha512.dart';

void main() {
  test('SHA512 Test for abc', () {
    final String test = 'abc';
    final String expectedHash =
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
    final Uint8List testInUint8 = createUint8ListFromString(test);
    final Digest hashed = sha512.newInstance().convert(testInUint8);
    final List<int> inBytes = hashed.bytes;

    expect(hashed.toString(), equals(expectedHash));
  });
}
