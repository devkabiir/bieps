import 'package:test/test.dart';

import '../../lib/bieps.dart';
import '39_test_vectors.dart';

void main() {
  group('BIP39 generate mnemonic tests', () {
    testVectorsForBip39.forEach((List<String> singleTestVector) {
      test('for intropy: ${singleTestVector[0]}', () {
        final String generatedMnemonic =
            BIP39.generateMnemonics(createUint8ListFromHexString(singleTestVector[0])).join(' ');
        expect(generatedMnemonic, equals(singleTestVector[1]));
      });
    });
  });
  group('BIP39 generate seed tests', () {
    testVectorsForBip39.forEach((List<String> singleTestVector) {
      test('for mnemonic: ${singleTestVector[1]}', () {
        final String generatedSeed = formatBytesAsHexString(BIP39.generateSeed(singleTestVector[1], 'TREZOR'));
        expect(generatedSeed, equals(singleTestVector[2]));
      });
    });
  });
}
