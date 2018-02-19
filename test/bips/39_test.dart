import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';

import '../../lib/bieps.dart';

void main() {
  test('BIP39 generate mnemonic', () {
    final List<int> elements = new List<int>.generate(16, (int index) {
      final Random rng = new Random.secure();

      return rng.nextInt(255);
    });
    final Uint8List initialEntropy = createUint8ListFromHexString('1998bc74c9ec24c6964233c332a86b0b49009765');
    print(BIP39.generateMnemonics(initialEntropy));
  }, skip: true);
  test('BIP39 Seed Test', () {
    final String testPassphrase = '';
    final String testMnemonic = 'bullet issue candy captain wheel keep budget recall country slot slot trouble';
    final String testSeed =
        '766881710e81d10abf7faa91f4d778659bbd2682462081231b8fcbbbce7afb52ff049039a2adf77ce237504507ab1b906bab55759b65c74d0962008046c25d9a';

    final Uint8List generatedSeed = BIP39.generateSeed(testMnemonic, testPassphrase);
    final String generatedSeedHex = formatBytesAsHexString(generatedSeed);

    expect(generatedSeedHex, equals(testSeed));
  }, skip: false);
}
