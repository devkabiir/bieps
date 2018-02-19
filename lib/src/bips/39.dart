library bieps.bips.bip39;

import 'dart:typed_data';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import '../utils/utils.dart';
import 'en-mnemonic-word-list.dart';

/// Used for generating 12-24 words which can be then be converted to 512-bit seed
class BIP39 {
  static final int _seedIterations = 2048;
  static final int _seedKeySize = 64;
  static final List<String> _wordList = mnemonicWordList;

  ///
  static List<String> generateMnemonics(Uint8List initialEntropy) {
    final List<String> results = <String>[];
    return results;
  }

  ///
  static Uint8List generateSeed(String mnemonic, [String passphrase]) {
    final String salt = 'mnemonic${passphrase ?? ''}';
    print('Mnemonic: $mnemonic');
    print('Salt: $salt');

    final Pbkdf2Parameters params =
        new Pbkdf2Parameters(createUint8ListFromString(salt), _seedIterations, _seedKeySize);

    /// Without mirrors (flutter)
    ///     HMac._DIGEST_BLOCK_LENGTH['SHA-512'] = 128
    final HMac hmanSha512 = new HMac(new SHA512Digest(), 128)..reset();
    final PBKDF2KeyDerivator gen = new PBKDF2KeyDerivator(hmanSha512)..init(params);
    return gen.process(createUint8ListFromString(mnemonic));
  }
}

void main() {
  final String generatedSeedHex = formatBytesAsHexString(
      BIP39.generateSeed('legal winner thank year wave sausage worth useful legal winner thank yellow', 'TREZOR'));
  print(generatedSeedHex);
  final String expected =
      '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607';
  if (generatedSeedHex == expected) {
    print('it works');
  }
}
