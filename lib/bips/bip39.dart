import 'dart:core';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/export.dart';
import '../crypto/helpers.dart';
import 'en-mnemonic-word-list.dart';
import 'dart:convert';

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
    print(salt);

    ///     _seedIterations = 2048;
    ///     _seedKeySize = 64;
    final Pbkdf2Parameters params = new Pbkdf2Parameters(createUint8ListFromString(salt), 2048, 64);

    /// Using mirrors for everything
    final KeyDerivator gen = new KeyDerivator('SHA-512/HMAC/PBKDF2')..init(params);

    /// Using mirross for hmac only
    final Mac hmac2 = new Mac('SHA-512/HMAC');
    final PBKDF2KeyDerivator gen2 = new PBKDF2KeyDerivator(hmac2)..init(params);

    /// Without mirrors (flutter)
    ///     HMac._DIGEST_BLOCK_LENGTH['SHA-512'] = 128
    ///     HMac(Digest _digest, int _blockLength)
    final HMac hmac3 = new HMac(new SHA512Digest(), 128)..reset();
    final PBKDF2KeyDerivator gen3 = new PBKDF2KeyDerivator(hmac3)..init(params);
    return gen3.process(createUint8ListFromString(mnemonic));
  }
}

void main() {
  final String generatedSeedHex = formatBytesAsHexString(
      BIP39.generateSeed('legal winner thank year wave sausage worth useful legal winner thank yellow'));
  print(generatedSeedHex);
  final String expected =
      '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607';
  if (generatedSeedHex == expected) {
    print('it works');
  }
}
