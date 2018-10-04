library bieps.bips.bip32;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

import '../utils/utils.dart';

void main() {
  final HMac hmacSha512 = HMac(SHA512Digest(), 128)..reset();
  print(hmacSha512
      .process(createUint8ListFromHexString(
          '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f'))
      .length);
}

class BIP32 {
  /// Ranges from 128bit to 256bit
  final String bip39Seed;
  final String chainCode;
  final int depth = 0;
  final int index = 0;
  final Network network;
  final int parentFingerprint = 0x00000000;

  /// index has these ranges
  ///       Normal: [0, 2^31-1] => used when publickey is used
  ///       Hardened: [2^31, 2^32-1] => used with private key
  void childKeyDerivation(
      Uint32List index, Uint8List parentPrivatekey, Uint8List parentChainCode) {
    final HMac hmacSha512 = HMac(SHA512Digest(), 128)..reset();
    final KeyParameter key = KeyParameter(parentChainCode);
    hmacSha512.init(key);
// hmacSha512.process('data')
  }

  void childKeyDerivationFromPublicKey(
      Uint32List index, Uint8List parentPublickey, Uint8List parentChainCode) {}

  void generatePublicKeyUsingPrivateKey(Uint8List masterPrivateKeym) {}

  static void generateMasterPrivateKey(String bip39seed) {
    final HMac hmacSha512 = HMac(SHA512Digest(), 128)..reset();
    final Uint8List seedHash =
        hmacSha512.process(createUint8ListFromHexString(bip39seed));

    /// master private key m
    final Uint8List seedLeft = Uint8List.fromList(seedHash.sublist(0, 32));

    /// master chain code c
    final Uint8List seedRight =
        Uint8List.fromList(seedHash.sublist(32, seedHash.length));

    /// master public key M is generated from m
  }
}

class Network {}
