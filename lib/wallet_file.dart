import 'package:crypto_wallet/wallet_utils.dart';

/// Ethereum wallet file.
class WalletFile {
  String _address;
  Crypto _crypto;
  String _id;
  int _version;

  bool operator ==(dynamic other) {
    other = GetVal(other, WalletFile);

    if (_address != other._address) {
      return false;
    }

    return true;
  }
}

class Crypto {}
