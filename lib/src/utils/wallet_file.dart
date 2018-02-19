library bieps.utils.wallet_file;

import 'helpers.dart';

/// Ethereum wallet file.
/// This holds the private key, public address and can sign arbitrary data.
class WalletFile {
  String _address;
  Crypto _crypto;
  String _id;
  int _version;

  bool operator ==(dynamic other) {
    other = getValIfmatch(other, WalletFile);

    if (_address != other._address) {
      return false;
    }

    return true;
  }
}

class Crypto {}
