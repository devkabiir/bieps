library bieps.utils.wallet_file;

class Crypto {}

/// Ethereum wallet file.
/// This holds the private key, public address and can sign arbitrary data.
class WalletFile {
  final String _address;
  final Crypto _crypto;
  final String _id;
  final int _version;

  /// Create a wallet file with given address and version
  WalletFile(this._address, this._crypto, this._id, this._version);

  @override
  int get hashCode => _address.hashCode + _version.hashCode;

  @override
  //ignore: avoid_annotating_with_dynamic
  bool operator ==(dynamic other) {
    if (other is WalletFile) {
      if (_address == other._address && _version == other._version) {
        return true;
      }
    }

    return false;
  }
}
