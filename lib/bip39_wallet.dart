import 'package:dther/wallet_file.dart';
import 'package:meta/meta.dart';

/// Data class for generating a BIP-39 compatible Ethereum wallet.
class BIP39Wallet {
  /// Wallet file
  WalletFile _walletFile;

  /// List of mnemonics used to generate a WalletFile
  final List<String> _mnemonics;

  /// Used to generate a wallet with the given list of mnemonics.
  BIP39Wallet({@required List<String> mnemonics}) : _mnemonics = mnemonics;
}
