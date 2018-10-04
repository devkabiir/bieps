
# bieps

[![Build Status](https://travis-ci.com/devkabiir/bieps.svg?branch=master)](https://travis-ci.com/devkabiir/bieps)

BIP/EIP implementations in dart.

## Example

```dart
import 'package:bieps/bieps.dart';

void main(){
final String initialEntropy = '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f';
final String generatedMnemonic = BIP39.generateMnemonics(createUint8ListFromHexString(initialEntropy)).join(' ');

print(generatedMnemonic); // legal winner thank year wave sausage worth useful legal winner thank yellow

final String generatedSeed = formatBytesAsHexString(BIP39.generateSeed(generatedMnemonic, 'TREZOR'));

print(generatedSeed); // 2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607
}
```
