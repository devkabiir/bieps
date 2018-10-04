/// Copied from pointycastle/test/src/helpers.dart;

library bieps.util.helperss;

import 'dart:typed_data';

/// Converts given string of [bits] to an integer (byte)
int bitToByte(String bits) => int.parse(bits, radix: 2);

/// Converts given list of [bytes] to a string of bits.
String bytesToBits(Uint8List bytes) =>
    bytes.map((int x) => x.toRadixString(2).padLeft(8, '0')).join();

/// Coverts given [hex] string to `Uint8List`
Uint8List createUint8ListFromHexString(String hex) {
  final Uint8List result = Uint8List(hex.length ~/ 2);

  for (int i = 0; i < hex.length; i += 2) {
    final String number = hex.substring(i, i + 2);
    final int byte = int.parse(number, radix: 16);

    result[i ~/ 2] = byte;
  }

  return result;
}

/// Coverts given [string] to `Uint8List`
Uint8List createUint8ListFromString(String string) {
  final Uint8List ret = Uint8List(string.length);

  for (int i = 0; i < string.length; i++) {
    ret[i] = string.codeUnitAt(i);
  }

  return ret;
}

/// Creates `Uint8List` of [len] with incremental values of each element
Uint8List createUint8ListOfSequentialNumbers(int len) {
  final Uint8List ret = Uint8List(len);

  for (int i = 0; i < len; i++) {
    ret[i] = i;
  }

  return ret;
}

/// Coverts given [size] to human readable format returns size in
/// `B`(bytes), `KB`(KiloBytes), `MB`(MegaBytes) and `GB`(GigaBytes)
String formatAsHumanSize(num size) {
  if (size < 1024) {
    return '$size B';
  }

  if (size < 1024 * 1024) {
    return '${_format(size / 1024)} KB';
  }

  if (size < 1024 * 1024 * 1024) {
    return '${_format(size / (1024 * 1024))} MB';
  }

  return '${_format(size / (1024 * 1024 * 1024))} GB';
}

/// Truncates the given [string] after [truncAt] length and appends `[[...]]`
/// Returns `(empty string)` for empty string
/// Returns [string] if length < [truncAt]
String formatAsTruncated(String string, [int truncAt = 26]) {
  if (string.isEmpty) {
    return '(empty string)';
  }

  if (string.length > truncAt) {
    return '${string.substring(0, truncAt)}[...]';
  }

  return string;
}

/// Converts [bytes] to hexadecimal and returns it as string
String formatBytesAsHexString(Uint8List bytes) {
  final StringBuffer result = StringBuffer();

  for (int i = 0; i < bytes.lengthInBytes; i++) {
    final int part = bytes[i];

    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }

  return result.toString();
}

/// Formats [val] to 3 decimal places and converts to string
String _format(double val) {
  if (val.isInfinite) {
    return 'INF';
  } else if (val.isNaN) {
    return 'NaN';
  } else {
    return '${val.floor().toString()}.${(100 * (val - val.toInt())).toInt().toString()}';
  }
}
