/// Copied from pointycastle/test/src/helpers.dart;

library bieps.crypto;

import 'dart:typed_data';

/// Truncates the given [string] after [truncAt] length
/// [truncAt] = 26 (default)
String formatAsTruncated(String string, [int truncAt]) {
  if (string.length > (truncAt ?? 26)) {
    return '${string.substring(0, (truncAt ?? 26))}[...]';
  } else if (string.isEmpty) {
    return '(empty string)';
  } else {
    return string;
  }
}

///
String formatAsHumanSize(num size) {
  if (size < 1024) return '$size B';
  if (size < 1024 * 1024) return '${_format(size/1024)} KB';
  if (size < 1024 * 1024 * 1024) return '${_format(size/(1024*1024))} MB';
  return '${_format(size/(1024*1024*1024))} GB';
}

///
String formatBytesAsHexString(Uint8List bytes) {
  final StringBuffer result = new StringBuffer();
  for (int i = 0; i < bytes.lengthInBytes; i++) {
    final int part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
}

String _format(double val) {
  if (val.isInfinite) {
    return 'INF';
  } else if (val.isNaN) {
    return 'NaN';
  } else {
    return '${val.floor().toString()}.${(100 * (val - val.toInt())).toInt().toString()}';
  }
}

///
Uint8List createUint8ListFromString(String s) {
  final Uint8List ret = new Uint8List(s.length);
  for (int i = 0; i < s.length; i++) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}

///
Uint8List createUint8ListFromHexString(String hex) {
  final Uint8List result = new Uint8List(hex.length ~/ 2);
  for (int i = 0; i < hex.length; i += 2) {
    final String number = hex.substring(i, i + 2);
    final int byte = int.parse(number, radix: 16);
    result[i ~/ 2] = byte;
  }
  return result;
}

///
Uint8List createUint8ListFromSequentialNumbers(int len) {
  final Uint8List ret = new Uint8List(len);
  for (int i = 0; i < len; i++) {
    ret[i] = i;
  }
  return ret;
}

/// Checks if runtimeType match for [value] and [t],
/// if [allowNull] is `false` returns [value] if it's not null,
/// throws `ArgumentError.notNull` otherwise.
/// Specify [varName] for debugging.
/// {WIP}
dynamic getValIfmatch(dynamic value, Type t, {String varName, bool allowNull = false}) {
  if (!allowNull && (null == value)) {
    throw new ArgumentError.notNull('${varName ?? ''}');
  }
  if (value.runtimeType != t) {
    throw new ArgumentError('${varName ?? ''} type mismatch');
  }

  return value;
}
