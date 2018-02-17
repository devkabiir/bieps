/// Copied from pointycastle/test/src/helpers.dart;
/// // Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.test.src.helpers;

import "dart:typed_data";

import "package:test/test.dart";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Format //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

String formatAsTruncated(String str) {
  if (str.length > 26) {
    return str.substring(0, 26) + "[...]";
  } else if (str.length == 0) {
    return "(empty string)";
  } else {
    return str;
  }
}

String formatAsHumanSize(num size) {
  if (size < 1024) return "$size B";
  if (size < 1024 * 1024) return "${_format(size/1024)} KB";
  if (size < 1024 * 1024 * 1024) return "${_format(size/(1024*1024))} MB";
  return "${_format(size/(1024*1024*1024))} GB";
}

String formatBytesAsHexString(Uint8List bytes) {
  var result = new StringBuffer();
  for (var i = 0; i < bytes.lengthInBytes; i++) {
    var part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
}

String _format(double val) {
  if (val.isInfinite) {
    return "INF";
  } else if (val.isNaN) {
    return "NaN";
  } else {
    return val.floor().toString() + "." + (100 * (val - val.toInt())).toInt().toString();
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Data ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Uint8List createUint8ListFromString(String s) {
  var ret = new Uint8List(s.length);
  for (var i = 0; i < s.length; i++) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}

Uint8List createUint8ListFromHexString(String hex) {
  var result = new Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    var num = hex.substring(i, i + 2);
    var byte = int.parse(num, radix: 16);
    result[i ~/ 2] = byte;
  }
  return result;
}

Uint8List createUint8ListFromSequentialNumbers(int len) {
  var ret = new Uint8List(len);
  for (var i = 0; i < len; i++) {
    ret[i] = i;
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Matchers ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const isAllZeros = const _IsAllZeros();

class _IsAllZeros extends Matcher {
  const _IsAllZeros();

  bool matches(Iterable<int> item, Map matchState) {
    for (var i in item) {
      if (i != 0) return false;
    }
    return true;
  }

  Description describe(Description description) => description.add('is all zeros');

  Description describeMismatch(item, Description mismatchDescription, Map matchState, bool verbose) =>
      mismatchDescription.add("is not all zeros");
}
