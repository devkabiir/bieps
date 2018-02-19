class Bit {
  int _data = 0;

  /// By default a Bit is set to 0
  Bit([int data]) {
    x = data;
  }

  /// Set bit
  set x(int x) {
    x ??= 0;
    if (x == 0 || x == 1) {
      _data = x;
    } else {
      throw new ArgumentError('A bit can only be either 0 or 1');
    }
  }

  /// Get bit
  int get x => _data;

  String toString() => _data.toString();
}

class Byte {
  final List<Bit> _data = new List<Bit>.filled(8, new Bit());

  Byte([int number]) {
    number ??= 0;
    if (number < 0 || number > 255) {
      throw new ArgumentError('A byte can only be between 0 & 255');
    }
    if (number == 0) {
      return;
    }
    for (int i = _data.length - 1; i >= 0; i--) {
      if (number >= 2 ^ i) {
        _data[i] = new Bit(1);
        number -= 2 ^ i;
      } else {
        _data[i] = new Bit();
      }
    }
  }

  Bit operator [](int index) {
    return _data[index];
  }

  void operator []=(int index, Bit value) {
    _data[index] = value;
  }

  String toString() => _data.join();
}
