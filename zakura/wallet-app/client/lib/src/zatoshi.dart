/// An amount of ZEC, in the smallest unit the protocol has.
///
/// A raw `int` would work and is what most of this ends up being, but it makes
/// two mistakes easy that this type makes impossible: adding a zatoshi count to
/// a ZEC count, and formatting one as the other. Both produce a number that
/// looks plausible and is wrong by a factor of a hundred million.
extension type const Zatoshi(int value) implements Object {
  /// Nothing.
  static const Zatoshi zero = Zatoshi(0);

  /// How many zatoshis make one ZEC.
  static const int perZec = 100000000;

  /// The largest amount that can exist.
  static const Zatoshi max = Zatoshi(21000000 * perZec);

  /// Builds an amount from a decimal count of ZEC.
  ///
  /// Throws [ArgumentError] if the value is negative or has more than eight
  /// decimal places, because silently rounding somebody's payment is worse than
  /// refusing it.
  factory Zatoshi.fromZec(num zec) {
    if (zec < 0) {
      throw ArgumentError.value(zec, 'zec', 'must not be negative');
    }
    final scaled = zec * perZec;
    if ((scaled - scaled.roundToDouble()).abs() > 1e-6) {
      throw ArgumentError.value(zec, 'zec', 'has more than eight decimals');
    }
    return Zatoshi(scaled.round());
  }

  /// Whether this is nothing at all.
  bool get isZero => value == 0;

  /// The amount in ZEC, for display only.
  ///
  /// Lossy above about 90 million ZEC, which cannot exist, but the loss is real
  /// and this must not be used for arithmetic.
  double get asZec => value / perZec;

  Zatoshi operator +(Zatoshi other) => Zatoshi(value + other.value);

  Zatoshi operator -(Zatoshi other) => Zatoshi(value - other.value);

  bool operator <(Zatoshi other) => value < other.value;

  bool operator >(Zatoshi other) => value > other.value;

  bool operator <=(Zatoshi other) => value <= other.value;

  bool operator >=(Zatoshi other) => value >= other.value;

  /// Formats the amount for a person to read.
  ///
  /// Trailing zeros are trimmed but at least [minimumDecimals] are kept, so a
  /// column of amounts lines up without every row carrying eight decimals.
  String format({int minimumDecimals = 2}) {
    final whole = value ~/ perZec;
    final fraction = value.remainder(perZec).abs().toString().padLeft(8, '0');
    var trimmed = fraction.replaceFirst(RegExp(r'0+$'), '');
    if (trimmed.length < minimumDecimals) {
      trimmed = trimmed.padRight(minimumDecimals, '0');
    }
    final sign = value < 0 && whole == 0 ? '-' : '';
    return trimmed.isEmpty ? '$sign$whole' : '$sign$whole.$trimmed';
  }
}
