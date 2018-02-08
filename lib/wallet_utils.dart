/// Checks if runtimeType match for [value] and [t],
/// if [allowNull] is `false` returns [value] if it's not null,
/// throws `ArgumentError.notNull` otherwise.
/// Specify [varName] for debugging.
dynamic GetVal(dynamic value, Type t,
    {String varName, bool allowNull = false}) {
  if (!allowNull && (null == value)) {
    throw new ArgumentError.notNull('${varName ?? ''}');
  }
  if (value.runtimeType != t) {
    throw new ArgumentError('${varName ?? ''} type mismatch');
  }

  return value;
}
