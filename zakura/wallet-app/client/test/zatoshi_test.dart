import 'package:test/test.dart';
import 'package:zakura_client/zakura_client.dart';

void main() {
  group('Zatoshi', () {
    test('converts from ZEC', () {
      expect(Zatoshi.fromZec(1).value, 100000000);
      expect(Zatoshi.fromZec(0.00000001).value, 1);
      expect(Zatoshi.fromZec(1.5).value, 150000000);
    });

    test('refuses more precision than exists', () {
      expect(() => Zatoshi.fromZec(0.000000001), throwsArgumentError);
    });

    test('refuses a negative amount', () {
      expect(() => Zatoshi.fromZec(-1), throwsArgumentError);
    });

    test('formats with at least two decimals', () {
      expect(const Zatoshi(100000000).format(), '1.00');
      expect(const Zatoshi(0).format(), '0.00');
    });

    test('keeps the precision it has and trims the rest', () {
      expect(const Zatoshi(150000000).format(), '1.50');
      expect(const Zatoshi(100000001).format(), '1.00000001');
      expect(const Zatoshi(1).format(), '0.00000001');
    });

    test('adds and subtracts', () {
      expect((const Zatoshi(100) + const Zatoshi(50)).value, 150);
      expect((const Zatoshi(100) - const Zatoshi(50)).value, 50);
    });

    test('compares', () {
      expect(const Zatoshi(100) > const Zatoshi(50), isTrue);
      expect(const Zatoshi(50) <= const Zatoshi(50), isTrue);
    });
  });
}
