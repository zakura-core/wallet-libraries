import 'dart:io';

/// What this build of the application is for.
///
/// Told at build time and never inferred: a wallet that decided for itself
/// whether it was a demonstration would be a demonstration that could be
/// mistaken for a wallet. The value comes from `--dart-define=ZAKURA_MODE=`
/// and a build with none is refused on screen rather than defaulted.
enum ZakuraMode {
  /// The in-memory demonstration. Touches no chain, holds no money, and says
  /// so. Never falls back to from another mode.
  demo,

  /// A validation profile: recovers privately so that its results can be
  /// compared with an independent reconstruction. Its transparent figures
  /// are for comparison and are never presented as the balance.
  shadow,

  /// The opt-in recovery beta: restore, synchronise, read balances and
  /// history. Sending is absent from the interface and refused by the native
  /// build. Its transparent figures come from private retrieval and are
  /// named as unverified until the independent correctness gate passes.
  recovery;

  /// Parses the build-time value, or null for one this build does not know.
  static ZakuraMode? parse(String value) {
    for (final mode in values) {
      if (mode.name == value.trim().toLowerCase()) return mode;
    }
    return null;
  }

  /// Whether this mode runs against the real chain with the native wallet.
  bool get isBeta => this != ZakuraMode.demo;

  /// What the mode is called on screen.
  String get label => switch (this) {
    ZakuraMode.demo => 'Demo',
    ZakuraMode.shadow => 'Shadow validation',
    ZakuraMode.recovery => 'Recovery beta',
  };

  /// The sentence shown at the top of every screen in this mode.
  String get banner => switch (this) {
    ZakuraMode.demo =>
      'Demo wallet: nothing here touches a chain, and no money is real.',
    ZakuraMode.shadow =>
      'Shadow validation: transparent figures come from private retrieval '
          'and are for comparison only. They are not a balance. '
          'Sending is disabled.',
    ZakuraMode.recovery =>
      'Recovery beta: restore and read only. Transparent figures come from '
          'private retrieval and have not passed independent verification. '
          'Sending is disabled in this build.',
  };
}

/// Where the beta keeps its wallets, and what it was told to talk to.
///
/// Everything here comes from build-time defines. Nothing is defaulted for a
/// beta mode: a default endpoint is a host the wallet talks to because nobody
/// chose otherwise, and a default directory is somebody's existing wallet.
class BetaConfig {
  /// The mode, or null when none or an unknown one was given.
  final ZakuraMode? mode;

  /// The raw mode string, for the error that names it.
  final String modeText;

  /// The lightwalletd endpoint.
  final String lightwalletdUrl;

  /// Where the shard map and public filters come from, if configured.
  final String? transparentFiltersUrl;

  /// Where private retrieval is answered, if configured.
  final String? transparentShardsUrl;

  const BetaConfig({
    required this.mode,
    required this.modeText,
    required this.lightwalletdUrl,
    required this.transparentFiltersUrl,
    required this.transparentShardsUrl,
  });

  /// The lightwalletd server the beta uses when none is given.
  ///
  /// The one default, because it is public, mainnet, and what the shielded
  /// scan needs before the private ledger has anything to bind to. The
  /// chain it serves is checked before the wallet opens and again on every
  /// connection.
  static const defaultLightwalletdUrl = 'https://us.zec.stardust.rest:443';

  /// Reads the build-time defines.
  static BetaConfig fromEnvironment() => fromValues(
    mode: const String.fromEnvironment('ZAKURA_MODE'),
    lightwalletdUrl: const String.fromEnvironment('ZAKURA_LIGHTWALLETD'),
    filters: const String.fromEnvironment('ZAKURA_TRANSPARENT_FILTERS'),
    shards: const String.fromEnvironment('ZAKURA_TRANSPARENT_SHARDS'),
  );

  /// Builds a configuration from the strings the defines would carry.
  static BetaConfig fromValues({
    required String mode,
    required String lightwalletdUrl,
    required String filters,
    required String shards,
  }) => BetaConfig(
    mode: ZakuraMode.parse(mode),
    modeText: mode,
    lightwalletdUrl: lightwalletdUrl.isEmpty
        ? defaultLightwalletdUrl
        : lightwalletdUrl,
    transparentFiltersUrl: filters.isEmpty ? null : filters,
    transparentShardsUrl: shards.isEmpty ? null : shards,
  );

  /// Everything wrong with this configuration for the mode it names.
  ///
  /// Empty means the beta may try to start. The native side checks the same
  /// things again when the wallet opens, so nothing here is the only line;
  /// this is what lets the screen say precisely what to fix.
  List<String> problems() {
    final out = <String>[];
    final mode = this.mode;
    if (mode == null) {
      out.add(
        modeText.isEmpty
            ? 'No mode was configured. Build with '
                  '--dart-define=ZAKURA_MODE=demo, shadow or recovery.'
            : 'The mode "$modeText" is not one this build knows: use demo, '
                  'shadow or recovery.',
      );
      return out;
    }
    if (!mode.isBeta) return out;
    if (transparentFiltersUrl == null || transparentShardsUrl == null) {
      out.add(
        'Both transparent services must be configured: '
        'ZAKURA_TRANSPARENT_FILTERS and ZAKURA_TRANSPARENT_SHARDS. Their '
        'absence is not an empty transparent history.',
      );
    }
    for (final (what, url) in [
      ('light server', lightwalletdUrl),
      ('filter service', transparentFiltersUrl),
      ('shard service', transparentShardsUrl),
    ]) {
      if (url != null && !url.startsWith('https://')) {
        out.add('The $what must be reached over TLS: $url');
      }
    }
    final filters = transparentFiltersUrl;
    final shards = transparentShardsUrl;
    if (filters != null && shards != null && hostOf(filters) == hostOf(shards)) {
      out.add(
        'The filter service and the shard service are one host, which could '
        'join the public filter reads to the private queries.',
      );
    }
    return out;
  }

  /// The scheme-free authority of a URL, for comparison only.
  static String hostOf(String url) {
    final rest = url.contains('://') ? url.split('://')[1] : url;
    return rest.split('/').first;
  }
}

/// Where a beta profile lives, apart from every other wallet on the machine.
///
/// Under the application's own support directory and under the mode's name,
/// so a shadow profile and a recovery profile never share a store and neither
/// is the example wallet's `.zakura-example`. A marker file records what the
/// directory was made for; a directory made for something else is refused
/// rather than opened, and never altered.
class BetaProfile {
  /// The directory the wallet's two files live in.
  final String directory;

  /// The mode the directory belongs to.
  final ZakuraMode mode;

  const BetaProfile({required this.directory, required this.mode});

  /// The application's own namespace.
  static const namespace = 'org.valargroup.zakura-recovery-beta';

  /// The network every beta profile is on.
  static const network = 'main';

  /// The profile for [mode] under [home].
  ///
  /// [home] is the sandbox container's home when the application is
  /// sandboxed, which is what keeps this apart from any wallet outside it.
  static BetaProfile under(String home, ZakuraMode mode) => BetaProfile(
    directory: '$home/Library/Application Support/$namespace/${mode.name}',
    mode: mode,
  );

  /// The marker's path.
  String get marker => '$directory/profile.json';

  /// What the marker says, in a form that carries nothing about the wallet.
  String markerContents() =>
      '{"namespace":"$namespace","mode":"${mode.name}","network":"$network"}';

  /// Creates the directory and its marker, or refuses a directory that was
  /// made for something else.
  ///
  /// Returns what is wrong, or null when the profile is ready. A directory
  /// with wallet files and no marker was not made by this application and is
  /// left exactly as found.
  Future<String?> prepare() async {
    final dir = Directory(directory);
    final markerFile = File(marker);
    if (await markerFile.exists()) {
      final found = await markerFile.readAsString();
      final expected = markerContents();
      if (found.trim() != expected) {
        return 'The profile directory was made for another mode or network '
            'and has been left alone: $directory';
      }
      return null;
    }
    if (await dir.exists()) {
      final entries = await dir.list().toList();
      if (entries.isNotEmpty) {
        return 'The profile directory is not empty and carries no profile '
            'marker, so it was not made by this application and has been '
            'left alone: $directory';
      }
    }
    await dir.create(recursive: true);
    await markerFile.writeAsString('${markerContents()}\n');
    return null;
  }
}
