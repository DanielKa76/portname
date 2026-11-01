import Foundation

/// Localized user-facing text ("Deutsch behalten, Englisch ergänzen").
///
/// The *source strings are the German originals*: every call site passes its
/// German text, and the `Localizable` table maps that text to the current
/// localization (`de.lproj` keeps it, `en.lproj` provides the English
/// variant). A string missing from a table falls back to the German source —
/// new UI text therefore never shows up as a raw key, it is simply
/// German-only until it joins the table.
///
/// Interpolated strings use printf-style patterns (`%@`, `%ld`) via
/// `L10n.format`; the tables carry the full pattern as the key.
///
/// The tables live in SwiftPM's resource bundle (``resourceBundleName``).
/// The shipped app carries it in `Portname.app/Contents/Resources/`
/// (copied by scripts/build-macos-app.sh) and ``resourceBundle`` resolves it
/// explicitly. The generated `Bundle.module` accessor is not used in release
/// builds: it only searches the `.app` root and the build machine's absolute
/// `.build` path and traps (`fatalError`) when neither exists — i.e. on
/// every other Mac.
///
/// The language is CoreFoundation's choice: a nested bundle like this one
/// follows the language chosen for the app itself, among the localizations
/// the APP declares. The app's Info.plist therefore lists every shipped
/// table in `CFBundleLocalizations` (scripts/build-macos-app.sh) — without
/// it, only the development region's table would ever be read.
public enum L10n {
    /// Test/preview hook: force a specific localization ("en", "de").
    /// When nil, the app's preferred localization decides.
    public static var forcedLocalization: String?

    /// File name of the SwiftPM resource bundle that carries the tables.
    static let resourceBundleName = "portname-macos_PortnameCore.bundle"

    /// The bundle the tables are read from, resolved once.
    static let resourceBundle: Bundle = locateResourceBundle()

    /// Returns the localized variant of a German source string.
    public static func text(_ german: String) -> String {
        if let code = forcedLocalization, let value = table(for: code)[german] {
            return value
        }
        // `value: german` keeps the German text for any key missing from the
        // active table — the fallback IS the source string.
        return resourceBundle.localizedString(forKey: german, value: german, table: "Localizable")
    }

    /// Formats a localized pattern with arguments (`%@` strings, `%ld` ints).
    ///
    /// No locale: every `%ld` here is a port, a count, a status or seconds.
    /// With `locale: .current`, Foundation on macOS 27 groups `%ld` in a
    /// German locale, so port 5173 showed up as ":5.173".
    public static func format(_ german: String, _ args: CVarArg...) -> String {
        String(format: text(german), arguments: args)
    }

    /// Loads one localization's table explicitly (deterministic for tests).
    static func table(for localization: String) -> [String: String] {
        guard
            let path = resourceBundle.path(forResource: "Localizable", ofType: "strings",
                                           inDirectory: nil, forLocalization: localization),
            let dict = NSDictionary(contentsOfFile: path) as? [String: String]
        else { return [:] }
        return dict
    }

    /// The explicit search alone, without any fallback; nil when no
    /// candidate holds the resource bundle. Lookup order: the app's
    /// `Contents/Resources` (shipped layout), then bundle-relative
    /// candidates — next to a plain `swift build`/`swift run` executable,
    /// and next to the binary that contains this code (the `swift test`
    /// bundle). Separate from the fallback so a test can tell the two apart:
    /// `Bundle.module` carries the same file name.
    static func explicitResourceBundle() -> Bundle? {
        var candidates: [URL] = []
        if let shipped = Bundle.main.resourceURL {
            candidates.append(shipped.appendingPathComponent(resourceBundleName))
        }
        candidates.append(Bundle.main.bundleURL.appendingPathComponent(resourceBundleName))
        let codeBundle = Bundle(for: BundleToken.self)
        if let codeResources = codeBundle.resourceURL {
            candidates.append(codeResources.appendingPathComponent(resourceBundleName))
        }
        candidates.append(codeBundle.bundleURL.deletingLastPathComponent()
            .appendingPathComponent(resourceBundleName))
        for url in candidates {
            if let bundle = Bundle(url: url) {
                return bundle
            }
        }
        return nil
    }

    /// The explicit search first; `Bundle.module` is a DEBUG-only last
    /// resort. Without any table the app degrades instead of crashing:
    /// `Bundle.main` has no `Localizable` table, so every lookup returns its
    /// German `value:` fallback.
    private static func locateResourceBundle() -> Bundle {
        if let bundle = explicitResourceBundle() {
            return bundle
        }
        #if DEBUG
        return Bundle.module
        #else
        return Bundle.main
        #endif
    }
}

/// Anchor for `Bundle(for:)`: identifies the binary that contains
/// PortnameCore (the app executable, or the `swift test` bundle).
private final class BundleToken {}
