import Steward

/// The rules Steward checks this fork's replayed pull requests with.
///
/// The Steward workflow builds the Mac and iOS apps and runs SwiftLint,
/// then runs these rules through steward-action, which posts the summary
/// as a comment on the pull request.
@main
struct Checks: Dangerfile {
    static var rules: [Rule] {
        diagnostics
    }

    /// Both builds' and SwiftLint's diagnostics on the lines the pull request
    /// changes. Errors fail; warnings and notes are reported.
    static let diagnostics = Rule.diagnosticsOnChangedLines(
        in: [.xcodebuild("build-macos.log"), .xcodebuild("build-ios.log"), .swiftLint("swiftlint.log")]
    )
}
