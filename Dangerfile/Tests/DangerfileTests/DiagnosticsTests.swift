@testable import Dangerfile
import StewardTesting
import Testing

@Suite("Diagnostics on changed lines")
struct DiagnosticsTests {
    /// A build log with a warning on the line `SampleDiff.source` adds and
    /// one on a line it leaves alone.
    static let buildLog = """
        /ci/NetNewsWire/Shared/Timeline/ArticleFetcher.swift:2:5: warning: initialization of immutable value \
        'unused' was never used
        /ci/NetNewsWire/Shared/Timeline/ArticleFetcher.swift:3:10: warning: never reported
        """

    /// A SwiftLint log, in its default reporter's format, with a violation
    /// on the added line.
    static let swiftLintLog = """
        /ci/NetNewsWire/Shared/Timeline/ArticleFetcher.swift:2:15: warning: Trailing Whitespace Violation: \
        Lines should not have trailing whitespace (trailing_whitespace)
        """

    @Test("a warning on a changed line, in any log, is a warning")
    func warnings() async throws {
        let workspace = try ReportWorkspace(logs: [
            "build-macos.log": Self.buildLog,
            "build-ios.log": "",
            "swiftlint.log": Self.swiftLintLog
        ])
        defer { workspace.remove() }
        let context = try Context.fixture(diff: SampleDiff.source, workspace: workspace.path)
        let findings = try await Checks.diagnostics.evaluate(context)
        let location = Location(path: "Shared/Timeline/ArticleFetcher.swift", line: 2)
        #expect(findings.map(\.kind) == [.warning, .warning])
        #expect(findings.map(\.location) == [location, location])
    }

    @Test("a missing log is a failure")
    func missingLog() async throws {
        let workspace = try ReportWorkspace(logs: ["build-macos.log": "", "swiftlint.log": ""])
        defer { workspace.remove() }
        let context = try Context.fixture(diff: SampleDiff.source, workspace: workspace.path)
        let findings = try await Checks.diagnostics.evaluate(context)
        #expect(findings.map(\.kind) == [.failure])
        #expect(findings.first?.text.contains("`build-ios.log`") == true)
    }
}
