@testable import Dangerfile
import StewardTesting
import Testing

/// Every rule at once, as a run in GitHub Actions checks a pull request,
/// against a fake host that records what the run posts.
@Suite("Checks")
struct ChecksTests {
    @Test("warnings on changed lines are posted, and the run passes")
    func warnings() async throws {
        let workspace = try ReportWorkspace(logs: [
            "build-macos.log": DiagnosticsTests.buildLog,
            "build-ios.log": "",
            "swiftlint.log": ""
        ])
        defer { workspace.remove() }
        let context = try Context.fixture(diff: SampleDiff.source, workspace: workspace.path)
        let host = FakePullRequestHost(pullRequest: context.pullRequest)
        let outcome = await Checks.run(on: context, postingTo: host)
        #expect(outcome.exitStatus == 0)
        #expect(await host.comments.map(\.body) == [outcome.summary])
    }
}
