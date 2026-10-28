/// Pull requests' diffs as `git diff` writes them, for the rule tests.
enum SampleDiff {
    /// An edit to a shared source file, which adds its line 2.
    static let source = """
        diff --git a/Shared/Timeline/ArticleFetcher.swift b/Shared/Timeline/ArticleFetcher.swift
        index 1111111..2222222 100644
        --- a/Shared/Timeline/ArticleFetcher.swift
        +++ b/Shared/Timeline/ArticleFetcher.swift
        @@ -1,2 +1,3 @@
         import Foundation
        +let unused = 1
         protocol ArticleFetcher {}

        """
}
