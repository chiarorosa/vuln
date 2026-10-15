<div align="center">

<img src="desktop/assets/vuln.png" width="96" alt="VULN logo">

# VULN

**Open-source desktop workbench for web application security testing.**
Intercepting proxy, Repeater, Intruder, Scanner, WebSockets, Decoder and more, in one native Windows app.

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/chiarorosa/vuln?label=release)](https://github.com/chiarorosa/vuln/releases/latest)
[![Build](https://github.com/chiarorosa/vuln/actions/workflows/build.yml/badge.svg)](https://github.com/chiarorosa/vuln/actions/workflows/build.yml)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Java 21](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/chiarorosa/vuln?style=social)](https://github.com/chiarorosa/vuln/stargazers)

[**Download**](https://github.com/chiarorosa/vuln/releases/latest) ·
[Features](#features) ·
[Build from source](#build-from-source) ·
[Extensions](#writing-an-extension) ·
[Roadmap](desktop/VULN-Roadmap.md) ·
[Contributing](CONTRIBUTING.md) ·
[Português](README.pt-BR.md)

<img src="docs/screenshot.png" alt="VULN Repeater: editable raw HTTP request on the left, response on the right" width="900">

</div>

---

## Why VULN?

- **Free and open source.** GPL-3.0, no license keys, no telemetry, no account.
- **Native and offline.** A Java/Swing desktop app with a bundled Java runtime. Download, unzip and run `VULN.exe`. Nothing to install, no browser wrapper.
- **Honest output.** VULN shows real measured traffic only, with no demo data. Findings are labeled as evidence that needs review, not as proof of a vulnerability.
- **Hackable.** A small codebase with no build framework, a one-method extension API and an integration suite that runs against real loopback servers.

## Features

| Tool | What it does |
|---|---|
| **Proxy** | HTTP/1.1 intercepting proxy with manual request/response interception (Forward, edit, Drop), history and opt-in HTTPS interception through a local CA |
| **Repeater** | Edit a raw HTTP request and resend it. Shows Params and Headers views, status, time and size. JSON responses are syntax-highlighted. Shortcut: `Ctrl+Enter` |
| **Intruder** | Four payload-position attack modes with wordlists, URL encoding, request limits, delays and cancellation |
| **Scanner** | Same-origin crawl with passive header and cookie checks and optional reflection detection. Exports an HTML report |
| **WebSockets** | Direct `ws://` and `wss://` client for text messages, with a log of received binary sizes |
| **Target** | Map of observed hosts and paths |
| **Decoder** | URL/form, Base64 and Hex |
| **Sequencer** | Collects tokens by regex and reports descriptive statistics |
| **Comparer** | Line diff between two messages |
| **TLS** | Local CA generation, PKCS#12 import/export and upstream certificate validation |
| **Extensions** | Load your own Java JAR inspectors through the `VulnExtension` API |
| **Projects** | Save and reopen history, drafts and findings |
| **Wiki** | Offline help in Brazilian Portuguese: twenty articles with search (`F1`) |

**Coming next on `main`** (in source, not yet in the 3.2.1 binary): WebSocket proxy with frame edit/drop, HTTP/2 over ALPN, session macros with token refresh, bounded-concurrency Intruder, a custom scan-check DSL, a codec pipeline, an isolated JavaScript scripting sandbox, a local callback service (HTTP/DNS), a dedicated browser for DOM link extraction, and HAR import/export.

See the [roadmap](desktop/VULN-Roadmap.md) for what is not implemented yet. It is a good place to pick a first contribution.

## Quick start

1. Download `VULN-<version>-windows-x64.zip` from [Releases](https://github.com/chiarorosa/vuln/releases/latest).
2. Unzip it and run `VULN.exe`. A Java runtime is bundled.
3. Open **Overview → Start local test server**, return to **Repeater** and press **Send**.

## Build from source

Requirements: Windows, **JDK 21+** (with `JAVA_HOME` set) and **Node.js 18+**. Node is only used to download and checksum-verify dependencies.

```powershell
git clone https://github.com/chiarorosa/vuln.git
cd vuln\desktop
node setup-deps.mjs            # FlatLaf (Apache-2.0), verified against Maven Central SHA-1
node setup-workspace-deps.mjs  # Rhino (MPL-2.0) and curl, checksum-verified
.\build.ps1                    # -> desktop\dist-vuln\vuln.jar
.\test.ps1                     # build + full integration suite (loopback only)
.\package-vuln.ps1             # Windows app image with bundled runtime (jlink + jpackage)
```

Run the jar directly:

```powershell
java --add-modules jdk.httpserver -jar dist-vuln\vuln.jar
```

### Tests

`test.ps1` runs `vuln.jar --self-test`. The suite starts real local servers and checks the HTTP/TLS stack end to end. It covers framing and binary bodies, chunked encoding, `Expect: 100-continue`, rejection of ambiguous framing, interception, CONNECT and HTTPS modification, all Intruder modes, crawl and scanner evidence, WebSocket frames, project persistence, certificate SANs and extension loading. All traffic stays on loopback.

## Writing an extension

Implement a single interface:

```java
public class HeaderInspector implements VulnExtension {
    public String name() { return "Example: server header inventory"; }
    public List<Issue> inspect(String method, String url, byte[] request, byte[] response) {
        // return zero or more Issue(severity, title, evidence)
    }
}
```

Register the class in `META-INF/services/VulnExtension`, package the JAR and load it from **Extensions**. A complete example is in [`desktop/extensions`](desktop/extensions).

## Project layout

```
desktop/
  src/            application sources (Swing + FlatLaf), integration tests
  extensions/     sample extension and its build script
  assets/         icon
  tools/          icon generator
  build.ps1 · test.ps1 · package-vuln.ps1 · setup-*.mjs
DESIGN.md         UI design system (palette, spacing, typography)
```

## Contributing

Contributions are welcome: bug reports, roadmap features, scan checks, extensions, documentation and translations of the Wiki. Read [CONTRIBUTING.md](CONTRIBUTING.md) to get started, and look for issues labeled [`good first issue`](https://github.com/chiarorosa/vuln/labels/good%20first%20issue).

If VULN is useful to you, **consider giving it a ⭐**. It helps other people find the project.

## Responsible use

VULN is for testing systems **you own or are explicitly authorized to test**. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse. To report a security issue in VULN itself, see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0](LICENSE) © Pablo De Chiaro Rosa. Third-party dependencies keep their own licenses: FlatLaf (Apache-2.0) and Rhino (MPL-2.0).
