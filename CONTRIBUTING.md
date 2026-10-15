# Contributing to VULN

Thanks for your interest in VULN! Bug reports, features, docs and translations are all welcome. Issues and PRs can be written in **English or Portuguese**.

## Ways to help

- **Report a bug.** Use the bug template and include the VULN version, Windows version and steps to reproduce.
- **Pick a roadmap item.** [`desktop/VULN-Roadmap.md`](desktop/VULN-Roadmap.md) lists what is missing. Comment on or open an issue before starting large work so we can agree on the approach.
- **Add scan checks or extensions.** See the `VulnExtension` example in [`desktop/extensions`](desktop/extensions).
- **Improve the Wiki.** It lives in `desktop/src/WikiContent.java` and is currently in pt-BR. Translations are welcome.
- **Star the repo.** It helps other people find the project.

## Development setup

```powershell
cd desktop
node setup-deps.mjs
node setup-workspace-deps.mjs
.\test.ps1
```

You need JDK 21+ (`JAVA_HOME`) and Node.js 18+. `test.ps1` builds the app and runs the full integration suite.

## Guidelines

1. **Keep it native.** VULN is a Java/Swing desktop app themed with FlatLaf. Please don't propose a web or WebView rewrite.
2. **Follow [`DESIGN.md`](DESIGN.md)** for any UI change: palette, spacing, typography and keyboard access.
3. **Real data only.** No simulated traffic, fake findings or decorative placeholders in the UI.
4. **Test networking locally.** Add an integration check in the `*Tests.java` files. Tests must use loopback fixtures and never reach third-party hosts.
5. **Describe capabilities honestly.** Docs and UI should state limits clearly. A heuristic result is evidence to review, not proof of a vulnerability.
6. **Match the surrounding code style.** Keep changes focused and avoid new dependencies unless they are discussed first.
7. **Keep compatibility.** Existing project files and the `VulnExtension` API should keep working.

## Pull requests

1. Fork the repo and create a branch: `git checkout -b feature/my-change`.
2. Make your change and run `.\test.ps1` until every check passes.
3. Open a PR that describes **what** changed and **why**. Add screenshots for UI changes.

By contributing, you agree that your contributions are licensed under [GPL-3.0](LICENSE).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be kind.
