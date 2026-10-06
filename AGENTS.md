# AGENTS.md

Guidance for AI coding agents (Claude, Gemini, Codex, Copilot and others) working in this repository. Humans are welcome to read it too.

## Project

**Agamemnon** is a free, open-source antivirus for macOS, licensed under GPLv2 and shipped as a DMG. It is a native SwiftUI app with a menu bar icon.

- **Mac repo:** https://github.com/Agamemnon-Intelligence/Agamemnon-macOS (this one)
- **Windows repo:** https://github.com/Agamemnon-Intelligence/Agamemnon-windows (separate, in development)
- **Creators:** mirazbakis and mertyesileducation. Keep both credited in the README, the About page and Info.plist.

Read [HOW_IT_WORKS.md](HOW_IT_WORKS.md) before changing detection, quarantine, real-time protection or DNS behaviour. It's the source of truth for how those parts work, so **update it whenever you change that behaviour.**

## Repository layout

```
App/
├── AgamemnonApp.swift      Entry point: main Window + MenuBarExtra, AppDelegate
├── Engine/                 Detection, no UI: Signatures, ScanEngine, ArchiveInspector,
│                           Gatekeeper, ClamAV, Models
├── Services/               @MainActor ObservableObjects: AppModel (owns everything),
│                           ScanController, SignatureManager, QuarantineVault,
│                           DownloadGuard, SystemWatchers, DNSManager, ScanScheduler,
│                           ActivityLog
├── Support/                Shell/LineProcess, FolderWatcher (FSEvents), AppPaths,
│                           Prefs, Privileged (admin prompt)
├── Views/                  SwiftUI pages + Theme.swift (colours, glass, components)
└── Assets.xcassets         AppIcon, Emblem, AccentColor
Support/                    Info.plist, Agamemnon.entitlements
scripts/make-dmg.sh         Packs the .app into a DMG
project.yml                 XcodeGen project definition
.github/workflows/build.yml CI: build → sign → DMG → (notarize) → nightly release
```

## Building

The Xcode project is **generated** and not committed.

```sh
brew install xcodegen
xcodegen generate
xcodebuild -project Agamemnon.xcodeproj -scheme Agamemnon -configuration Debug build
```

- If you add, move or delete source files, nothing needs editing: `project.yml` picks up everything under `App/`. Run `xcodegen generate` again.
- Never commit `Agamemnon.xcodeproj/`, `build/`, `*.dmg` or signing material.
- GitHub Actions is the reference build: a universal binary (arm64 + x86_64) built with the latest Xcode. If you can't build locally (for example on Linux), say so plainly. Don't claim code compiles when you couldn't compile it.
- Signing secrets (`DEVELOPER_ID_P12`, `DEVELOPER_ID_P12_PASSWORD`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`) are optional. Without them CI makes an ad-hoc signed build.

## Platform and language rules

- **Deployment target: macOS 13.0.** Anything newer needs an `if #available` / `@available` check with a working fallback.
- **Swift 5 language mode** (`SWIFT_VERSION: 5.0`). Don't switch to Swift 6 mode without fixing strict-concurrency errors across the project.
- **Concurrency:**
  - Services are `@MainActor final class … : ObservableObject` with `@Published` state, and every file that uses them has `import Combine`.
  - Heavy work (scanning, hashing, unpacking, downloads) runs off the main actor: `Task.detached`, a `DispatchQueue` or `Thread.detachNewThread`.
  - Results come back with `Task { @MainActor in … }`. Don't use `DispatchQueue.main.async` to touch main-actor state.
  - `nonisolated static` helpers can't read main-actor statics. Mark shared constants `nonisolated` too.
- **Not sandboxed, Hardened Runtime on.** The app must read the whole disk and run system tools. Don't enable the App Sandbox.
- **No new dependencies** (Swift packages, CocoaPods, bundled binaries) without the maintainers' agreement. Prefer Foundation, SwiftUI, AppKit and the tools that ship with macOS.
- Run command-line tools through `Shell.run` (one-shot) or `LineProcess` (streaming). Always pass a `timeout` and full tool paths (`/usr/bin/bsdtar`, not `bsdtar`).

## UI and design

- **Dark midnight theme only.** The app forces `.dark`. Use the `Theme` colours, never hard-coded colours in views:
  - midnight `#050916` / `#0A1230`
  - card `#0D1632`
  - navy buttons `#1B3474`
  - accent `#5B93FF`
  - gold `#D8B26A`
  - success, warning and danger colours for status
- **Liquid Glass:** use the helpers in `Theme.swift` instead of calling `glassEffect` directly:
  - `.liquidGlass(shape, tint:, interactive:)` draws real Liquid Glass on macOS 26 and a frosted fallback on 13 to 15.
  - `.glassGroup(spacing:)` wraps related glass shapes in a `GlassEffectContainer` on macOS 26.
  - `Card { }`, `Notice`, `NavyButtonStyle` (`.navy`, `.navySecondary`, `.navyDestructive`, `.navyCompact`) and `AuroraBackground` already use them.
- **Page structure:** pages use `Page { PageHeader(...) … Card { … } }`, and settings rows use `SettingRow`.
- **New sidebar pages:** add a case to `AppSection` (title and SF Symbol), then a branch in `ContentView.detail`.
- **New services:** add the service to `AppModel` and inject it in `agamemnonEnvironment`.
- **Copy:** user-facing text is plain, friendly English, written for non-technical users.

## Security and safety rules

This is security software. A bug can delete user files or let malware through. Follow these rules.

1. **Never delete user files directly.** Threats are *moved* to the quarantine vault (`QuarantineVault.quarantine`). Only the user deletes them for good.
2. **Suspicious ≠ malicious.** Gatekeeper findings (unsigned or un-notarized) and ClamAV `PUA.*` hits are `.suspicious`. They are never auto-quarantined unless the user turns on that setting.
3. **Keep the archive safety limits** in `ArchiveInspector`: list before extracting, a 4 GB expanded-size cap, 100,000 entries, 3 levels of nesting, timeouts, read-only `-nobrowse` disk image mounts, skipping encrypted images and archives instead of prompting, and always cleaning up scratch folders and detaching images. Don't loosen these without a clear reason in the PR.
4. **Never execute, open or `Process`-launch a file being scanned.** Only read it, hash it, or hand it to the unpack and assessment tools.
5. **Admin rights** go only through `Privileged.run`, only for quarantine or restore in protected locations and for removing the DNS profile. Shell-quote every path with `Shell.quote`.
6. **Privacy:**
   - No telemetry, analytics, crash reporters or file uploads.
   - The only network calls are the MalwareBazaar exports, ClamAV's `freshclam`, and the GitHub avatars on the About page. Don't add more without discussing it.
7. **Signature data:**
   - The MalwareBazaar exports at `https://bazaar.abuse.ch/export/txt/sha256/{full,recent}/` are CC0 and work without an auth key. The newer `mb-api.abuse.ch/v2` exports need a key, so don't switch to them silently.
   - Keep the binary format: sorted 32-byte records. Loading it and doing lookups depend on that format.
8. **Don't overstate protection** in the UI or docs. Known limits are listed in HOW_IT_WORKS.md: hash matching only catches known samples, download protection acts just after the download finishes rather than blocking it, encrypted DNS needs the user's approval, and admin alerts need an admin account.
9. **Never add or commit real malware samples.** For testing, use the EICAR test file (`Eicar.signature`).

## Testing changes

There's no automated test target yet. Before handing work back:

- **Detection:** scan a folder containing an EICAR file and a ZIP/DMG holding one. The scan should report it, with an inner path like `outer ▸ inner`.
- **Download protection:** use **Run Test** on the Real-Time Protection page. The file should be quarantined within a few seconds.
- **Quarantine:** quarantine, restore (check the file's permissions come back), delete.
- **UI:** check on macOS 26 (glass) and, if you can, on macOS 13 to 15 (fallback).
- If you couldn't run something, say exactly what wasn't verified.

## Git and pull requests

- **Don't commit, push, tag or create releases unless a maintainer explicitly asks.** The maintainers review and commit changes themselves with GitHub Desktop. Leave changes as uncommitted edits, or hand back files.
- Never rewrite history or force-push `main`. CI manages the `nightly` tag.
- Keep changes focused. Explain user-visible changes in plain language.
- New source files are GPLv2 like the rest of the project. Don't paste in code under licenses that aren't compatible with GPLv2.

## Keeping these files in sync

`AGENTS.md` is the only source of rules. `CLAUDE.md` and `GEMINI.md` contain just `@AGENTS.md`, so they load this file. Edit rules here.
