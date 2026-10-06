# How Agamemnon works

This document explains what Agamemnon does under the hood: how it finds malware, what happens to a threat, how real-time protection and encrypted DNS work, and where its limits are. For installing and building, see the [README](README.md).

## Contents

1. [The big picture](#the-big-picture)
2. [Detection engines](#detection-engines)
3. [Scans](#scans)
4. [Looking inside archives, installers and disk images](#looking-inside-archives-installers-and-disk-images)
5. [The quarantine vault](#the-quarantine-vault)
6. [Real-time protection](#real-time-protection)
7. [Encrypted DNS](#encrypted-dns)
8. [Scheduled scans and running in the background](#scheduled-scans-and-running-in-the-background)
9. [Where Agamemnon keeps its data](#where-agamemnon-keeps-its-data)
10. [Permissions and privacy](#permissions-and-privacy)
11. [Limits](#limits)
12. [Code map](#code-map)

---

## The big picture

Agamemnon is a native SwiftUI app. It lives in the menu bar, so its protection keeps running after you close the main window.

```
                ┌──────────────────────── Agamemnon.app ────────────────────────┐
                │                                                               │
  You ────────► │  Scan page / menu bar / schedule ──► ScanController           │
                │                                          │                    │
  New download ►│  DownloadGuard (FSEvents) ───────────────┤                    │
                │                                          ▼                    │
  New startup  ►│  BackgroundItemWatcher (FSEvents) ──► ScanEngine              │
  item          │                                          │                    │
                │        ┌─────────────────────────────────┼──────────────┐     │
                │        ▼                 ▼               ▼              ▼     │
                │  Hash database     ArchiveInspector   Gatekeeper     ClamAV   │
                │  (MalwareBazaar)   (bsdtar, hdiutil,  (spctl)      (optional) │
                │                     pkgutil)                                  │
                │                          │                                    │
                │                          ▼                                    │
                │                  QuarantineVault ──► notifications, activity  │
                │                                                               │
  Admin prompt ►│  AdminWatcher (system log)  ──► warning                       │
                │  DNSManager ──► configuration profile ──► System Settings     │
                └───────────────────────────────────────────────────────────────┘
```

Every scan, whether you start it, the schedule starts it, or a new download triggers it, goes through the same `ScanEngine`. The only differences are which files it's given and which options are on.

---

## Detection engines

Agamemnon has three ways of deciding a file is dangerous. A file only needs to fail one of them.

### 1. Known-malware hashes (Agamemnon's own engine)

Every file gets a **SHA-256 fingerprint**. Changing even one byte of a file changes its fingerprint completely, so a match means the file is *exactly* a known malware sample.

The fingerprints come from **[MalwareBazaar](https://bazaar.abuse.ch)** by abuse.ch, a free, community-run collection of confirmed malware samples. Its hash list is published under CC0.

- **First launch:** Agamemnon downloads the full list. That's a zip of about 45 MB, holding more than 1.1 million hashes.
- **About every 12 hours:** it downloads the hashes added in the last 48 hours and merges them in.
- **Once a week:** it downloads the full list again, so nothing is missed.

The hashes are stored in a compact binary file: each hash is 32 raw bytes, sorted. That's about 37 MB on disk and in memory. Because the list is sorted, checking a file is a [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) of about 20 comparisons, however big the list gets.

Large files are read in 1 MB chunks, so even a 1 GB file is hashed without loading it all into memory. Files bigger than 1 GB aren't hashed, because malware samples are almost never that large.

**The EICAR test file.** Every antivirus recognises EICAR, a harmless 68-byte text file made for testing. Agamemnon recognises it by its fingerprint and its contents, and reports it as a *Test file*. The **Run Test** button on the Real-Time Protection page saves one into your Downloads folder, so you can watch download protection catch it.

### 2. Gatekeeper (Apple's own check)

When a download contains an **app** (`.app`) or an **installer** (`.pkg`), Agamemnon asks macOS whether Gatekeeper would let it run:

```
spctl --assess --type execute  Some.app
spctl --assess --type install  Some.pkg
```

| Gatekeeper says | Agamemnon reports |
| --- | --- |
| Accepted (signed and notarized) | Nothing, it's fine |
| No signature | **Suspicious:** "Unsigned app" |
| Signed but not notarized | **Suspicious:** "Not notarized by Apple" |
| Developer certificate revoked | **Malware:** Apple revokes certificates it has caught being used for malware |

A suspicious item isn't necessarily malware: plenty of small open-source apps aren't notarized. That's why suspicious items are only flagged, unless you turn on **Quarantine apps Apple hasn't verified**.

### 3. ClamAV (optional second opinion)

[ClamAV](https://www.clamav.net) is a free, open-source antivirus engine by Cisco Talos. Its signatures go far beyond exact hashes: patterns inside documents, scripts, email attachments and more. Agamemnon doesn't bundle ClamAV, but if you install it:

```sh
brew install clamav
```

then Agamemnon:

1. Keeps **its own** ClamAV signature folder up to date by running `freshclam` with a one-line config file. You don't have to edit Homebrew's config, and the signatures don't need administrator rights. The first download is about 300 MB.
2. Runs `clamscan` over the same paths **after** its own engine has finished, and adds anything it finds to the results.

ClamAV results are labelled by type: `PUA.*` (potentially unwanted apps) count as **Suspicious**, `Eicar` as a **Test file**, and everything else as **Malware**.

---

## Scans

| Scan | What it checks |
| --- | --- |
| **Quick Scan** | Downloads, Desktop, /Applications, ~/Applications, the startup folders (`LaunchAgents`, `LaunchDaemons`, `StartupItems`, `PrivilegedHelperTools`), /Users/Shared and /tmp. These are the places Mac malware usually lands or starts from. |
| **Full Scan** | Your whole startup disk. It skips the sealed, read-only system volume (`/System`), devices, virtual-memory files and other drives (`/Volumes`). |
| **Custom Scan** | Whatever you drop onto the page or choose. Files, folders, apps, archives and disk images all work. |

During a scan, Agamemnon:

1. Walks every folder, including inside app bundles. It skips symbolic links, so it can't loop forever or wander off the disk.
2. Skips your **exclusions** and its own folders, such as the quarantine vault.
3. For each file: checks for EICAR, hashes it and looks the hash up, then opens it if it's an archive, installer or disk image (see below).
4. Runs ClamAV, if it's installed and turned on.
5. Moves malware to quarantine, if **Quarantine threats automatically** is on (the default). **Suspicious items always wait for you.**
6. Saves a summary, adds it to Recent Activity and sends a notification if anything was found.

You can stop a scan at any time, and that also stops ClamAV. Some protected folders, like Mail and Messages, can only be scanned if you give Agamemnon **Full Disk Access**. The app tells you when it doesn't have it.

---

## Looking inside archives, installers and disk images

Malware is often delivered inside a ZIP, a disk image or an installer, so Agamemnon opens these and scans what's inside **before you do**. It only uses tools that ship with macOS:

| Type | Tool | How |
| --- | --- | --- |
| ZIP, RAR, 7Z, TAR (`.gz`/`.bz2`/`.xz`), ISO, XAR, CAB, CPIO, JAR, IPA, APK, DEB, RPM… | `bsdtar` (libarchive) | Lists the contents, then unpacks them into a private temporary folder |
| DMG, sparse images | `hdiutil` | Mounts the image **read-only**, hidden from Finder, without opening anything |
| PKG, MPKG | `pkgutil --expand-full` | Unpacks the installer, its scripts and the files it would install |

Archives are also recognised by their first few bytes, so a ZIP renamed to `.jpg` still gets opened.

**Safety rules:**

- **Zip bombs.** Before unpacking, Agamemnon reads the archive's table of contents. It refuses if the archive would unpack to more than **4 GB** or hold more than **100,000 files**.
- **Nesting.** Archives inside archives are followed **3 levels** deep.
- **No escaping.** `bsdtar` refuses absolute paths and `../` tricks by default, so nothing can be written outside the temporary folder.
- **No password prompts.** Encrypted disk images and password-protected archives are skipped and listed as *couldn't be opened*, instead of popping up a dialog.
- **Timeouts.** Every tool has a time limit, so a broken file can't hang a scan.
- **Clean-up.** Temporary folders are deleted and disk images are ejected as soon as they've been checked. Anything left over after a crash is removed the next time Agamemnon starts.

If something bad is found inside an archive, the **whole archive** goes to quarantine, and the result shows exactly where it was found, for example:

```
~/Downloads/Setup.dmg ▸ Installer.pkg ▸ Payload/usr/local/bin/helper
```

---

## The quarantine vault

Quarantined items are **moved** (not copied) into:

```
~/Library/Application Support/Agamemnon/Quarantine/<id>/<original name>
```

- The vault folder can only be opened by you (permissions `700`).
- Quarantined files lose their execute permission (they become read-only, `400`), so they can't be run from the vault.
- An index records each item's original location, its threat name, the engine that found it, its fingerprint, its size and its original permissions.

**Restore** puts the item back where it came from with its original permissions. If something with the same name is already there, the restored copy is renamed `name (restored 1)`. **Delete** removes it for good.

If a threat is somewhere your account can't write to, such as `/Library/LaunchDaemons`, macOS's standard password prompt appears. Agamemnon uses it **only** to move that one item, and its own admin-access monitor ignores the prompt.

---

## Real-time protection

These run in the background for as long as Agamemnon is open, including from the menu bar.

### Download protection

Agamemnon watches your **Downloads** folder, plus any folders you add, using **FSEvents**, the macOS service that reports file changes.

1. A change inside a watched folder is mapped to the item at the top level of that folder. For example, a file inside a newly unzipped folder maps to the folder.
2. Files that are still downloading are ignored: `.download`, `.crdownload`, `.part`, `.partial`, `.opdownload`, `.tmp` and hidden files.
3. When an item has had **no changes for 2 seconds**, the download is considered finished, and the item is scanned. Archives are opened and apps and installers get the Gatekeeper check. ClamAV is used only for archives and installers, because it takes a few seconds to start.
4. Then:
   - **Malware:** quarantined immediately, with an urgent notification.
   - **Suspicious** (unsigned or un-notarized app): a warning notification, or quarantine if you turned that on.
   - **Clean:** logged on the Real-Time Protection page.

Agamemnon remembers each item's size and modification time, so the same file isn't scanned twice.

### Administrator access alerts

When an app asks for your admin password, macOS's authorization service (`authd`) writes it to the system log. Agamemnon follows that log live:

```
log stream --style ndjson --predicate 'process == "authd" AND …'
```

It looks for requests that **can show a password prompt** and ask for powerful rights, such as installing software, installing a background helper, changing system settings, controlling other apps or editing keychains. Then it notifies you which app is asking, and later shows whether you **allowed** or **denied** it. Alerts for the same app and right are grouped for 30 seconds. This needs an administrator account, because macOS only lets admins read the live log.

### Background item alerts

Mac malware usually makes itself start automatically by dropping a `.plist` into one of these folders:

```
~/Library/LaunchAgents
/Library/LaunchAgents
/Library/LaunchDaemons
```

Agamemnon notes what's already there when it starts, then watches for new or changed files. When one appears, it reads the item's name and the program it launches, notifies you, and scans both the plist and the program. Known malware is quarantined.

---

## Encrypted DNS

Every time you visit a website, your Mac first looks up its address with **DNS**. Normally those lookups go unencrypted to your network or internet provider, who can read and log them. Encrypted DNS (**DNS-over-HTTPS**) sends them, encrypted, to a provider you choose.

| Provider | Malware-blocking option | Unfiltered option |
| --- | --- | --- |
| Cloudflare | `security.cloudflare-dns.com` (1.1.1.2) | `cloudflare-dns.com` (1.1.1.1) |
| Quad9 | `dns.quad9.net` (9.9.9.9) | `dns10.quad9.net` (9.9.9.10) |
| Mullvad | `base.dns.mullvad.net`: ads, trackers and malware | `dns.mullvad.net` |
| AdGuard | `dns.adguard-dns.com`: ads, trackers, malware and phishing | `unfiltered.adguard-dns.com` |

**How it's turned on.** macOS only allows system-wide DNS changes through a **configuration profile**, or through a Network Extension, which needs a special entitlement from Apple. Agamemnon:

1. Writes a small, readable `.mobileconfig` file containing your provider's address (`com.apple.dnsSettings.managed`, protocol `HTTPS`).
2. Opens it and takes you to **System Settings › General › Device Management**, where you double-click **Agamemnon Encrypted DNS** and click **Install**. macOS requires you to approve this step yourself.
3. Checks every few seconds (using `system_profiler`, which doesn't need admin rights) until it sees the profile installed, then shows **Encrypted DNS is on**.

Every Agamemnon profile uses the same identifier, so switching provider **replaces** the old profile instead of adding another one. **Turn Off** removes it (`profiles remove`, after your password). If that doesn't work, it opens System Settings so you can remove it there. While a VPN is connected, the VPN's own DNS settings take priority.

---

## Scheduled scans and running in the background

- **Schedule:** a Quick or Full scan, every day or on one day each week, at a time you pick. Agamemnon checks every 30 seconds whether a scheduled scan is due. If your Mac was asleep at that time, the scan runs as soon as it wakes. Changing the schedule never triggers a "missed" scan straight away.
- **Menu bar:** closing the window doesn't quit Agamemnon. The shield in the menu bar shows its status: ✓ protected, ! needs attention, half-filled while scanning, ✕ threats found. It also has Quick Scan and shortcuts to each page.
- **Open at login:** uses macOS's built-in login item support (`SMAppService`), so protection starts when you log in.

---

## Where Agamemnon keeps its data

| What | Where |
| --- | --- |
| Malware hash database | `~/Library/Application Support/Agamemnon/Signatures/` |
| Quarantine vault and index | `~/Library/Application Support/Agamemnon/Quarantine/` |
| ClamAV signatures | `~/Library/Application Support/Agamemnon/ClamAV/` |
| DNS profiles it created | `~/Library/Application Support/Agamemnon/Profiles/` |
| Recent activity (last 300 events) | `~/Library/Application Support/Agamemnon/activity.json` |
| Settings and schedule | macOS preferences (`com.mirazbakis.Agamemnon`) |
| Temporary unpacking space | Your user's temporary folder, under `Agamemnon/` (cleaned automatically) |

To remove Agamemnon completely: quit it, delete the app, delete `~/Library/Application Support/Agamemnon`, and remove the DNS profile in System Settings if you installed one.

---

## Permissions and privacy

- **No account, no telemetry, no uploads.** Your files never leave your Mac. Only fingerprints are compared, and only against a list stored on your Mac.
- **Network use:** downloading the MalwareBazaar hash list, ClamAV signatures (if installed), and creators' profile pictures on the About page. Nothing else.
- **Not sandboxed.** An antivirus has to read the whole disk and run system tools, which Apple's App Sandbox doesn't allow. The app runs with **Hardened Runtime**.
- **Full Disk Access** is optional but recommended for full scans. Agamemnon only reads files with it, and never changes them, except to quarantine a threat.
- **Administrator password:** only asked for when quarantining or restoring something in a protected location, or when turning encrypted DNS off. Never for scanning.

---

## Limits

No antivirus catches everything. Agamemnon is honest about what it can and can't do:

- **Hash matching only catches known files.** Brand-new or slightly altered malware has a fingerprint nobody has seen yet. Installing ClamAV adds pattern-based detection, but neither engine replaces keeping macOS up to date. macOS also has its own built-in protection, XProtect.
- **Download protection reacts after the download finishes.** It usually acts within about 2 seconds. Truly blocking a file *before* any app can open it needs Apple's Endpoint Security entitlement, which this version doesn't have.
- **Encrypted DNS needs your approval** in System Settings. A VPN's own DNS settings override it while the VPN is connected.
- **Admin alerts need an admin account** and depend on macOS's log messages. Apple can change those messages between versions.
- **Password-protected and very large archives** can't be looked inside. They're listed after the scan so you know.

---

## Code map

```
App/
├── AgamemnonApp.swift          App entry: main window + menu bar extra
├── Engine/
│   ├── Signatures.swift        Hash256, SHA-256 hashing, sorted hash store, EICAR
│   ├── ScanEngine.swift        Walks files, runs every check, gathers results
│   ├── ArchiveInspector.swift  bsdtar / hdiutil / pkgutil with safety limits
│   ├── Gatekeeper.swift        spctl assessment of apps and installers
│   ├── ClamAV.swift            Finds clamscan, runs freshclam and clamscan
│   └── Models.swift            Detection, ScanKind, ScanSummary…
├── Services/
│   ├── AppModel.swift          Owns every service, works out overall status
│   ├── ScanController.swift    Starts/stops scans, auto-quarantine, summaries
│   ├── SignatureManager.swift  Downloads and merges MalwareBazaar hashes
│   ├── QuarantineVault.swift   Quarantine, restore, delete
│   ├── DownloadGuard.swift     Download protection
│   ├── SystemWatchers.swift    Admin access alerts + background item alerts
│   ├── DNSManager.swift        Providers, profile generation, status
│   ├── ScanScheduler.swift     Scheduled scans + open at login
│   └── ActivityLog.swift       Recent activity + notifications
├── Support/                    Process runner, FSEvents wrapper, paths, prefs,
│                               admin prompt helper
└── Views/                      SwiftUI pages, midnight theme, Liquid Glass
```

The build is described in `project.yml` (XcodeGen) and `.github/workflows/build.yml`, which builds a universal app and packs it into a DMG.

---

Agamemnon is free software under the [GNU GPL v2](LICENSE). Created by [mirazbakis](https://github.com/mirazbakis) and [mertyesileducation](https://github.com/mertyesileducation).
