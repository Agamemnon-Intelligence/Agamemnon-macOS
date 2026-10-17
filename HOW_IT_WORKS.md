# How Agamemnon works

This document explains what Agamemnon does under the hood: how it finds malware, what happens to a threat, how real-time protection and encrypted DNS work, and where its limits are. For installing and building, see the [README](README.md).

## Contents

1. [The big picture](#the-big-picture)
2. [Detection engines](#detection-engines)
3. [Scans](#scans)
4. [Looking inside archives, installers and disk images](#looking-inside-archives-installers-and-disk-images)
5. [The quarantine vault](#the-quarantine-vault)
6. [Real-time protection](#real-time-protection)
   - [Behaviour protection](#behaviour-protection)
   - [Ransomware shield](#ransomware-shield)
   - [Browser protection](#browser-protection)
   - [Startup items check](#startup-items-check)
7. [Security Checkup](#security-checkup)
8. [Encrypted DNS](#encrypted-dns)
9. [Scheduled scans and running in the background](#scheduled-scans-and-running-in-the-background)
10. [Where Agamemnon keeps its data](#where-agamemnon-keeps-its-data)
11. [Permissions and privacy](#permissions-and-privacy)
12. [Limits](#limits)
13. [Code map](#code-map)

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
  New program  ►│  BehaviorMonitor (libproc, 1 s) ──► BehaviorRules + hashes    │
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

Agamemnon has five ways of deciding a file is dangerous: its hash list, Gatekeeper, ClamAV, its own pattern rules, and where the file came from (URLhaus). A file only needs to fail one of them.

### 1. Known-malware hashes (Agamemnon's own engine)

Every file gets a **SHA-256 fingerprint**. Changing even one byte of a file changes its fingerprint completely, so a match means the file is *exactly* a known malware sample.

The fingerprints come from **[MalwareBazaar](https://bazaar.abuse.ch)** by abuse.ch, a free, community-run collection of confirmed malware samples. Its hash list is published under CC0.

- **First launch:** Agamemnon downloads the full list. That's a zip of about 45 MB, holding more than 1.1 million hashes.
- **About every 12 hours:** it downloads the hashes added in the last 48 hours and merges them in.
- **Once a week:** it downloads the full list again, so nothing is missed.

The hashes are stored in a compact binary file: each hash is 32 raw bytes, sorted. That's about 37 MB on disk and in memory. Because the list is sorted, checking a file is a [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) of about 20 comparisons, however big the list gets.

Large files are read in 1 MB chunks, so even a 1 GB file is hashed without loading it all into memory. Files bigger than 1 GB aren't hashed, because malware samples are almost never that large.

**The EICAR test file.** Every antivirus recognises EICAR, a harmless 68-byte text file made for testing. Agamemnon recognises it by its fingerprint and its contents, and reports it as a *Test file*. The **Run Test** button on the Real-Time Protection page saves one into your Downloads folder, so you can watch download protection catch it.

### 1b. VirusShare (extra known-malware hashes)

[VirusShare](https://virusshare.com/hashes) publishes the MD5 fingerprints of every malware sample in its collection as free numbered lists (500 lists, about 42 million hashes; mostly Windows malware, with Mac malware among them).

- **Download:** in the background, list by list (`VirusShare_00000.md5` …), politely spaced, about 1.4 GB in total the first time. It resumes where it stopped after a restart. After that, Agamemnon looks for new lists once a week. Turn it off in Settings.
- **Storage:** 256 sorted files in `Signatures/VirusShare/` (one per first byte of the hash, 16 bytes per hash, about 680 MB). New lists go into `.new` files and are sorted in every 50 lists, so protection grows during the first download.
- **Lookup:** the MD5 is worked out in the same pass as the SHA-256, so files are only read once. The right bucket file is memory-mapped and binary-searched; the full list is never loaded into memory.
- **What it judges:** VirusShare's lists also contain harmless files that happened to sit inside malware archives (fonts, the standard `Credits.rtf`, Python's Windows launcher stubs `cli-64.exe`/`w32.exe`, tiny packaging files). A test on a normal Mac found 14 of these (including a Ruby library file). So VirusShare is only used for **Mac programs** (Mach-O binaries) and **installers and archives** (DMG, PKG, ZIP…), and never for files under 64 bytes or the empty-file hash. Scripts are left to the pattern rules, MalwareBazaar and ClamAV.
- **Results:** an unsigned program on the list is **malware**. A match on something signed by Apple or a Developer ID, or on an installer or archive, is only **suspicious**, so it's reported but never moved automatically.

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

**Agamemnon's own builds.** Nightly builds without a Developer ID are ad-hoc signed, so Gatekeeper rejects them. Agamemnon doesn't warn about a copy of itself, but the bundle ID alone isn't trusted, because malware can copy it. The app must have Agamemnon's bundle ID and a valid signature, **and** one of these must hold:

- it's exactly the build that's running (same code-directory hash),
- it's signed by the same Developer ID team as the running build, or
- macOS's "Where from" record shows it was downloaded from `github.com/Agamemnon-Intelligence/Agamemnon-macOS/` or `athenesoftworks.com`.

Only the Gatekeeper warning is skipped. Hash and ClamAV checks still run on it.

A suspicious item isn't necessarily malware: plenty of small open-source apps aren't notarized. That's why suspicious items are only flagged, unless you turn on **Quarantine apps Apple hasn't verified**.

### 3. ClamAV (second opinion)

[ClamAV](https://www.clamav.net) is a free, open-source antivirus engine by Cisco Talos. Its signatures go far beyond exact hashes: patterns inside documents, scripts, email attachments and more. Agamemnon doesn't bundle ClamAV. Instead, about 45 seconds after the first launch, it **installs it for you, once**:

- **With Homebrew:** it runs `brew install clamav` as you. No password needed.
- **Without Homebrew:** it finds the newest `*.macos.universal.pkg` on [ClamAV's GitHub releases](https://github.com/Cisco-Talos/clamav/releases), downloads it, and checks with `pkgutil --check-signature` that it's signed with Cisco's Apple Developer ID (team `DE8Y96K9QP`). Anything else is thrown away. Then macOS asks for your password once and `installer` puts ClamAV in `/usr/local/clamav`.

If you cancel, **Install ClamAV** stays in Settings. You can also install it yourself:

```sh
brew install clamav
```

then Agamemnon:

1. Keeps **its own** ClamAV signature folder up to date by running `freshclam` with a one-line config file. You don't have to edit Homebrew's config, and the signatures don't need administrator rights. The first download is about 300 MB.
2. Runs `clamscan` over the same paths **after** its own engine has finished, and adds anything it finds to the results.

ClamAV results are labelled by type: `PUA.*` (potentially unwanted apps) count as **Suspicious**, `Eicar` as a **Test file**, and everything else as **Malware**.

---

### 4. Pattern rules (Agamemnon's own engine)

Hashes only catch files someone has already reported. Pattern rules recognise a malware *family* by what its code contains, so a fresh build with a brand-new hash is still caught. They live in `PatternRules.swift`.

A rule only looks at:

- **scripts** (shell, `.command`, AppleScript, Python, JavaScript, Ruby, Perl, or anything starting with `#!`), up to 4 MB, and
- **programs (Mach-O) that nobody has signed, or that are only ad-hoc signed**, up to 48 MB. Apple-signed and Developer ID-signed programs are skipped. A match there is much more likely to be a security tool, and Apple can revoke a real attacker's certificate.

Each rule needs several strings together, never one word. For example, the password-phishing rule needs `display dialog` **and** `hidden answer` **and** two of the things stealers go after (browser logins, cookies, the keychain, Notes, wallets, `dscl -authonly`). Matching ignores upper and lower case.

| Rule | What it recognises | Families | Result |
| --- | --- | --- | --- |
| `MacOS.Stealer.PasswordPhish` | A fake password dialog plus stealer targets | AMOS, Banshee, Cuckoo, FrigidStealer | Malware |
| `MacOS.Stealer.BrowserData` | Three or more browsers' data folders, their login/cookie files, and a way to send them off | AMOS, Poseidon, Cthulhu | Malware |
| `MacOS.Stealer.CryptoWallets` | Three or more crypto wallets or wallet extensions, and a way to send them off | AMOS, Banshee, Cuckoo, BeaverTail | Malware |
| `MacOS.Stealer.SandboxEvasion` | Checking for QEMU/VMware/VirtualBox, plus stealer behaviour | AMOS, Banshee | Malware |
| `MacOS.Stealer.KeychainDump` | `security dump-keychain` plus a network upload | KeySteal | Malware |
| `MacOS.Stealer.Upload` | Uploading files from a temp folder with stolen-data names | AMOS, FrigidStealer | Malware |
| `MacOS.Stealer.BeaverTail` | JavaScript reading two or more wallet extensions and its upload paths | BeaverTail | Malware |
| `MacOS.Backdoor.SysJoker` | Its install folder and file name together | SysJoker | Malware |
| `MacOS.Backdoor.ReverseShell` | A script handing a shell to `/dev/tcp/` | Backdoors | Malware |
| `MacOS.Spyware.PrivacyTamper` | Writing new rows into the privacy database (TCC.db) | Spyware | Malware |
| `MacOS.CoinMiner` | A mining-pool address plus miner settings | CoinMiner | Malware |
| `MacOS.Dropper.Shlayer` | `openssl enc -base64 -d` into a temp folder, then running it | Shlayer | Malware |
| `MacOS.Stealer.BrowserKey` | Asking the keychain for a browser's "Safe Storage" key plus a network call | KeySteal, AMOS | Suspicious |
| `MacOS.Dropper.GatekeeperBypass` | A script that downloads into a temp folder, removes the quarantine flag and makes it runnable | Droppers, ClickFix | Suspicious |
| `MacOS.Downloader.HiddenScript` | Decoding base64 and piping it into a shell | ClickFix, Bundlore | Suspicious |
| `MacOS.Persistence.FakeAppleAgent` | A script writing a `com.apple.` LaunchAgent that runs from a temp or hidden folder | Backdoors | Suspicious |

Pattern rules run in every scan (after the hash check), in download protection, in the startup items check, on browser extensions, and in behaviour protection (on each new unsigned program, and on the script file an interpreter such as `bash`, `python` or `osascript` is started with).

To keep false alarms away, pattern rules skip:

- files inside an app signed by Apple or a Developer ID (VS Code's bundled scripts, for example). The app's signature seals them, so macOS won't run the app if they're changed;
- anything installed by a package manager (Homebrew, pyenv, nvm…);
- Agamemnon's own program, in every version, because it contains the rules' strings. A copy of malware that pretends to be Agamemnon is still checked by hash, ClamAV and behaviour protection;
- for the warning-level ("Suspicious") rules, scripts bigger than 256 KB. Droppers are tiny, and large bundles mention everything somewhere.

### 5. URLhaus (malware sites)

[URLhaus](https://urlhaus.abuse.ch) by abuse.ch is a public list of links that are spreading malware right now. Agamemnon downloads the "online" list (about 25,000 links, CC0, no key) every 6 hours and keeps it in `Signatures/urlhaus-online.txt`.

- **Downloads:** browsers record where a file came from (`com.apple.metadata:kMDItemWhereFroms`). If that exact link is listed, or it came from a bare IP address that serves listed links, the download is **malware** and goes to quarantine. If it came from a site that's only *partly* listed, it's **suspicious**. Big shared sites (GitHub, Google Drive, Dropbox, Discord and others) are never judged by one bad link.
- **Behaviour protection:** `curl` or `wget` fetching a listed link is stopped.

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

### Behaviour protection

Malware families change their files constantly, so a new build of AMOS has a hash nobody has seen yet. What they *do* once they run changes much less. Behaviour protection watches programs as they start and looks for those actions.

About once a second, Agamemnon lists running processes with `proc_listallpids` and reads each **new** one's path, parent and command line (`proc_pidinfo`, `KERN_PROCARGS2`). It launches no tools to do this. Each new program outside macOS's own folders is also checked against the malware hash list.

| What it recognises | How | Seen in | Confidence |
| --- | --- | --- | --- |
| Fake password prompt | `osascript` showing a `display dialog` with `hidden answer` | AMOS, FrigidStealer, Banshee | High |
| Collecting browser data with a script | `osascript` reading browser cookies or saved logins, Apple Notes or the keychain file | AMOS, FrigidStealer, Banshee | High |
| Backdoor posing as a macOS update | Running from `~/Library/MacOsServices/` or named `updateMacOs` | SysJoker | High if unsigned |
| Checking the stolen password | `dscl … -authonly`, started by an unsigned program | AMOS, Banshee | High (medium otherwise) |
| Browser password theft | `security find-generic-password … Safe Storage`, or `security dump-keychain` | KeySteal, AMOS | High |
| Uploading stolen files | `curl`/`wget` uploading a file from a temp folder to a bare IP address | AMOS, FrigidStealer | High |
| Cryptocurrency mining | `stratum+tcp://` / `stratum+ssl://` arguments, or known miner names | CoinMiner | High |
| Fake job-interview malware | Running from `~/.n2`, `~/.n3`, `~/.pyp` or `~/.npl` | BeaverTail, InvisibleFerret | High |
| Known malware file | The program's SHA-256 is on the MalwareBazaar list | Any | High |
| Running a script straight from the internet | A shell running `curl … \| sh`, `$(curl …)` or `base64 -d \| sh` (official installers such as Homebrew and rustup are allowed) | AMOS "ClickFix", Shlayer, Bundlore | Medium |
| Unsigned program in an odd place | An unsigned or ad-hoc program running from `/tmp`, `/Users/Shared` or a hidden folder in `~/Library` | SysJoker, Shlayer, Bundlore | Medium |
| Hidden miner | An unsigned program keeping a CPU core over 85 % busy for 10 minutes | CoinMiner | Medium |
| Downloading from a known malware site | `curl`/`wget` fetching a link on the URLhaus list | Droppers, ClickFix | High |
| Copying crypto wallets or browser data | AppleScript naming two or more wallets / Telegram / keychain, or `cp`/`ditto`/`rsync`/`sqlite3` doing it when started by AppleScript or an unsigned program | AMOS, Banshee, Cuckoo, Poseidon | High |
| Checking for a virtual machine | `system_profiler` output searched for QEMU/VMware/VirtualBox/Parallels | AMOS, Banshee, Cuckoo | High from AppleScript or an unsigned program, otherwise medium |
| Secret screenshots | `screencapture -x` (no shutter sound) started by an unsigned program | Cuckoo, Poseidon, Banshee | High |
| Packing up stolen files | `ditto -c -k` from one temp folder to another, started by AppleScript or an unsigned program | AMOS, Banshee, Cthulhu | High |
| Switching off the download check | `xattr` removing `com.apple.quarantine` when started by an unsigned program, or on temp-folder files from AppleScript | Droppers, Shlayer, ClickFix | High (medium for a temp-folder file otherwise) |
| Turning off Gatekeeper | `spctl --master-disable` / `--global-disable` | Shlayer, Bundlore | High from an unsigned program, otherwise medium |
| Granting itself privacy permissions | `sqlite3` writing to `TCC.db` | Spyware, backdoors | High |
| Remote control connection | A shell using `/dev/tcp/` with `-i` | Backdoors | High |
| Hiding the Terminal window | AppleScript hiding or minimising Terminal | ClickFix, Cuckoo | Medium |
| Malware recognised by its code | The new program, or the script an interpreter runs, matches a malicious pattern rule | Any covered family | High; a matching script is quarantined |

**What happens next.** Medium findings are only reported: a notification, an entry in Recent Activity, and an alert on the Real-Time Protection page with **Stop**, **Quarantine** and **Trust** buttons. High findings are acted on automatically when **Stop dangerous programs automatically** is on (the default):

1. The process doing it is stopped.
2. Agamemnon walks up the parent chain to the nearest **unsigned or ad-hoc** program installed by the user. That's the program held responsible. It's stopped too, and moved to quarantine (the whole `.app` if it's inside one).

**Guardrails.** These keep behaviour protection from turning on the user:

- Programs that are part of macOS, signed by Apple, or signed with a Developer ID are **never** stopped or quarantined automatically. The one exception is the single running instance of a system tool (`osascript`, `curl`, `security`, `dscl`…) caught doing the malicious thing itself. Stopping that instance is harmless.
- Interpreters and shells (`python`, `node`, `bash`…), and anything installed by a package or version manager (Homebrew, MacPorts, nvm, pyenv, cargo…), are never quarantined.
- Agamemnon never touches itself, other users' processes or root processes.
- Nothing is deleted. Quarantined programs can be restored from the Quarantine page.
- **Trust** stops all alerts about a program. Trusted programs are listed on the Real-Time Protection page and can be removed there.

### Ransomware shield

Watches **Documents, Desktop and Pictures** (plus any folders you add) with FSEvents. When **25 or more files change within 15 seconds**, it takes a closer look:

- **Do the files still match their type?** Up to 40 changed files are sampled and their first bytes checked: a `.jpg` must start like a JPEG, a `.pdf` with `%PDF`, Office files like a ZIP, text files must be mostly printable, and so on. If **60 %** or more of at least 8 checked files fail, they've most likely been encrypted.
- **Were they renamed?** Ten or more files getting the same unknown extension after a known one (`photo.jpg.locked`).
- **Ransom notes** (`HOW_TO_DECRYPT`, `_readme.txt`…) appearing while files are being scrambled.

Then it finds the program doing it: it compares every user program's disk-write counter one second apart (`proc_pid_rusage`) and checks which ones have files open in the protected folders (`proc_pidinfo`). Apple-signed programs (Finder, Photos, iCloud) are never blamed. If the top writer is **unsigned or ad-hoc** and "Stop dangerous programs automatically" is on, it's stopped and quarantined. A signed program is only named in the alert.

Normal work doesn't trigger it: copying, exporting or syncing files leaves them valid, so the type check passes. The shield acts within a few seconds, so some files may already be damaged; a Time Machine backup gets those back (the Security Checkup reminds you).

### Browser protection

Looks for adware (Adload, Bundlore, Pirrit, Shlayer's payloads) in every browser profile. It checks when Agamemnon starts, whenever an extension folder or a managed-preferences file changes, and every 30 minutes.

- **Chrome, Brave, Edge, Vivaldi, Arc, Opera, Chromium:** reads each extension's `manifest.json`.
  - An extension that changes the **search engine** to anything other than a well-known one (Google, Bing, DuckDuckGo, Ecosia…) is flagged.
  - An extension that **didn't come from the official store** (no store `update_url`) and can read every website, use `webRequest`/`proxy`/`nativeMessaging`, or change the home page is flagged.
  - Every file under 8 MB in an extension is hash-checked, and its JavaScript goes through the pattern rules. A match there is **malware** and is quarantined automatically.
- **Forced installs:** JSON files in Chrome's `External Extensions` folders make Chrome install an extension. Ones pointing at the official store are fine (some apps add their own extension this way); ones pointing at a local file are flagged.
- **Configuration profiles:** browser policies under `/Library/Managed Preferences` (forced extensions, search engine, home page, proxy) for Chrome, Brave, Edge and Safari, and Firefox's `policies.json`. Skipped on Macs enrolled in a company's device management (`profiles status -type enrollment`), where these are expected.
- **Safari:** lists Safari extensions with `pluginkit` and flags ones inside an unsigned app, or an app hidden outside the Applications folders.

Apart from malware matches, nothing is removed automatically. **Remove** moves the extension (or file) to quarantine; for a profile it opens System Settings › Device Management. **Trust** hides it for good.

### Startup items check

`BackgroundItemWatcher` only sees *new* startup items. The startup items check looks at **everything already there**: `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` and your `crontab`. It runs 20 seconds after launch, every 6 hours, and on **Check Now**. For each item it checks the program it runs, or the script when the program is an interpreter:

| Finding | Result |
| --- | --- |
| The program is on the malware hash list | Malware |
| It matches a pattern rule | That rule's result |
| It calls itself `com.apple.…` but isn't signed by Apple | Malware if unsigned, otherwise suspicious |
| It downloads or decodes code and runs it every time (`curl … \| sh`, `base64 -d`, `/dev/tcp/`) | Suspicious |
| An unsigned program in a temp folder or a hidden folder in your home | Suspicious |

Malware is stopped and moved to quarantine with its startup item when "Quarantine threats automatically" is on. Suspicious items wait for you (**Quarantine** or **Trust**).

---

## Security Checkup

A page that checks the macOS settings that matter most, each with a **Fix…** button to the right System Settings page. Agamemnon only reads them and never changes them.

| Check | How |
| --- | --- |
| macOS still supported | The version number: Apple fully patches the newest three releases |
| Automatic security updates | `CriticalUpdateInstall` and `ConfigDataInstall` (XProtect) in `com.apple.SoftwareUpdate` |
| FileVault | `fdesetup status` |
| Firewall | `socketfilterfw --getglobalstate` |
| Gatekeeper | `spctl --status` |
| System Integrity Protection | `csrutil status` |
| Password at login | No `autoLoginUser` in `com.apple.loginwindow` |
| Remote Login (SSH) | Whether `com.openssh.sshd` is loaded |
| Time Machine | `tmutil destinationinfo` |

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
- **Network use:** downloading the MalwareBazaar hash list, VirusShare's MD5 lists, the URLhaus malware-link list, ClamAV itself (once, from Homebrew or ClamAV's GitHub releases) and its signatures, and creators' profile pictures on the About page. Nothing else.
- **Not sandboxed.** An antivirus has to read the whole disk and run system tools, which Apple's App Sandbox doesn't allow. The app runs with **Hardened Runtime**.
- **Full Disk Access** is optional but recommended for full scans. Agamemnon only reads files with it, and never changes them, except to quarantine a threat.
- **Administrator password:** only asked for when quarantining or restoring something in a protected location, or when turning encrypted DNS off. Never for scanning.

---

## Limits

No antivirus catches everything. Agamemnon is honest about what it can and can't do:

- **Hash matching only catches known files.** Brand-new or slightly altered malware has a fingerprint nobody has seen yet. Pattern rules and ClamAV catch many new builds of known families, but heavily obfuscated or completely new malware can get past all of them. Keep macOS up to date: it has its own protection, XProtect.
- **Pattern rules skip signed programs.** A family that ships Developer ID-signed builds is only caught by hash, ClamAV or behaviour until Apple revokes the certificate.
- **The ransomware shield reacts, it doesn't prevent.** It needs a burst of damaged files to recognise an attack, and it can only stop programs that aren't signed. Keep a backup.
- **Browser protection is a review list, not a blocklist.** Apart from extensions containing malware, it flags and you decide.
- **Behaviour protection reacts just after a program starts, not before.** It checks new processes about once a second, so a program that starts and finishes within a second can be missed, and it can't see which files a program opens. Blocking programs before they run, and watching file access, both need Apple's Endpoint Security entitlement.
- **Download protection reacts after the download finishes.** It usually acts within about 2 seconds. Truly blocking a file *before* any app can open it needs Apple's Endpoint Security entitlement, which this version doesn't have.
- **Encrypted DNS needs your approval** in System Settings. A VPN's own DNS settings override it while the VPN is connected.
- **Admin alerts need an admin account** and depend on macOS's log messages. Apple can change those messages between versions.
- **Password-protected and very large archives** can't be looked inside. They're listed after the scan so you know.
- **Files that are only in iCloud Drive or another cloud drive** (not downloaded to this Mac) are skipped. Reading them would make macOS download them, so Agamemnon checks them once they're on the Mac.

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
│   ├── CodeIdentity.swift      Who signed a program; recognising Agamemnon's own builds
│   ├── ProcessList.swift       Running processes via libproc / sysctl
│   ├── BehaviorRules.swift     What stealers, backdoors and miners do
│   ├── PatternRules.swift      Malware families recognised by their code
│   ├── URLhaus.swift           Live malware-link list, where downloads came from
│   ├── VirusShare.swift        VirusShare MD5 lists: download, bucketed storage, lookup
│   ├── ClamAV.swift            Installs ClamAV, runs freshclam and clamscan
│   └── Models.swift            Detection, ScanKind, ScanSummary…
├── Services/
│   ├── AppModel.swift          Owns every service, works out overall status
│   ├── ScanController.swift    Starts/stops scans, auto-quarantine, summaries
│   ├── SignatureManager.swift  Downloads MalwareBazaar hashes and the URLhaus list
│   ├── QuarantineVault.swift   Quarantine, restore, delete
│   ├── DownloadGuard.swift     Download protection
│   ├── SystemWatchers.swift    Admin access alerts + background item alerts
│   ├── BehaviorMonitor.swift   Behaviour protection and its guardrails
│   ├── RansomwareShield.swift  Encryption-burst detection in protected folders
│   ├── BrowserGuard.swift      Adware extensions, search hijacks, browser policies
│   ├── StartupSweep.swift      Checks every existing startup item
│   ├── SecurityCheckup.swift   FileVault, firewall, Gatekeeper, updates…
│   ├── DNSManager.swift        Providers, profile generation, status
│   ├── ScanScheduler.swift     Scheduled scans + open at login
│   └── ActivityLog.swift       Recent activity + notifications
├── Support/                    Process runner, FSEvents wrapper, paths, prefs,
│                               admin prompt helper
└── Views/                      SwiftUI pages, midnight theme; Liquid Glass on the
                                sidebar and buttons, solid panels for content
```

The build is described in `project.yml` (XcodeGen) and `.github/workflows/build.yml`, which builds a universal app and packs it into a DMG.

---

Agamemnon is free software under the [GNU GPL v2](LICENSE). Created by [mirazbakis](https://github.com/mirazbakis) and [mertyesileducation](https://github.com/mertyesileducation).
