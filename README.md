# Rewind Launcher 0.0.8 — Binary analysis and functional map

Analysis date: 2026-10-21  
Target analyzed: `Rewind Launcher_0.0.8_x64-setup.exe` → `rewind-launcher-v2.exe`  
Analysis type: installer extraction, static PE analysis, Tauri resource extraction, string and web bundle analysis, and targeted disassembly with native reference correlation.

> This document describes behavior observed in the artifact. It does not contain Rewind source code and is not intended to redistribute its assets. Paths, endpoints, and names are retained solely as technical evidence.

---

## 1. Executive summary

The installer is a 32-bit NSIS package containing a 64-bit Tauri 2 application. The actual application is `rewind-launcher-v2.exe`, an 18,712,576-byte Rust/PE executable with no Authenticode signature, with the React frontend compressed inside the binary itself.

The architecture is:

```text
NSIS installer (32-bit)
  └─ rewind-launcher-v2.exe (64-bit, Rust + Tauri 2.11.5)
       ├─ compressed React frontend (Tauri assets)
       ├─ Rust backend with Tauri commands
       ├─ WebSocket to Rewind's private service
       ├─ HTTP to backend, R2, splash service, and Arc
       ├─ Fortnite build download/extraction
       └─ Fortnite launch with credentials and arguments
```

The application is not a simple Fortnite "wrapper." The binary:

- authenticates a session against Rewind's backend;
- maintains a WebSocket with hotfix, clan, friend, message, voice, poll, Mares, and update events;
- downloads full Fortnite builds, resumes downloads, extracts RAR/7Z/ZIP, and verifies files;
- downloads and runs an external anti-cheat (`Arc.exe`);
- launches Fortnite with account credentials, launcher token, render mode, FOV, and performance options;
- downloads and runs an updater (`RewindLauncherUpdate.exe`);
- implements WebRTC voice between participants, with signaling through Rewind.

Most social and authentication features depend on Rewind's private services. Exact parity is impossible without those services; the same user experience can be rebuilt with a custom backend and local functionality.

---

## 2. Artifacts and method

### 2.1 Original installer

| Field | Value |
|---|---|
| File | `Rewind Launcher_0.0.8_x64-setup.exe` |
| Size | 5,863,351 bytes |
| SHA-256 | `db655a15fc51d79869a444a4d2a6ffce3c850019582cf3f7b6888b64e6b54116` |
| Architecture | `IMAGE_FILE_MACHINE_I386` (32-bit) |
| Subsystem | GUI |
| PE timestamp | 2025-03-09 (per header) |
| ProductVersion | `0.0.8` |
| Authenticode signature | No |
| Overlay | 5,810,615 bytes (NSIS data) |

The installer extracts, among other files:

```text
$PLUGINSDIR\modern-wizard.bmp
$PLUGINSDIR\nsDialogs.dll
$PLUGINSDIR\NSISdl.dll
$PLUGINSDIR\nsis_tauri_utils.dll
$PLUGINSDIR\StartMenu.dll
$PLUGINSDIR\System.dll
rewind-launcher-v2.exe
```

### 2.2 Actual application

| Field | Value |
|---|---|
| File | `rewind-launcher-v2.exe` |
| Size | 18,712,576 bytes |
| SHA-256 | `c90a8707af867af5779a12945c6948817066d21ef1875272d3cc3e6556c24672` |
| Architecture | AMD64 |
| Subsystem | Windows GUI |
| Image base | `0x140000000` |
| Entry point RVA | `0xa948e0` |
| Timestamp | 2026-10-09 11:43:48 UTC |
| FileVersion / ProductVersion | `0.0.8` |
| PDB | `rewind_launcher_v2.pdb` (Age 1) |
| Authenticode signature | No |
| Overlay | No |
| Sections | `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc` |
| Inferred compiler | Stable Rust, target `x86_64-pc-windows-msvc` |
| UI runtime | Tauri 2.11.5 + WebView2 |

### 2.3 PE sections

| Section | VA | Virtual size | Raw size | Entropy |
|---|---:|---:|---:|---:|
| `.text` | `0x1000` | 11,273,328 | 11,273,728 | 6.18 |
| `.rdata` | `0xac2000` | 6,637,156 | 6,637,568 | 6.68 |
| `.data` | `0x1117000` | 22,024 | 12,800 | 2.34 |
| `.pdata` | `0x111d000` | 665,052 | 665,088 | 6.71 |
| `.rsrc` | `0x11c0000` | 67,056 | 67,072 | 7.96 |
| `.reloc` | `0x11d1000` | 55,000 | 55,296 | 5.47 |

There is no `.dep-v0` section; therefore there is no `cargo-auditable` metadata that authenticates the dependency list. Crate versions were inferred from panic paths and binary strings.

### 2.4 Identified dependencies

| Component | Observed version |
|---|---|
| Tauri | 2.11.5 |
| `tauri-runtime-wry` | 2.11.4 |
| `tauri-utils` | 2.9.3 |
| `tauri-plugin-deep-link` | 2.4.9 |
| `tauri-plugin-dialog` | 2.7.2 |
| `tauri-plugin-opener` | 2.5.4 |
| `tauri-plugin-single-instance` | 2.4.3 |
| `reqwest` | 0.12.28 |
| `hyper` | 1.11.0 |
| `hyper-tls` / `tokio-native-tls` | 0.6.0 / 0.3.1 |
| `tokio` | 1.53.1 |
| `tokio-tungstenite` | 0.24.0 |
| `serde` / `serde_json` | 1.0.229 / 1.0.151 |
| `zip` | 2.4.2 |
| `rfd` | 0.16.0 |
| `discord-rich-presence` | 0.2.5 |
| `semver` | 1.0.28 |
| `regex` | 1.13.1 |
| `base64` | 0.22.1 |
| `anyhow` | 1.0.104 |
| `cfb` | 0.7.3 |
| `brotli-decompressor` | 5.0.3 |

The binary uses native Windows TLS (`schannel`), not rustls.

### 2.5 Native traceability

In addition to strings, native functions were located through their RIP-relative references to application literals. These addresses make it possible to audit the binary without relying on symbols (the binary does not include them):

| Address | Approx. size | Evidence / responsibility |
|---|---:|---|
| `0x1405a2060` | 7 KB | `launch_build`, receipt and recording of `accountId`, `launcherToken`, and `renderingMode` |
| `0x14058e6a0` | 5 KB | command line with `-AUTH_LOGIN=` / `-AUTH_PASSWORD=`, Nexon, Arc, “Game launched!” |
| `0x140592330` | 20 KB | manifest, signatures, file verification, Arc download |
| `0x1403a8f40` | 26 KB | `download_build`, ranges, resume, disk space |
| `0x1403b8fd0` | 14 KB | extraction, cleanup, final installation |
| `0x1403c5610` | 5 KB | `RewindLauncherUpdate.exe` updater |
| `0x1403beee0` | 13 KB | WebSocket loop and message dispatch |
| `0x1404b2480` | 12 KB | Fortnite version detection and splash |
| `0x14010ed30` | 17 KB | Tauri command registration/dispatch |
| `0x14000ec30` | 3 KB | WinRAR/7-Zip/tar detection |

Targeted disassembly of these functions is preserved in `analysis/native-disassembly.txt`. Addresses are VAs with ImageBase `0x140000000`. Contiguous Rust literals may share the same byte block, so string attribution to a function was validated against the actual reference and disassembly, not merely the presence of the text in the binary. Full automated decompilation was unreliable on this Rust binary; the analysis therefore relies on sections, strings, xrefs, and targeted disassembly.

### 2.6 Frontend extraction

The frontend is embedded as compressed Tauri assets. The following were located and decompressed:

| Asset | Decompressed size | SHA-256 |
|---|---:|---|
| `/index.html` | 701 | `b9336ebae40071593d3e2a8ab80c40db4a52e0a5d00b30c26574f9e467917ce8` |
| `/assets/index-BxyUA_Lo.js` | 446,395 | `0c2c346a71fd55d9f6daa40c02d975d42a31135df513bf594ffefe602d49713e` |
| `/assets/index-DydwhWmu.css` | 38,214 | `c56c7220043e5aad9267b8fd115b61db3b3c4a4602aea44e79f2565bcdfbd722` |
| `/assets/hxgp5M-Cq5C6Qm1.png` | 2,082,915 | `77b99eaf88b667d65941a61e08b325add5fd76ac7b091732b0be651fd7b7ba86` |

The original `index.html` loads:

```html
<script type="module" crossorigin src="/assets/index-BxyUA_Lo.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-DydwhWmu.css">
```

It also loads the Poppins font from Google Fonts. The JavaScript bundle was formatted for analysis; that formatted copy is not part of the product.

---

## 3. Application architecture

### 3.1 Identified native modules

Panic paths and type names reveal the following Rust modules:

| Module | Responsibility |
|---|---|
| `src/lib.rs` | Tauri startup, general commands, WebSocket, hotfix, update installation, global state, Discord RPC |
| `src/launch.rs` | Fortnite detection, file preparation, launch, process, retries |
| `src/download_build.rs` | Resumable download, state sidecar, extraction, progress |
| `src/shop.rs` | Item shop catalog |
| `src/clans.rs` | Clans, applications, members, roles, sanctions |
| `src/social.rs` | Friends, conversations, messages, groups |
| `src/voice.rs` | Voice rooms and signaling |
| `src/mares.rs` | “14 Days of Nightmares” event |
| `src/discord_rpc.rs` | Discord Rich Presence |

### 3.2 Native states

The observed type names confirm a shared-state architecture with Tauri events:

```text
BannedState                 FilesReadyState
RateLimitState              HotfixState
UpdateStatusState           SocketState
PollsState                  BuildDownloadFinishedState
RetryUsedState              FriendsState
TrailerState                BuildDownloadStatusState
LaunchStatusState           NewsState
UpdateProgressState         BuildDownloadProgressState
UpdateFailedState           MessagesState
LaunchSessionState          VoiceRoomState
ClansState                  MaresState
LaunchProgressState         LaunchFinishedState
ConversationsState
```

The pattern is:

1. a Tauri command returns the current state (`get_latest_*`);
2. the backend emits events when it changes (`launch-status`, `build-download-progress`, etc.);
3. the frontend subscribes and updates the UI.

This allows the window to be closed and reopened without losing the state of a download or launch.

---

## 4. Boot and authentication flow

### 4.1 Observed sequence

```text
Start
  │
  ├─ get_app_version
  ├─ check_server_status
  │    └─ if no services → error/emergency screen
  │
  ├─ WebSocket: ws://public-launcher-service.privateuser.xyz/
  │    ├─ hotfix        → hotfix.ini
  │    ├─ updateUrl     → update URL
  │    └─ token-validation
  │
  ├─ check_version
  │    ├─ UPDATE + download_url → download_and_install_update
  │    └─ no update → continue
  │
  ├─ token stored in localStorage: rewind_launcher_token
  │    └─ send_launcher_token
  │         └─ backend responds token-validation
  │              ├─ isTokenValid
  │              └─ userInformation
  │                   ├─ username
  │                   ├─ avatarUrl
  │                   ├─ email
  │                   ├─ accountId
  │                   └─ password
  │
  └─ Discord login (if no token)
       └─ opens https://public-backend-service-prod.privateuser.xyz/api/v2/aether/discord
            └─ callback rewindlauncher://...?launcherToken=...
```

### 4.2 Discord login

The frontend opens the Discord endpoint with the `opener` plugin:

```text
https://public-backend-service-prod.privateuser.xyz/api/v2/aether/discord
```

The backend returns to the launcher through the scheme:

```text
rewindlauncher://
```

The token is received as a query parameter:

```text
rewindlauncher://...?launcherToken=...
```

The frontend listens for:

- `deep-link://new-url` (deep link plugin);
- `launcher-token` event;
- `token-validation` event.

The token is stored in `localStorage` under `rewind_launcher_token`.

### 4.3 Token validation

The native `send_launcher_token` command sends the token over the WebSocket. The backend responds with `token-validation`, whose payload includes:

```json
{
  "isTokenValid": true,
  "userInformation": {
    "username": "string",
    "avatarUrl": "string",
    "email": "string",
    "accountId": "string",
    "password": "string"
  }
}
```

The `password` field is especially sensitive: Rewind's backend provides a game password that is then passed to Fortnite on the command line. This is analyzed in the security section.

### 4.4 Hotfix and server status

The `hotfix` event provides an object with the shape:

```json
{
  "hotfix.ini": {
    "bAreServicesOnline": true,
    "login_background_url": "string",
    "emergency_notice": "string"
  }
}
```

The UI uses `login_background_url` as the login background and `emergency_notice` to block access when the services are down. `check_server_status` returns `{ "isServerReady": boolean }`.

### 4.5 Logout

The `logout` command:

- closes/disconnects the WebSocket;
- clears session state;
- removes the token from `localStorage`;
- returns to the login screen.

---

## 5. Interface map

### 5.1 Window and navigation

- Main window observed in the frontend: `1100 × 640`.
- The download panel expands to `1440 × 640` (`1100 + 340`).
- Custom title bar of 24 px.
- Fixed 64 px side rail, starting at `top: 24px`.
- Visual theme with `--rw-*` CSS variables, Poppins typography.

Main navigation:

```text
Home
Library
Item Shop
14 Days of Nightmares   (conditional)
Clans                    (conditional)
Friends
Settings
```

“Polls” is not in the rail: it opens from Home.

### 5.2 Home

Includes:

- banner/news;
- trailer (played in a modal or embedded player);
- polls;
- session status;
- shortcuts to the shop and library.

The trailer is controlled with:

```text
get_latest_trailer
clear_latest_trailer
show-trailer event
```

### 5.3 Library

Functions:

- list saved builds;
- search by version or folder;
- grid/list view;
- add an existing installation;
- detect version automatically;
- download a build;
- launch with confirmation;
- remove from the library;
- display “Last played”;
- display active downloads and allow cancel/resume.

Local build model:

```json
{
  "path": "C:\\...\\FortniteGame\\...",
  "version": "27.11",
  "splashImage": "data:image/jpeg;base64,..."
}
```

`rewind_builds` contains the array. `rewind_library_view` stores `grid` or `list`.

Build catalog observed in the frontend:

| ID | Season | URL |
|---|---|---|
| `27.11` | Chapter 4 Season OG | `https://public-service-live.privateuser.xyz/27.11.rar` |
| `24.20` | Chapter 4 Season 2 | `https://r2.ploosh.dev/24.20.zip` |

Build `27.11` is marked as `hosted: true`. Build `24.20` points to a third-party domain.

### 5.4 Item Shop

- Calls `get_item_shop_catalog`.
- Groups the catalog `storefronts`.
- Displays a countdown based on `expiration`.
- Uses images from `fortnite-api.com` for V-Bucks and cosmetics.
- Does not allow purchases: it is a catalog viewer.

### 5.5 Settings

Pages:

```text
Account
Appearance
Game
Launcher
```

Account:

- name;
- avatar;
- email;
- accountId;
- clan;
- session;
- logout.

Appearance:

- 10 themes: `basic`, `purple`, `sunset`, `ocean`, `forest`, `crimson`, `rose`, `gold`, `slate`, `rgb`.

Game:

- rendering mode: `dx11`, `dx12`, `performance`;
- potato graphics;
- FOV (80–120, default 80).

Launcher:

- sound effects (enabled by default);
- updates;
- launcher version.

### 5.6 Themes

| ID | Background | Accent |
|---|---|---|
| `basic` | `#07091a` | `#4f6bff` |
| `purple` | `#150a24` | `#a855f7` |
| `sunset` | `#1f0f18` | `#ff7a59` |
| `ocean` | `#061a24` | `#22d3ee` |
| `forest` | `#0a1a10` | `#34d399` |
| `crimson` | `#1a0a0d` | `#f43f5e` |
| `rose` | `#1c0a16` | `#ec4899` |
| `gold` | `#1a1408` | `#eab308` |
| `slate` | `#0d1117` | `#38bdf8` |
| `rgb` | gradient | animated conic gradient |

### 5.7 `localStorage` keys

```text
rewind_launcher_token
rewind_builds
rewind_active_download
rewind_download_destination
rewind_theme
rewind_sound_effects
rewind_render_mode
rewind_potato_graphics
rewind_fov
rewind_last_launch_version
rewind_reset_on_release
rewind_library_view
rewind_seen_poll_ids
rewind_seen_trailer_ids
```

Observed defaults:

- theme: `basic`;
- sound: enabled;
- render: `performance` in Settings, but the launch modal uses `dx11` if the key does not exist yet;
- FOV: `80`;
- download destination: `C:\RewindBuilds`.

---

## 6. Tauri command inventory

The bundle invokes 81 commands. The complete list with bundle line numbers is in `analysis/frontend-command-usage.tsv`. Grouped:

### 6.1 Application, session, and update

```text
get_app_version
check_server_status
check_version
download_and_install_update
send_launcher_token
logout
set_discord_presence
```

### 6.2 Library, download, and launch

```text
detect_fortnite_version
download_build
cancel_build_download
clear_build_download_state
get_latest_build_download_status
get_latest_build_download_progress
get_latest_build_download_finished
launch_build
retry_launch
clear_launch_state
get_latest_launch_status
get_latest_launch_progress
get_latest_launch_finished
get_latest_files_ready
has_retry_available
```

### 6.3 Friends and messaging

```text
request_friends
get_latest_friends
add_friend
remove_friend
cancel_friend_request
respond_friend_request
search_players
request_conversations
get_latest_conversations
open_direct_conversation
request_messages
get_latest_messages
send_message
delete_message
mark_conversation_read
leave_conversation
create_group_chat
add_group_members
remove_group_member
transfer_group_ownership
delete_group_chat
```

### 6.4 Clans

```text
request_clans
get_latest_clans
submit_clan_request
update_clan
cancel_clan_request
apply_to_clan
cancel_clan_application
review_clan_application
leave_clan
kick_clan_member
ban_clan_member
unban_clan_member
set_clan_member_role
disband_clan
create_clan_group_chat
join_clan_group_chat
```

### 6.5 Voice

```text
request_voice_room
join_voice
leave_voice
send_voice_signal
set_voice_state
get_latest_voice_room
```

### 6.6 Content, polls, and events

```text
get_latest_news
get_latest_hotfix
get_latest_polls
send_poll_vote
get_latest_trailer
clear_latest_trailer
get_latest_banned
request_mares
get_latest_mares
claim_mares_reward
claim_mares_challenge
get_item_shop_catalog
send_username_change
get_latest_update_status
get_latest_update_progress
get_latest_update_failed
clear_update_failed
```

---

## 7. WebSocket and event protocol

### 7.1 Connection

```text
URL: ws://public-launcher-service.privateuser.xyz/
```

On connection, the client sends:

```json
{
  "launcherToken": "string",
  "version": "0.0.8"
}
```

The server can send a new token through `launcher-token` and validates the session with `token-validation`.

### 7.2 Server messages

| Type | Purpose |
|---|---|
| `new` | new news item |
| `hotfix` | configuration/hotfix |
| `polls` | poll list |
| `clans` | clan state |
| `mares` | event state |
| `friends` | friend list |
| `conversations` | conversation list |
| `messages` | messages |
| `banned` | sanctioned user |
| `updateUrl` | update URL |
| `token-validation` | session validation |
| `launcher-token` | server-issued token |
| `show-trailer` | show trailer |
| `voice-room` | voice room state |
| `voice-signal` | WebRTC signal |
| `voice-result` | join/leave result |
| `message-result` | message result |
| `player-search` | search results |
| `friend-result` | friend result |
| `mares-result` | event action result |
| `clan-result` | clan action result |
| `vote-result` | vote result |
| `username-change` | name change result |

### 7.3 Tauri events emitted by the backend

| Event | Purpose |
|---|---|
| `launch-status` | launch phase |
| `launch-progress` | preparation/verification progress |
| `launch-finished` | launch result |
| `game-files-ready` | files ready to play |
| `download-progress` | download/verification during launch |
| `build-download-status` | build download state |
| `build-download-progress` | build download progress |
| `build-download-finished` | download completed |
| `update-status` | update state |
| `update-progress` | update progress |
| `update-failed` | update error |
| `socket-disconnected` | WebSocket disconnected |
| `deep-link://new-url` | login callback |

---

## 8. Launching Fortnite

### 8.1 `launch_build` arguments

The frontend sends:

```json
{
  "path": "C:\\...\\build",
  "version": "27.11",
  "renderingMode": "dx11",
  "ror": false,
  "potato": false,
  "fov": 80,
  "email": "user@example.com",
  "password": "********",
  "accountId": "string",
  "launcherToken": "string"
}
```

`ror` corresponds to `rewind_reset_on_release`. Its exact effect was not confirmed without dynamic analysis; the name suggests resetting configuration when the release changes.

### 8.2 Detecting an installation

The backend validates that these exist:

```text
FortniteGame/
Engine/
FortniteGame/Binaries/Win64/FortniteClient-Win64-Shipping.exe
FortniteGame/Content/Splash/Splash.bmp
```

It extracts the version with the pattern:

```text
++Fortnite+Release-(\d{1,2}\.\d{1,2}|Live|Next|Cert)-CL-(\d+)
```

If the splash file is not found, it uses:

```text
https://public-service-live.privateuser.xyz/FortniteGame/Content/Splash/Splash.bmp
```

The splash is returned as `data:image/bmp;base64,...` and the frontend compresses it to JPEG for storage in `localStorage`.

### 8.3 Observed native phases

Binary strings show this pipeline:

```text
Starting setup for Fortnite {version}
Preparing manifest (this may take a minute)...
Waiting for server signatures (this may take a minute)...
Verifying local files...
Waiting for the server to finish preparing files (...)
Network hiccup, retrying (...)
[launch] signatures still building, poll ...
Creating Nexon session...
Launching...
Game launched!
```

Launching is not limited to executing the `.exe`: before that, it downloads the manifest, queries signatures, compares local files, and downloads anything missing.

### 8.4 Files and processes

Referenced paths and executables:

```text
FortniteGame\Binaries\Win64\FortniteLauncher.exe
FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_EAC.exe
FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping_BE.exe
\Nexon\Nexon.exe
Arc.exe
taskkill /PID <pid> /F
```

Observed arguments:

```text
-FeatureLevelES31
-D3D11
-D3D12
-AUTH_LOGIN=<email>
-AUTH_PASSWORD=<password>
-potato
```

The suspended-process creation pattern is also observed:

```text
Launcher process suspended with PID: ...
```

The binary imports `CreateProcessW`, `SuspendThread`, and `TerminateProcess`, and uses `taskkill` to close processes. The exact purpose of the suspension is not confirmed; it is probably part of `FortniteLauncher`/anti-cheat handling.

### 8.5 Arc anti-cheat

The launcher downloads and runs:

```text
https://cloud.arc-services.dev/modules/anticheat/Arc.exe
```

Associated messages:

```text
Failed to launch Arc:
Failed to get Arc process ID
```

It also verifies `arc.exe` and `fortnitegame` files against the content manifest.

### 8.6 Retry

The backend stores a `LaunchSessionState` and allows a controlled retry:

```text
retry_launch
has_retry_available
clear_launch_state
```

The frontend displays `Retry` only when `has_retry_available` returns `true`.

---

## 9. Downloading and installing builds

### 9.1 Input

```text
download_build { url, destination }
```

Returns the final installation path.

### 9.2 Persistent state

The backend writes a sidecar:

```text
.dlstate.json
```

The schema is confirmed by the binary's serialization metadata:

```text
DownloadSidecar { url, total_size, etag, chunks }
ChunkState      { start, end }
DownloadState   { downloaded }
```

Example:

```json
{
  "url": "string",
  "total_size": 0,
  "etag": "string",
  "chunks": [
    { "start": 0, "end": 0 }
  ]
}
```

The following markers are also observed:

```text
.rewind_extract
.rewind_installed
v3.json
```

The download uses range requests (`Range`, `bytes=`), ETag, and resume. Chunks are stored in the state so that already received data is not downloaded again. If the server changes version (different ETag), it invalidates the state and asks for a retry.

### 9.3 Extraction

Supports:

```text
.rar
.7z
.zip
```

Searches for tools in:

```text
WinRAR
7-Zip
tar.exe
System32
```

Registry paths:

```text
SOFTWARE\WinRAR
SOFTWARE\WOW6432Node\WinRAR
SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe
SOFTWARE\7-Zip
```

Observed executables and switches:

```text
UnRAR.exe
Rar.exe
WinRAR.exe
7z.exe
tar.exe

WinRAR: x -y -o+ -p- -idcd -ibck -aoa -bsp1 -bb1 -xf <archive> -C <destination>
```

Using `-ibck` runs WinRAR in the background; `-bsp1` and `-bb1` allow progress to be read. Checksum and damaged-archive errors are translated into UI messages.

Error messages:

```text
WinRAR found a checksum error
WinRAR reported a damaged archive
WinRAR could not write the extracted files...
the archive produced no files
Your disk is full.
```

### 9.4 Progress

The confirmed native type contains thirteen fields:

```text
BuildDownloadProgress {
  success, message, phase,
  fileName, fileIndex, fileCount,
  bytesDownloaded, totalBytes,
  downloadSpeedBps, writeSpeedBps,
  etaSeconds
}
```

Example:

```json
{
  "success": true,
  "message": "string",
  "phase": "downloading | extracting | checking",
  "fileName": "string",
  "fileIndex": 0,
  "fileCount": 0,
  "bytesDownloaded": 0,
  "totalBytes": 0,
  "downloadSpeedBps": 0,
  "writeSpeedBps": 0,
  "etaSeconds": 0
}
```

It is emitted through `build-download-progress`; the state can be retrieved with `get_latest_build_download_progress`.

### 9.5 File verification during launch

The launch pipeline queries:

```text
https://r2.privateuser.xyz/cloud/manifest/manifest.json
https://public-backend-service-prod.privateuser.xyz/api/v1/rewind/client/pakchunk/development/signatures
https://r2.privateuser.xyz/cloud/content/development/
```

Observed structures:

```text
FileList
SigEntry { name, hash }
DownloadState { downloaded }
ChunkState { start, end }
DownloadSidecar { url, total_size, etag, chunks }
```

The manifest is used to verify and complete the installation. It was not confirmed whether `hash` is cryptographically validated; the binary does not show an obvious hashing dependency in the panic strings.

---

## 10. Item Shop

### 10.1 Flow

```text
get_item_shop_catalog
  └─ GET https://public-backend-service-prod.privateuser.xyz/fortnite/api/storefront/v2/catalog
       └─ JSON serialized to the frontend
```

The native backend checks the HTTP status and returns an error with:

```text
Shop request failed with status <code>
```

### 10.2 Presentation

- Groups by `storefronts`.
- Sorts by `sortPriority`.
- Distinguishes `small` entries.
- Countdown based on `expiration`.
- Cosmetic images from `fortnite-api.com`.
- No purchasing or real V-Bucks; catalog only.

---

## 11. Clans

### 11.1 Model

The `submit_clan_request` command sends:

```json
{
  "name": "string",
  "tag": "string",
  "description": "string",
  "color": "#rrggbb",
  "icon": "string",
  "maxMembers": 0,
  "recruiting": true
}
```

Observed roles:

```text
leader
officer
member
```

### 11.2 Functions

- create clan;
- edit clan;
- cancel request;
- apply to a clan;
- cancel application;
- review application (approve/deny);
- leave clan;
- kick member;
- ban member with reason;
- unban;
- change role;
- disband clan;
- clan chat;
- join clan chat.

The UI includes:

```text
My clan
Browse
Roster
Applications
Bans
```

Application states:

```text
Awaiting review
Denied
Approved
```

### 11.3 Dependency

All clan logic lives in the private backend. The launcher only sends commands and renders the state received over the WebSocket.

---

## 12. Friends, conversations, and messages

### 12.1 Friends

```text
request_friends
get_latest_friends
add_friend
remove_friend
cancel_friend_request
respond_friend_request
search_players
```

`add_friend` accepts:

```json
{
  "username": "string",
  "message": "string",
  "accountId": "string | null"
}
```

### 12.2 Conversations

Observed types:

```text
direct
group
clan
```

Operations:

```text
request_conversations
get_latest_conversations
open_direct_conversation
create_group_chat
create_clan_group_chat
join_clan_group_chat
add_group_members
remove_group_member
transfer_group_ownership
delete_group_chat
leave_conversation
mark_conversation_read
```

### 12.3 Messages

```text
request_messages { conversationId, before, limit }
get_latest_messages
send_message { conversationId, body }
delete_message { conversationId, messageId }
```

Observed fields:

```text
id
conversationId
senderAccountId
username
body
createdAt
unreadCount
```

The WebSocket delivers `messages` and `message-result`; the UI maintains history and updates the unread counter.

---

## 13. Voice

### 13.1 Architecture

Voice is peer-to-peer WebRTC, with Rewind as the signaling service:

```text
request_voice_room { conversationId }
join_voice { conversationId }
leave_voice { conversationId }
send_voice_signal { targetAccountId, payload }
set_voice_state { conversationId, muted }
```

The backend emits:

```text
voice-room
voice-signal
voice-result
```

### 13.2 UI

- up to 8 participants (`em = 8`);
- detects “speaking” with an audio analyzer (threshold `0.02`);
- local mute and deafen;
- publishes mute state;
- plays remote audio with `<audio>`;
- handles microphone errors:
  - permission denied;
  - no microphone;
  - microphone in use;
  - failure to start.

### 13.3 Dependency

The room and signaling depend on Rewind's backend. Audio is P2P; without signaling, it is impossible to join an existing room.

---

## 14. Polls, news, trailer, and Mares

### 14.1 Polls

Observed model:

```json
{
  "id": "string",
  "question": "string",
  "options": [
    { "id": "string", "text": "string", "votes": 0 }
  ],
  "totalVotes": 0,
  "hasVoted": false,
  "votedOptionId": "string | null",
  "expiresAt": "string"
}
```

Commands:

```text
get_latest_polls
send_poll_vote { pollId, optionId }
```

Events:

```text
polls
vote-result
```

The UI stores seen IDs in `rewind_seen_poll_ids` and displays “Polls are coming soon” when there are no polls.

### 14.2 News and trailer

```text
get_latest_news
get_latest_trailer
clear_latest_trailer
show-trailer
```

The trailer is shown in an embedded player. The UI stores seen IDs in `rewind_seen_trailer_ids`.

### 14.3 14 Days of Nightmares

Observed model:

```json
{
  "event": {},
  "rewards": [
    { "day": 1, "title": "string", "imageUrl": "string", "rarity": "string", "quantity": 1 }
  ],
  "challenges": [],
  "phases": [],
  "streak": { "current": 0 }
}
```

Commands:

```text
request_mares
get_latest_mares
claim_mares_reward { rewardId }
claim_mares_challenge { challengeId }
```

Events:

```text
mares
mares-result
```

The “14 Days of Nightmares” navigation entry appears only when the event is active.

---

## 15. Updates

### 15.1 Flow

```text
check_version
  ├─ { type: "UPDATE", download_url: "..." }
  └─ { type: "OK", message: "You are up to date" }
```

The literal `You are up to date` is present in the binary. The exact shape of the `OK` object is inferred from that literal and from frontend consumption; the frontend only checks `type === "UPDATE"` and `download_url`.

If an update is available:

```text
download_and_install_update { downloadUrl }
```

The backend:

1. downloads the file;
2. writes `RewindLauncherUpdate.exe`;
3. runs the installer;
4. emits `update-status`, `update-progress`, and `update-failed`;
5. restarts the launcher.

Messages:

```text
Downloading update...
Installing update...
Failed to launch installer:
Restarting...
```

No fixed “latest version” URL was recovered from the binary. The most consistent hypothesis is that the URL arrives through the `updateUrl` WebSocket event or through a dynamically constructed endpoint; `check_version` decides whether an update is required. This remains an open point.

---

## 16. Discord Rich Presence

Command:

```text
set_discord_presence { details, state }
```

The frontend updates presence according to the page:

```text
home      → Browsing Homepage
library   → Browsing Library
itemshop  → Browsing Item Shop
settings  → Configuring their Launcher
polls     → Voting on a Poll
clans     → Browsing Clans
friends   → Chatting with Friends
mares     → Surviving 14 Days of Nightmares
```

The binary contains the type `rewind_launcher_v2_lib::discord_rpc::DiscordRpc` and the dependency `discord-rich-presence 0.2.5`.

---

## 17. Endpoints and services

### 17.1 Confirmed in native strings

| Service | URL |
|---|---|
| Discord auth | `https://public-backend-service-prod.privateuser.xyz/api/v2/aether/discord` |
| WebSocket | `ws://public-launcher-service.privateuser.xyz/` |
| Shop catalog | `https://public-backend-service-prod.privateuser.xyz/fortnite/api/storefront/v2/catalog` |
| Pakchunk signatures | `https://public-backend-service-prod.privateuser.xyz/api/v1/rewind/client/pakchunk/development/signatures` |
| Manifest | `https://r2.privateuser.xyz/cloud/manifest/manifest.json` |
| Content | `https://r2.privateuser.xyz/cloud/content/development/` |
| Remote splash | `https://public-service-live.privateuser.xyz/FortniteGame/Content/Splash/Splash.bmp` |
| Arc anti-cheat | `https://cloud.arc-services.dev/modules/anticheat/Arc.exe` |
| Build 27.11 | `https://public-service-live.privateuser.xyz/27.11.rar` |
| Build 24.20 | `https://r2.ploosh.dev/24.20.zip` |
| Sidebar image | `https://r2.privateuser.xyz/images/SidebarRewind.png` |

### 17.2 Identifiers

```text
App identifier: com.privateuser.rewind-launcher-v2
Deep-link scheme: rewindlauncher
User-Agent: RewindLauncher/0.0.8
```

### 17.3 Non-private external dependencies

- `https://fortnite-api.com` for V-Bucks/cosmetic images.
- `https://fonts.googleapis.com` / `fonts.gstatic.com` for Poppins.
- `https://r2.ploosh.dev` for a third-party build.

---

## 18. Security and privacy

Objective observations from the artifact:

1. **WebSocket without TLS**
   The binary uses `ws://`, not `wss://`, for the launcher service. The token and session events travel without TLS transport encryption.

2. **Game password in arguments**
   The password returned by `token-validation` is passed to Fortnite through `-AUTH_PASSWORD=`. Process arguments are visible to other processes belonging to the same user and may remain in third-party tool logs.

3. **Backend provides credentials**
   The launcher receives `email` and `password` from the backend. These are not credentials entered locally by the user. This concentrates risk in the backend and the channel.

4. **No Authenticode signature**
   Neither the installer nor the application has a verifiable code signature.

5. **Auto-update**
   `download_and_install_update` downloads and runs `RewindLauncherUpdate.exe`. No signature validation of the updater was observed in the analyzed strings.

6. **External anti-cheat**
   `Arc.exe` is downloaded from `cloud.arc-services.dev` and run with the game.

7. **Frontend-controlled paths**
   `launch_build` receives `path`, `email`, `password`, and `launcherToken` from the WebView. A compromise of the WebView content or IPC would have a direct impact on local execution.

8. **Update HTTP**
   No fixed update URL was recovered; if the URL arrives through `updateUrl`, channel integrity depends on the WebSocket and backend.

The binary was not executed, and no credentials were sent to Rewind services during this analysis.

---

## 19. What can be rebuilt without the private services

### 19.1 Fully local

- UI and themes.
- Build library.
- Version detection.
- Build download/extraction from a custom URL.
- Progress, resume, and cancellation.
- Fortnite launch with the user's own credentials.
- Render, FOV, and potato settings.
- Discord Rich Presence.
- Logs and diagnostics.

### 19.2 Requires a custom backend

- Login (custom Discord OAuth or local login).
- Session token.
- Presence/event WebSocket.
- Clans.
- Friends, conversations, and messages.
- Voice signaling.
- Polls.
- Mares.
- Build catalog.
- News/trailer.
- Updates.
- Shop catalog (proxy or public API).

### 19.3 Not reproducible identically

- The `*.privateuser.xyz` endpoints.
- The game credentials issued by Rewind's backend.
- Rewind's catalog and assets.
- Its build signature/manifest system.
- The Arc anti-cheat and its backend.
- Private build IDs and community state.

A clean reconstruction must replace these points with its own services or public integrations, without reusing Rewind's backend or assets.

---

## 20. Open questions

1. Confirm the exact URL/source used by `check_version` and the update manifest format.
2. Confirm the exact meaning of `ror`.
3. Confirm whether `SigEntry.hash` is cryptographically verified and with which algorithm.
4. Confirm the purpose of `CreateProcessW` + `SuspendThread` during launch.
5. Confirm the exact argument sequence for `FortniteLauncher.exe`, `_EAC.exe`, and `_BE.exe`.
6. Confirm whether `Arc.exe` runs before or after Fortnite and how it is closed.
7. Confirm the complete `clans` and `voice-room` schema sent by the backend.
8. Confirm the exact Tauri window configuration (initial size, decorations, transparency).

---

## 21. Available evidence

| File | Contents |
|---|---|
| `analysis/pe-info.json` | PE headers, sections, imports, resources, version, PDB |
| `analysis/installer-pe-info.json` | NSIS installer metadata |
| `analysis/ui-labels.tsv` | UI texts and bundle line numbers |
| `analysis/frontend-command-usage.tsv` | 81 Tauri commands and usage lines |
| `analysis/native-string-xrefs.tsv` | Native functions and literals they reference |
| `analysis/native-disassembly.txt` | Targeted disassembly of selected native functions |
| `tools/native_xrefs.py` | `.pdata` + Capstone + strings correlation script |
| `tools/dump_native_disasm.py` | Disassembly dump with string annotations |
| `installer/rewind-launcher-v2.exe` | Extracted application |
| `installer/$PLUGINSDIR/` | Extracted NSIS plugins |
| `frontend/index.html` | Frontend entry point |
| `frontend/assets/index-BxyUA_Lo.js` | Original JavaScript bundle |
| `frontend/assets/index-DydwhWmu.css` | Original CSS |
| `frontend/tauri-dumper.manifest.json` | Offsets and hashes of embedded assets |

---

## 22. Conclusion

The binary confirms that Rewind 0.0.8 is a complete Tauri launcher, not a simple shortcut: it handles authentication, WebSocket events, library, resumable downloads, extraction, verification, launch, anti-cheat, voice, clans, chat, polls, events, and updates.

A clean reconstruction is viable if it is separated into two layers:

1. **Local launcher**: UI, library, download, extraction, launch, settings, and presence.
2. **Custom services**: auth, WebSocket, clans, friends, voice, polls, Mares, catalog, and updates.

Exact parity with Rewind is not possible without access to its private services. Functional parity is possible, provided those services are replaced with a custom implementation and the user supplies their own game credentials.
