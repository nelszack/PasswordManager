# User guide

[Back to README](../README.md) · [Command reference](commands.html) · [Security policy](../SECURITY.md)

- [Installation and upgrades](#installation)
- [Desktop interface](#desktop-interface)
- [Android app](#android-app)
- [Android preferences](#android-preferences)
- [Vaults, entries, search, and recovery](#usage)
- [Authenticators and Duo Push](#totp-and-hotp-authenticators)
- [Import, export, and encrypted backups](#importexport)
- [Configuration and data locations](#configuration-and-data-locations)
- [Shell completions](#shell-completions)
- [Browser extension](#browser-extension)
- [Clipboard behavior](#clipboard-behavior)

## Installation

### Desktop interface

Run `pm` without arguments, or `pm gui`, to open the Iced desktop interface.
The same executable also runs every CLI command and the background server.
Only one window runs at a time: launching it again, or choosing **Open desktop
app** in the browser extension, brings the existing window forward (on the
password field when the vault is locked). `pm gui --search` brings it forward with
the vault search focused; bind it to a key in your desktop, for example in
Hyprland: `bind = SUPER, P, exec, pm gui --search`. `pm gui --open ID` shows one
item (after you unlock, if the vault is locked); the extension's **Open** button on a
search result uses it. On Linux, a tray icon (shown by Waybar, KDE, and other
StatusNotifierItem hosts) shows whether the vault is locked, opens the window on
click, locks the vault on middle-click, and offers Open, Lock vault and Close window
in its menu.

In the item list, **Select** turns on selection mode: click items to choose them
(or **Select all shown**), then add them to favorites, add a tag, or move them to
trash in one step. Moving several items to trash lists them and asks first.
Opening the GUI starts the server when needed; closing the GUI does not stop
it. `pm --help`, scripted commands, native messaging, and the server do not open
windows or require a graphical session. Builds made with
`cargo build --release --locked --no-default-features` provide only CLI/server
functionality and report that the desktop interface is unavailable.

On Windows, `pm kill` waits for the server process to exit before reporting
success. If shutdown takes more than ten seconds after acknowledgement, it
reports that the server is still stopping. Pending cloud network requests are
cancelled during shutdown; vault writes already in progress finish safely.
Close any open PM windows before replacing `pm.exe`, and allow clipboard
helpers to finish their configured cleanup timeout. The browser's separate
native-host copy must be updated with Chrome fully closed.

On Linux, put the binary at a stable path and run:

```bash
pm gui --install-shortcut
```

This installs `com.passwordmanager.Pm.desktop` under your XDG user applications
directory, using the exact executable path, the lock icon shared with the
browser extension, and `Terminal=false`. Find **Password Manager** in the application menu
and pin it to your dock. Desktop environments that support desktop icons can
also use a copy of that file. Install again after moving the executable. On
Windows, make a shortcut to `pm.exe`, then select **Properties → Change Icon →
Browse** and choose `assets/password-manager.ico` from the source checkout or
`password-manager.ico` beside `pm.exe` in a release archive. Keep the icon file
at that location. On macOS, run the executable from your
preferred launcher. Automatic shortcut installation currently targets Linux.

The Vault tab supports creating a password-protected vault, selecting an
existing vault, unlocking with a password or an absolute external-key path,
searching item names/usernames/URLs/tags, adding items, and viewing/editing names,
types, usernames, primary secrets, URLs, tags, favorites, multiline notes, and
custom fields. Enter tags as a comma-separated list. Favorites show a ★ in the
item list; use **Add to favorites** on an open item to star it without editing.
The list's tag picker and **Favorites only** checkbox narrow the items shown.
Open **Custom fields & advanced options** and enable **Edit as a multiline secret** when entering private keys or other multiline values;
that editor displays the text while editing. The desktop creation form accepts a
friendly vault name and opens the new vault using the password just entered.
CLI-created vaults still remain locked. If another client creates a vault at
the same time and the new file cannot be identified unambiguously, select and
unlock it explicitly. Moving an item to trash requires confirmation; the feedback
bar offers **Undo deletion** until you navigate elsewhere. **Tools → Deleted
items** and **Tools → Password history** provide recovery afterward.
Open **Advanced unlock options** to choose a key file or change the inactivity timeout for that session. With no vaults, the welcome screen offers creation and import/restore directly. Narrow windows show the item list and details one at a time; **Back to items** returns to the list. Search can be narrowed by item type, with **Advanced search** beside the list.

Large item lists show 50 items per page. Use Previous/Next or enter a page
number to jump directly; search still covers the whole vault. The A–Z/Z–A control
changes name order. Ctrl/Cmd+R refreshes the list.

The Generator tab can transfer its exact output into a new or existing item
draft without using the clipboard. Confirm replacement, review the item, then
save it. Expired generated values and values from a previous unlock cannot be transferred.

If another client changes an item while you edit, your masked draft is kept.
Choose **Review latest version** to compare metadata, note previews, and public
custom fields. **Reapply my edits to this version** retains changes to untouched
fields from the other client; it does not save automatically. Review the result
before saving. Stored passwords and secret custom values remain hidden.

Closing the window or changing connections asks before discarding an unsaved
item. Locking remains immediate and discards the draft. Long feedback messages
can be focused with Tab and scrolled with arrow keys, Page Up/Down, or Home/End.

Use **Browse…** beside the external-key path to select a file with the native
file picker, or enter the path manually. Choosing a file fills its path; press
**Unlock vault** to use it. Cancelling keeps the existing path unchanged.
On Linux, the picker needs the D-Bus library, `xdg-desktop-portal`, and a
FileChooser backend such as `xdg-desktop-portal-gtk` or
`xdg-desktop-portal-kde`. If your desktop lacks a file-picker portal, enter
the absolute key-file path directly. Windows and macOS use their native dialogs.

The primary secret stays unchanged during edits unless **Replace primary secret** is checked. An empty replacement deliberately clears it.
**Generate a strong password** fills a new secret that is committed only
when you save the item. The Generator tab also creates passwords and
passphrases independently of the vault, with character-class controls, a custom
symbol set, ambiguous-character exclusion, word count, and separator. It also
checks an existing password's strength locally without storing it. Generated
values disappear after 60 seconds. Saved-item secrets reveal for 15 seconds and hide on focus loss
or Escape. Ctrl+L (Command+L on macOS) locks the vault. Copy buttons use the
configured clipboard cleanup; see [clipboard behavior](#clipboard-behavior).

Vault names are labels on this device, stored in `vault-names.json` beside the
configuration. Encrypted filenames are unchanged; the advanced unlock section
shows the underlying filename when needed. **Settings → Security → Save vault
name** changes the selected vault's label. Names survive preference resets.

Item details offers **Copy username**, **Copy secret**, and **Open website**.
Website opening accepts explicit HTTP/HTTPS URLs without embedded credentials or
wildcards and uses the system browser. Username copying checks the unlock session
and item revision, follows the clipboard timeout, and is disabled at timeout zero.

The editor keeps **Save item** and **Cancel** visible while its fields scroll.
The name and type selector share a row. Login credentials also share a row
when there is room; enlarged and narrow layouts stack the fields. **Show**
reveals only the primary secret you are entering, and **Hide**, Escape, switching
tabs, or leaving the window masks it again.
Saving returns to the saved item's details with its current revision and keeps
your search and type filter. If concurrent additions make a newly saved item
ambiguous, the app refreshes the list instead of guessing which item to open.
Each item type has relevant labels and guidance. Cards, identities, Wi-Fi,
licenses, SSH keys, and API secrets show their usual optional fields directly;
untouched fields are preserved, and new optional fields are stored only when
edited. Routine feedback appears in a fixed footer without moving the form.
Validation appears beside names, custom fields, and settings inputs. Custom
fields and copy overrides are under **Custom fields & advanced options**;
authenticator enrollment has its own disclosure. Changing tabs preserves an
open item draft and offers **Return to item draft**. Navigating to another
item requires saving or explicitly discarding dirty changes.

**Settings → Appearance** provides Dark, Light, and High contrast themes and
100%, 115%, and 130% interface sizes. Appearance previews immediately and persists
when you save settings. Settings are grouped into Appearance, Security,
Passwords, Recovery, and Connection; Save remains visible in each section.
Section navigation scrolls with the settings content to leave room for controls
at enlarged sizes. Very short windows scroll the whole page. The keyboard guide
opens in the main content area and can be closed without moving the current form.

Generated secrets appear above the generation options. After generation, the
view returns to the top so the result and its Copy/Show controls are visible.
The feedback bar announces completion and the secret is cleared after 60 seconds.
Saved-item Copy buttons are disabled when the clipboard timeout is zero, with a
message pointing to **Settings → Security**. Undo deletion is cleared when you
leave its context or the deleted item is restored or erased. Recovery dates use
the same readable local format as item details. A health check with no login
items explains that there is nothing to assess and does not display a score.

Choose **Shortcuts** for the keyboard guide. Ctrl (Command on macOS) + F searches.
With that same modifier, N creates an item, S saves the current item or settings,
1–4 switches between Vault, Generator, Tools, and Settings, E edits the selected
item, and L locks the vault. Ctrl/Command+Shift+C copies the selected item's username,
Shift+P its password (or card number, key, …), Shift+T its current one-time code,
and Shift+O opens its first website. Up and Down select the previous or next item,
also while the search box has focus. These companion actions operate on saved
item details, not unsaved drafts. Time-based one-time codes appear as soon as an
item opens and count down by themselves.

When you close the window while a vault is unlocked, the app asks whether to lock
it or keep it available to the browser extension and `pm`; choose a default in
**Settings → Security**. **Settings → Appearance** can follow the system's light or
dark setting and offers text sizes up to 200%.
Tab / Shift+Tab moves between controls; Enter / Space activates buttons and
checkboxes. Arrow keys, Home, and End change selection-list values. Keyboard
focus has a visible outline and scrolls into view in forms. Escape hides
revealed secrets. Native screen-reader integration still depends on toolkit
and platform support.

The Tools overview offers direct tasks for vault health, deleted items, password
history, encrypted backups, restore, import, export, advanced search, credentials,
and browser setup. Results open in their own view at the top, with **Back to
options**, **Clear result**, and **View your items** actions. Health findings open
the affected item directly. Destructive confirmations replace the options view so
the reviewed operation and decision controls are visible together.

Settings exposes every `pm config` preference: password length, strength/statistics,
automatic copying of generated passwords and newly added login passwords,
clipboard timeout, inactivity timeout, default vault, password history limit,
trash retention, and server port. The GUI and CLI use the same configuration file.
The Generator tab follows saved defaults unless you choose a one-time statistics,
automatic-copy, or clipboard-timeout override. Length and generation options are
also temporary. New items have their own Copy / Do not copy override, including
non-login items. A timeout of zero disables copying. Settings reload when opened;
**Refresh** reloads them again while preserving unsaved edits. Generation,
item saving, and copy actions read current defaults before proceeding, including
changes made through the CLI.

Inactivity accepts seconds or durations such as `15m`, `1h`, and `1d`, and takes
effect on the next unlock. Clipboard timeout is in seconds; zero disables copying.
Zero password-history limit disables history, and zero trash retention keeps trash
indefinitely. Default vault can be set to **Automatic selection** without resetting
other preferences. **Reset to defaults** resets every preference after confirmation.
Unsaved edits to other settings do not overwrite unrelated preferences changed
through the CLI in the meantime.

Stop the running server before changing its configured port, including when a
reset would change that port. The GUI switches its connection to the new port
after saving, unless the current connection uses a temporary port. The separate
**Temporary connection port** control connects to an existing server without
changing the saved port or starting a new server. Vault filenames appear on the
unlock screen after connecting; the disconnected screen hides them. Recovery changes
require a server restart. **Settings → Browser & service** provides **Stop local service…** and **Start local service**. Stopping requires confirmation because it locks the vault, discards an open draft, and disconnects the CLI and extension. Closing the window leaves the existing server
and lock policy in effect.

The local service notifies the window of CLI/extension locks and vault
switches as they happen (older services are polled every two seconds) and the
old window contents are cleared. Status updates do not extend the inactivity
timeout.
Edits check the reviewed revision; if another client changes an item, refresh
and reopen it before editing again. Unsaved edits require an explicit discard
when navigating away.

A lost mutation reply may mean the server already saved the change. The GUI
records random operation IDs (never credentials) privately under
`desktop-operations/` in the application data directory and blocks new changes
until the outcome is reviewed, even after reopening the window. Use **Check
last change**; if the result remains unknown, unlock and inspect the vault,
then explicitly acknowledge it. This never retries the previous operation.

Open **Edit item** to add, replace, or remove an authenticator using a Base32 secret
or otpauth URI, enroll Duo Push/passcodes using a fresh activation link, or remove
Duo Push credentials. Each change has a confirmation and keeps the editor open
with the refreshed item. If you have unsaved item changes, use **Save changes &
continue editing** first. Save new items before configuring their authenticators.
Removing Duo Push retains passcodes; remove the authenticator separately to remove
those too.

Select an account in **Vault** to show/copy its OTP codes and review its Duo Push
requests. **OTP options** contains the per-operation clipboard timeout and TOTP
watch/copy controls. Codes remain hidden until requested, so selecting a HOTP
account does not consume a counter. Custom fields appear in the same account
details, with a Copy button for every field and individual Reveal/Hide controls
for secret fields. Reveals last up to 15 seconds and hide on focus loss or Escape.
Custom-field copying uses the saved clipboard timeout, reloaded before each copy.

Import/export, backups, audits, password history, and trash recovery are available
in **Tools**:

| Tools section | Available operations |
| --- | --- |
| History, trash & audit | Select an item and restore a saved password revision; restore or permanently purge trash; audit weak, reused, duplicate, stale, breached, or under-protected logins. |
| Import, export & backups | Preview CSV/JSON/Bitwarden imports, choose conflict handling, import into the current or a new vault, export plaintext CSV or portable JSON, and create/restore complete encrypted backups. |
| Vault security | Create key-file vaults, rekey, or delete a vault. |
| Advanced search | Combine text/name/username/URL/notes, type, authenticator, weak/stale, and sorting filters; open a matching item in Vault. |
| Browser integration | Register or update the native browser bridge and install the Linux application-menu shortcut. |
| CLI utilities | Check any reported operation ID without retrying it; save Bash, Elvish, Fish, PowerShell, or Zsh completions to a new file. |

Choose files using native open/save dialogs or enter their paths. Backup creation
uses a dedicated password (entered twice) or an existing external key. Restoring
a backup requires locking the current vault and creates a separate vault.
New key-based vaults, rekeying, and new-vault imports create a new external key
at a path that must not already exist. Deleting a vault requires its existing
credentials; lock first and select the intended filename on the Vault tab.
External keys are preserved by default during deletion.

Destructive operations, plaintext exports, import application, credential changes,
and enrollment show a review and confirmation step. A Duo request's card is its
review: **Approve** or **Deny** on the card answers it in one click. Editing the
form cancels that pending confirmation. Save or discard any unsaved item edits
before making changes in Tools. Untouched hidden custom fields remain unchanged;
renaming or changing the secrecy of a hidden field requires entering its
replacement value.

Selecting a Push-enrolled account fetches its current Duo requests once and shows
Approve and Deny controls in the account details, including Verified Push code
entry. Clicks are ignored for half a second after the listed requests change, so
a double-click or a click aimed at the previous list cannot answer a request you
have not seen. **Watch Duo requests in background** defaults to off. Enable it explicitly
for repeated polling; its interval and private desktop alerts appear while enabled.
Duo monitoring stays bound to its enrolled account while you change tabs, select
other accounts, or switch to a browser. Choose an interval from 3 to 60 seconds. A
global indicator offers **Review requests** and **Stop watching**. Selecting
another item never displays or approves the watched item's requests as its own.
Locking, changing connections, or changing the watched item's revision stops
monitoring. Automatic refresh pauses as soon as an unexpired request is available,
so its Approve/Deny controls and entered code stay stable while you review.
Responding or expiration resumes monitoring; **Fetch Push requests** explicitly
refreshes the list at any time. Confirmation also pauses refresh. Desktop alerts carry
no account details or codes, and never approve a request. Alerts depend on the
operating system's notification permissions: Linux uses `notify-send`, macOS uses
its notification service, and Windows uses an available registered PowerShell
sender. Unavailable or disabled notification delivery is reported in the GUI;
request polling continues.

TOTP refresh can optionally copy the first and each newly changed code once,
using its own timeout override or the saved clipboard timeout. It stops on focus
loss, Escape, navigation, or a vault lock. Neither TOTP nor Duo refresh keeps the
vault unlocked. HOTP advances only after an explicit show/copy
request; automatic refresh rejects HOTP. Codes and
individual revealed custom fields disappear after at most 15 seconds and do
not reappear if an in-flight reply arrives after focus loss.

Cloud settings include **Download comparison copy**, equivalent to `pm sync pull
--copy`: it downloads a separate vault with synchronization disabled.

**Tools → CLI utilities → Check operation outcome** accepts IDs from any client.
It reports committed, failed, pending, or uncertain outcomes without retrying the
operation or acknowledging a different pending operation in this window.
Completion export generates the same definitions as `pm completions`; choose a
new destination file, then configure your shell to load it.

Internal native-host/clipboard commands, generated developer artifacts, and
terminal output flags remain CLI-specific. See the [CLI, desktop and Android feature map](gui-cli-parity.md). Settings controls
persistent defaults; generation and authenticator controls provide one-time
overrides.

### Build and upgrade

Build from the repository root with a current stable Rust toolchain and a native
C/C++ build toolchain (MSVC on Windows):

```bash
cargo build --release --locked
```

The binary will be at `target/release/pm` (`target/release/pm.exe` on Windows).
Add that directory to your `PATH`, or use the full executable path in the
commands below. Release archives include a prebuilt binary and the extension;
keep the binary at a stable path before registering the browser native host.

Building does not change shell setup or browser native-host registrations.
Enable dynamic completions as described in [Shell Completions](#shell-completions),
and register the native host once with
`pm native-host install` as described in [Browser Extension](#browser-extension).

After upgrading, run the intended executable explicitly to update an existing
native host while preserving browser manifests and approved extension IDs:

```bash
./target/release/pm native-host update
```

Unix hosts link to that executable. Windows copies it to the registered host.
On Windows, recompile or replace `pm.exe` **before** running `native-host update`
with that new executable. Rebuilding afterward does not refresh the copied host.
Fully close the browser, including background processes, before updating the host.
Restart the server and reload the extension after upgrading. Open a new shell to
refresh dynamic completion registration. If using static completion files,
regenerate them with `pm completions` to pick up new commands.

If a Windows build fails with `failed to remove file ...\\target\\release\\pm.exe`,
a running process is holding the build executable open. Older native-host
launchers ran that executable directly. Fully exit the browser, including its
background processes, and stop the server with `.\target\release\pm.exe kill`.
Then build and replace the old launcher with the current copied host:

```powershell
cargo build --release --locked
.\target\release\pm.exe native-host update
```

Reopen the browser after updating. The copied Windows native host allows future
builds while the browser is open. A server started from `target\release\pm.exe`
still needs to be stopped with `pm kill` before rebuilding that executable.

## Android app

The native Android app manages its own encrypted local vault using the shared
Rust core. It works without a running desktop. Install or update the private APK
using the [Android build and installation guide](../android/README.md). Updates
must use the same signing key; install over the existing app to retain its data.
Android 9+ on ARM64/x86_64 supports the app and password autofill. Android 14+ is
required for the password/passkey credential provider. iPhone is not implemented.

### Get started on Android

Choose **Set up your vault** or **Add or restore a vault**. You can download from
your sync server, import an encrypted `.enc` file, create a vault, restore an
encrypted backup, or use an external key file. Choose **Open a local vault** to
select another vault already stored on this device. Unlock an existing vault
with its original password or key file; your server credential is separate.

For cloud setup, open **Settings → Cloud sync settings / download vault**. Enter
the full HTTPS server URL, including its port, and the credential issued for
this phone, then choose **Save connection**. Choose **List cloud vaults**, download
the desired vault, and unlock it. See [cloud setup and troubleshooting](cloud-sync.md).

### Find, edit, and recover items

Use the bottom navigation to switch between **Vault**, **Tools**, and **Settings**.
The vault list searches as you type, and the search box stays at the top while the
list scrolls. Swipe the type filters horizontally to see all eight types. Long-press
an item to copy its username, password, or code without opening it. **Select items**
lets you tap several items, then **Add tag…** or **Move to trash** (restore them from
**Tools → Deleted items**). Long-press the app icon for **Search vault** and
**Generate** shortcuts. Open an item to reveal or copy its password, one-time code,
notes, or custom fields. Passwords and notes start hidden; copy actions do not
require revealing them first. TOTP codes refresh for each copy and display an
expiry countdown when shown. HOTP generation is an explicit action that advances
the saved counter.

The details screen also lists attachments: tap one to save a copy, or use
**Add attachment** to store a file of up to 5 MiB.

Choose the floating **Add item** button or **Edit item** for typed editing, multiple website addresses,
notes, comma-separated tags, the favorite mark, and custom fields. A new item
starts with the fields suggested for its type, such as **Expiry** and **Security
code** for a payment card; blank suggestions are not saved. The **★ Favorites**
filter chip lists starred items, the tag picker below the chips lists items with
one tag, and the star at the top of an item's details screen marks or unmarks it. **Tools →
Advanced search** can require several tags or favorites only. **Save item** and **Cancel** stay at the bottom while
the form scrolls. Back and Cancel ask before discarding changed drafts. A failed
save keeps your draft so you can correct the problem. Switching to another app
keeps the screen and any draft until **Lock after leaving the app** (Mobile
settings, 30 seconds by default; 0 locks at once) runs out. Rotating the phone
keeps the screen. Turning off the screen, locking, or the inactivity timeout
clears sensitive views; a draft is not a saved recovery copy.

**Tools** groups generation, advanced search, vault health, vault credentials,
deleted items, files/backups, sync controls, and mobile preferences. Password
history and authenticator/Duo controls are on the item's details screen. File
operations use Android's document picker with a 16 MiB transfer limit. Returning
from the picker requires unlocking again for vault exports. Restore a complete
encrypted backup for history/trash/authenticator/passkey preservation; plaintext
CSV has fewer fields and cannot export vaults containing passkeys.

### Fingerprint unlock and autofill

After an original password/key-file unlock, open **Settings → Biometric unlock**
and choose **Enable biometric unlock**. The page shows whether it is enabled for
this vault on this device. The home and unlock screens also show its status.
Enrollment is optional and local to the phone. Keep the original password/key
for recovery after a credential change, new fingerprint enrollment, or new phone.

Open **Settings → Enable password autofill** and select Password Manager in
Android's settings. Chrome may also need its autofill preference changed to use
other providers. On Android 14+, use **Enable password and passkey provider**
for Credential Manager. These are separate system settings.

Tap a site's username/password field and choose the Password Manager suggestion.
The compact unlock sheet offers configured biometrics automatically. After a
completed fill, another explicit account selection on the same site can reuse
that unlock for up to five minutes; the configured inactivity timeout can end
it sooner. Changing sites/callers, cancelling, opening management, locking,
screen-off, or restarting the process revokes that grant. Website-matched TOTP
entries can fill recognized verification-code fields or offer **Copy verification
code and return**. The vault must already contain that site's authenticator.

When Android offers to save a login, the sheet first checks the vault: a login
that already holds the same username (ignoring case) and password is left
unchanged instead of saved twice. Otherwise choose **Save new login** or update a
saved account with the same username. Change-password forms often hide the
username; then every saved account for the site may be updated, and when the
site has only one, updating it is the suggested action. The saved username is
kept.

On Android's legacy Chrome autofill API, the page port may be unavailable. The
exact-hostname picker then requires explicit login/address selection and shows
saved nonstandard ports; it cannot verify the current page port. See the
[origin and browser restrictions](../android/README.md#setup). Native-app matching
uses the app's package and signing certificate.

Payment-card and identity forms (checkout, address, and contact forms) offer
**Fill a saved card** or **Fill a saved identity** when the screen has no login
fields. Choosing it opens the sheet: unlock if needed, then pick the card or
identity explicitly; nothing is filled without that choice, and no card or
identity data reaches Android before it. Fields are recognized from Android
autofill hints, the page's `autocomplete` attributes, and field names and labels,
using the same rules as the browser extension. Cards fill the number, cardholder
(the item's username), and **Expiry**/**Security code** fields; an `MM/YY` expiry
also fills separate month and year fields. Identities fill their name (split into
first and last names when needed) and fields such as **Email**, **Phone**,
**Address**, **City**, and **ZIP**. Email and phone fields alone, as on many
login and search forms, are not treated as identity forms. Dropdown fields are
not filled.

### Android preferences

Open **Settings → Mobile settings**. Tap a preference for its explanation, units,
default, supported range, and validated edit dialog. Save applies that preference;
Cancel keeps its previous value. Light/dark appearance follows Android, and the
screens support larger system text.

| Preference | Default | Supported values / meaning |
| --- | --- | --- |
| Lock after inactivity | 5 minutes | 15 seconds–24 hours; leaving management or turning off the screen also locks. |
| Clear copied secrets after | 30 seconds | 1–300 seconds; verification-code expiry may shorten it. Cleanup is best effort and never clears a newer clipboard value. |
| Previous passwords to keep | 10 per item | 0–1,000; zero stops keeping history on future password changes. |
| Deleted-item retention | Off | 0–36,500 days; zero disables age-based purging. Apply it explicitly from Deleted items. |
| Generated password length | 24 characters | 1–255 characters; existing passwords are unchanged. |
| Generated passphrase length | 6 words | 1–64 words. |

These device-local preferences are independent of desktop `pm config` and are
not synchronized with the vault. Generator character groups and separators are
chosen in the generator. Android stores vaults, checkpoints and
`mobile-settings.json` in private app storage; its server token is protected by
Android Keystore. Desktop environment-variable path overrides do not configure
the installed Android app.

See the [mobile acceptance checklist](mobile-implementation.md) for measured
coverage and remaining interactive/device checks. Successful synthetic tests do
not establish live Google MFA, Duo, or Android 14+ passkey-provider acceptance.

## Usage

The commands below use the desktop/CLI service. For native phone controls and
device-specific defaults, use [Android app](#android-app).

### Create Your First Vault

```bash
pm new
pm unlock
pm add --name "Example account" --username alice --url https://example.com
pm view
pm lock
```

`pm new` and `pm unlock` start the background server when it is not already
running. `pm new` prompts twice for a master password, creates an empty vault, and leaves
it locked. New master passwords must contain at least 14 characters and pass a
predictability check. Use `pm unlock` before adding or reading entries.

For a vault protected by an external key instead:

```bash
mkdir -p ./keys
pm new --key ./keys/vault.key
pm unlock --key ./keys/vault.key
```

The key's parent directory must exist. The new key path must not already exist
and must be outside the application data directory. Keep the key separately from the vault. `pm init` and `pm create` are
aliases for `pm new`. Creating another vault locks the currently open vault.

### Start the Server

```bash
pm start
```

The server creates a new private session token on every start. CLI and
native-messaging clients read it from the protected application data directory;
it is not displayed to the user or stored in the extension. A clean shutdown
removes the token file. Before any command is sent, the server proves possession
of that token with a fresh challenge. Commands and responses are then protected
with direction-specific XChaCha20-Poly1305 session keys.

Committed mutations with uncertain durability return response code `5`; the
native bridge marks these outcomes as uncertain so browser controls require
review before retrying. Existing response codes and framing are unchanged.
Older clients reject code `5` as an unknown error instead of reporting success;
upgrade the CLI and native host together with the server.

Check the server with `pm status`; stop it with `pm kill`. The server holds one
unlocked vault at a time. Lock it before unlocking a different vault.
Only one server can own an application data directory, including when different
ports are requested. Its private `server.lock` file stays in place after shutdown;
the operating system releases the lock when the server exits.

### Generate a Password

```bash
pm genpass --length 20 --copy
pm genpass --length 24 --exclude-ambiguous --no-symbols
pm genpass --passphrase --words 7 --separator "."
```

Character classes can be disabled with `--no-uppercase`, `--no-lowercase`,
`--no-digits`, and `--no-symbols`; replace the default symbol set with
`--symbols`. Lengths and passphrase word counts must be at least one, and at
least one non-empty character class must remain. Character-set flags cannot be
combined with passphrase generation.

### Add a New Entry

```bash
pm add --name "github.com" --username "user@email.com" --generate-password --copy
```

Login items are the default. Repeat `--url` to associate several sites with the
same login; the first URL is primary and every additional URL participates in
search and browser-extension matching:

```bash
pm add --name "Example account" --username alice \
  --url https://example.com --url https://accounts.example.net
```

Other encrypted item types use the same compact field model: `--name` is the
display name, `--username` is an optional account/owner identifier, the hidden
password prompt stores the primary secret, and `--notes` stores supporting
details. Identity items have no primary-secret prompt.

```bash
pm add --type secure-note --name "Alarm code"
pm add --type payment-card --name "Personal Visa" --username "Alice Example"
pm add --type identity --name "Shipping identity" --username "alice@example.com" --notes "Home address"
pm add --type wifi --name "Office Wi-Fi" --username WPA3
pm add --type software-license --name "Design app" --username "Alice Example"
pm add --type ssh-key --name "Production SSH" --username deploy
pm add --type api-secret --name "Deployment API" --username key-id-123
```

For secure notes the primary secret is the note body; for cards it is the card
number; for Wi-Fi it is the network password; and for licenses, SSH, and API
items it is the corresponding key or secret. These values are read through the
hidden prompt and handled like login passwords.

Add searchable custom fields with `--field NAME=VALUE`. For sensitive values,
use `--secret-field NAME`; the value is read through a hidden prompt and is not
searched or displayed in ordinary listings (field names remain visible):

```bash
pm add --name "Hosting" --field environment=production --secret-field recovery-code
```

### View All Entries

```bash
pm view
```

Listings can be sorted by stable ID, name, creation time, modification time, or
password age. Add `--descending` to reverse the selected order:

```bash
pm view --sort name
pm view --sort modified --descending
pm view --sort password-age
```

Date sorting compares actual timestamps across time zones and supported formats.
Entries with unrecognized dates sort first in ascending order and last in
descending order.

### Search and Filter Entries

Search across names, usernames, all associated URLs, notes, custom-field names,
and non-secret custom-field values (passwords and secret field values are never
searched):

```bash
pm search github
pm search --username alice --url github.com
pm search work --name git --notes account
pm search --type wifi
pm search --totp --sort name
pm search --weak --sort password-age
pm search --stale-days 365 --sort password-age
pm view --tag work --favorites
```

### Tags and favorites

Tags organize items without changing how they are matched or filled. Each item
can have up to 32 tags of up to 64 bytes; tags cannot contain commas, and
duplicates that differ only by case are merged. `--tag` (repeatable) on `list`
or `search` lists only items carrying every given tag, and `--favorites` lists
only starred items. The general search term also matches tags.

```bash
pm add --name "AWS console" --url https://aws.amazon.com --tag work --tag cloud --favorite
pm update --id 3 --add-tag finance --remove-tag old --favorite
pm update --id 3 --clear-tags --unfavorite
```

A vault that uses tags or favorites is saved in vault document schema 3. Older
releases refuse to open it rather than silently discard the new data, so update
every device (desktop, CLI, and Android) before relying on tags in a synced
vault. The first save that needs the new schema says so once: the CLI prints a
warning, the desktop app shows a banner until you dismiss it, and Android adds it
to the save message. Removing every tag, favorite, and attachment returns the
vault to the previous schema.
Sync conflict review lists tags and favorites as their own **organization** field.

### SSH agent

On Linux, macOS, and Windows the local service can act as an SSH agent, so `ssh`, `git`,
and `ssh-keygen -Y sign` use keys stored in your vault without key files on
disk. It is off by default:

```bash
pm config --ssh-agent true
pm kill && pm start          # the agent starts with the service
eval "$(pm ssh-agent)"       # sets SSH_AUTH_SOCK for this shell
ssh-add -l                   # lists keys from the unlocked vault
```

Add the `eval` line to your shell profile to use it everywhere.

On Windows the agent listens on a named pipe for the built-in OpenSSH client
(`C:\Windows\System32\OpenSSH\ssh.exe`). In PowerShell:

```powershell
pm config --ssh-agent true
pm kill; pm start
pm ssh-agent | Out-String | Invoke-Expression   # sets SSH_AUTH_SOCK for this session
ssh-add -l
```

To use it in every new terminal, store the variable once with
`setx SSH_AUTH_SOCK "\\.\pipe\pm-ssh-agent-…"`, using the exact pipe name
`pm ssh-agent` prints. It does not replace Windows' own **OpenSSH Authentication
Agent** service (`\\.\pipe\openssh-ssh-agent`); the two can run side by side,
and `SSH_AUTH_SOCK` picks which one `ssh` uses. Git for Windows uses its own
bundled `ssh`, which cannot reach a named pipe, so point Git at the Windows
client: `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`.

Keys are off
until you enable them: give the SSH-key item a custom field named **SSH agent**
(the desktop SSH-key template includes it) with the value

- `on` — serve the key while its vault is unlocked, or
- `confirm` — ask before every signature.

The primary secret must be an OpenSSH **Ed25519** private key
(`-----BEGIN OPENSSH PRIVATE KEY-----`, as written by `ssh-keygen -t ed25519`).
For a passphrase-protected key, store the passphrase in a secret custom field
named **Passphrase**; it is decrypted once and kept in memory only while the
vault stays unlocked. RSA and ECDSA keys are not served.

```bash
pm update --id 5 --field "SSH agent=confirm"
```

With `confirm`, the desktop app shows **SSH key requested** naming the key and
the destination, with **Allow once** and **Refuse**; `pm status` lists the same
requests and `pm ssh-agent approve ID` or `pm ssh-agent deny ID` answers them.
Unanswered requests are refused after 30 seconds. The destination comes from
OpenSSH's session binding: the host's name from `~/.ssh/known_hosts` when it is
stored unhashed, otherwise its key fingerprint. Tools that do not bind a session
(such as `ssh-keygen -Y sign`) show "an unknown host".

Requests relayed through agent forwarding (`ssh -A`) from another machine are
always refused, so a server you log in to cannot use your keys. Keys appear only
while their vault is unlocked; locking, the inactivity
timeout, or a screen lock leaves the agent with no identities. Agent use does not
count as vault activity, so it never keeps a vault unlocked.

The agent only lists keys and signs; `ssh-add` cannot add or remove keys
through it. Any process running as your user can ask it to sign with an `on`
key while the vault is unlocked, as with OpenSSH's own agent; use `confirm` for
keys that need more protection. Its socket is owner-only (mode 0600 in a 0700
directory), normally in `agent/ssh-agent.sock` under the data directory, or in a
private directory under `$XDG_RUNTIME_DIR` (or the temporary directory) when
that path would be too long for a socket. On Windows the pipe
`\\.\pipe\pm-ssh-agent-` plus a tag derived from the data directory admits only
your user account and refuses connections from other machines; the agent does
not start if another process already holds that name. If the agent cannot start,
`pm status` reports why.

### Attachments

Attach small files such as recovery-code PDFs, scanned documents, or key files
to any item except a passkey. Attachments are encrypted inside the vault, so
encrypted backups, sync, and portable JSON exports carry them automatically.
Each attachment can be up to 5 MiB, and a vault holds at most 25 MiB of
attachments (including items in the trash). An item can have up to 32
attachments with unique names; names cannot contain `/`, `\`, or control
characters.

```bash
pm attachment add --id 4 --path ~/Documents/recovery-codes.pdf
pm attachment add --id 4 --path scan.png --name "Passport scan.png"
pm get --id 4                       # lists attachments and their sizes
pm attachment save --id 4 --name recovery-codes.pdf --path ~/Downloads/codes.pdf
pm attachment remove --id 4 --name recovery-codes.pdf
```

Saved copies are created with owner-only permissions and never replace an
existing file unless you pass `--force`. Removing an attachment is permanent;
restore an encrypted backup to recover it. In the desktop app, open an item and
use **Add attachment…**, **Save as…**, or **Remove…** (which asks for
confirmation). On Android, the item's details screen lists attachments; tap one to
save a copy through the system file picker, or choose **Add attachment**.
Portable JSON stores attachment content as base64; plaintext CSV omits it.
A vault with attachments uses vault document schema 3, like tags.

The general search term matches any non-secret field. Field-specific filters are
combined, so every supplied filter must match. Matching is case-insensitive.
The `--type`, `--totp`, `--no-totp`, `--weak`, and `--stale-days` filters work with both
`list` and `search`. Supported types are `login`, `secure-note`,
`payment-card`, `identity`, `wifi`, `software-license`, `ssh-key`, and
`api-secret`. TOTP and weakness filters apply across item types; `--no-totp`
also includes non-login items without authenticators. Add `--type login` to limit
these filters to accounts. Weakness filtering ignores items with no primary
secret and selects zxcvbn scores of 0–2.

Vault writes enforce the same 128 MiB encrypted-file limit used during unlock.
An operation that exceeds the limit fails before replacement and rolls back its
in-memory changes.

### Get a Password

```bash
pm get "github.com"
```

Select an item by name (exact, or ignoring case when only one item matches) or
with `--id ID` from `pm view`. When several items share a name, the command stops
and lists their IDs instead of guessing. `--entry-name NAME` is an equivalent
spelling of the positional name.

`get` prints item details with the password (or card number, key, …) and secret
custom fields hidden, using labels for the item's type. It never touches the
clipboard unless you add `--copy`, which copies the password and clears it after
the clipboard timeout. Use `--password-only` to print just the password for a
pipe. Use `--reveal-secrets` to display secret custom-field values, or `--field
NAME` to print one custom field by its case-insensitive name; with `--copy`, that
field is copied instead of printed. Copying requires a nonzero clipboard timeout
and reports clipboard failures. `--json` returns structured data and respects the
selected reveal option.

```bash
pm get github --copy
pm get --id 3 --reveal-secrets
pm get --id 3 --field recovery-code
pm get --id 3 --field recovery-code --copy
```

### Update an Entry

```bash
pm update "github.com" --name "New Name"
```

Change the primary secret through a hidden prompt, or generate a replacement:

```bash
pm update --id 3 --password
pm update --id 3 --password --generate-password
```

Item types and URL associations can be changed without altering the secret:

```bash
pm update --id 3 --type login
pm update --id 3 --add-url https://login.example.net
pm update --id 3 --remove-url https://old.example.com
pm update --id 3 --clear-urls
pm update --id 3 --field environment=staging
pm update --id 3 --secret-field api-token
pm update --id 3 --remove-field environment
pm update --id 3 --clear-fields
pm update --id 3 --add-tag work --favorite
```

### Delete an Entry

```bash
pm delete "github.com"
```

Deletion moves the entry and its password history into encrypted trash. Manage
deleted entries with:

```bash
pm trash
pm restore --id 1
pm purge --id 1
pm purge --all
```

Permanent CLI deletion (`pm purge` and `pm delete --vault`) asks you to type
`yes` before continuing. In scripts or other noninteractive sessions, pass
`--yes` explicitly. Ordinary item deletion still moves an item to recoverable trash.

`restore` and `purge --id` use the **stable entry IDs** shown by `pm trash`.
These IDs remain unchanged when other trash items are restored or purged.
Purging is permanent.

Trash retention can optionally purge old items whenever a vault is unlocked.
It is disabled by default; configure a number of days to enable it.

Active entry IDs are persistent: deleting or restoring a different entry does
not renumber them. Restoring a trashed entry also restores its original ID, and
imports receive new local IDs instead of trusting IDs from the source file.

To permanently delete an entire vault, supply its password or key:

```bash
# Prompt for the vault's master password
pm delete --vault

# Select a vault explicitly when multiple vaults exist
pm delete --vault --vault-file VAULT_ID.enc

# Delete a key-based vault and its key file
pm delete --vault --key ./keys/vault.key

# Delete the vault but intentionally retain a shared or backup key
pm delete --vault --key ./keys/vault.key --keep-key
```

Whole-vault deletion cannot be restored. A supplied key file is removed only
after it has successfully opened the matching vault and that vault has been
deleted. Deletion uses `--vault-file`, then the configured default vault, or the
only vault when exactly one exists. It never searches vaults by password.

### Password History

Changing a password retains previous passwords inside the encrypted vault. The
default limit is ten revisions and can be configured or set to zero to disable
new history. History output shows timestamps, not password values:

```bash
pm history "github.com"
pm restore-password "github.com" --revision 1
```

Revision `1` is the newest previous password. Restoring a revision places the
current password back into history, so the operation can be reversed.

### Audit the Vault

```bash
pm audit
pm audit --stale-days 365 --require-totp
pm audit --breaches
```

The audit assigns a health score and checks active logins for weak passwords,
reused-password groups, and duplicate site/username combinations. Optional
checks report passwords older than a chosen number of days and accounts without
TOTP. Reports identify affected entries but never print their passwords.

`--breaches` performs an opt-in Pwned Passwords range check. It sends only the
first five characters of each password's SHA-1 hash, requests padded responses,
and never sends a password or complete hash. The ordinary audit remains fully
offline. Network failures retain both local results and successful
breach findings, identify entries with unchecked breach status, and return a
failure exit status to indicate an incomplete audit. Up to eight requests run
concurrently with a 15-second request timeout and a four-minute overall deadline.

### TOTP and HOTP Authenticators

Paste either a Base32 TOTP secret or a complete `otpauth://totp/...` or `otpauth://hotp/...`
URI into the hidden setup prompt:

```bash
pm totp set "github.com"
pm totp show "github.com"
pm totp show "github.com" --watch
pm totp show --id 3 --copy --copy-time 20
pm totp remove --id 3
```

TOTP output includes the current code and its remaining validity. Raw Base32
secrets use the standard SHA-1, six-digit, 30-second configuration; OTPAuth
URIs can specify their algorithm, digits, and period. Correct system time is
required for valid codes. Entry and trash listings mark configured accounts
with an authenticator indicator without revealing their secrets. The existing
`--totp`, `--no-totp`, and `--require-totp` options include HOTP authenticators too.

Use `pm totp show --watch` with an entry selector to keep the code and countdown
updated until Ctrl+C or the vault locks. Add `--copy` to copy each new code once;
`--copy-time` still controls clipboard clearing. Watching does not extend the
vault's auto-lock deadline. In a terminal the countdown updates in place; redirected
output and `--json` emit one line per update. HOTP cannot be watched and attempting
to do so does not consume a counter.

The countdown follows the configured period's Unix-time boundaries (normally
every 30 seconds). Duo Mobile may start its displayed 30-second countdown when
you reveal a passcode, so its refresh can appear 10–20 seconds later even with
the same secret and synchronized clocks. See [Duo's explanation of its countdown](https://community.cisco.com/t5/duo-mobile-app/delay-in-authenticator-code/td-p/4884436).
If the actual codes are consistently shifted, check automatic time on both devices
and that both authenticators use the same secret, algorithm, digits, and period.

HOTP URIs must include an unsigned `counter` parameter, for example
`otpauth://hotp/Example?secret=BASE32_SECRET&counter=0`. HOTP supports SHA-1,
SHA-256, or SHA-512 and six to eight digits. Each `pm totp show` or browser
authenticator selection generates the code at the saved counter and atomically
saves the next counter in the encrypted vault **before returning the code**.
HOTP output shows the consumed counter rather than a countdown. JSON and browser
API responses represent the counter as a decimal string so the
full unsigned 64-bit range survives JavaScript parsing. Request codes
when you intend to use them: repeatedly generating unused codes can move beyond
the provider's acceptance window. Restoring an older backup or importing an old
export also restores its counter and may require provider resynchronization.

#### Duo passcode enrollment

Use a fresh Duo enrollment link for a separate device, then paste either the
`https://m-….duosecurity.com/activate/…` setup link or its `duo://…` activation
link into the hidden prompt:

```bash
pm totp duo "work"
pm totp show "work" --copy
```

Duo enrollment defaults to **HOTP**. If your organization accepts time-based
codes, select TOTP explicitly with `pm totp duo "work" --mode totp`.
The link does not identify which passcode type your organization accepts; there
is no automatic fallback. The command saves the authenticator without generating
or consuming its first HOTP code. Enrollment refuses to overwrite an existing
authenticator; remove it explicitly first if replacing it.

This is experimental compatibility with Duo's undocumented mobile activation
endpoint, based on the [duo-hotp protocol implementation](https://github.com/WillForan/duo-hotp).
It enrolls for **passcode generation only**. Push credentials are discarded;
use `pm duo enroll` below for push support. Keep an official Duo Mobile device
as a fallback while testing this experimental client. Organizational settings can reject this enrollment
or its passcodes. Activation links are consumed by enrollment and can expire;
an already-used link does not export an existing phone's secret or HOTP counter.
If enrollment succeeds but saving fails, or the request times out, check your
Duo device enrollment before trying again with a fresh link.

At sign-in, Duo may automatically send a push for an enrolled device. Choose
**Other options → Duo Mobile passcode** for the device enrolled through `pm`,
then enter the code from `pm totp show "work"`. Available sign-in
methods are controlled by your organization's [Duo authentication policy](https://duo.com/docs/policy#authentication-methods).
If the passcode method is missing, an administrator must check whether it is
allowed for your account and application. Enrollment through `pm` cannot change
those policies.

The importer restricts setup and activation requests to HTTPS Duo hosts, bounds
responses, and keeps links and returned secrets out of diagnostics. The passcode-only command stores the OTP configuration in the encrypted vault;
no plaintext secret files are created.

Enrollment failures identify the setup-page or activation step and show the HTTP
status and Duo error code when available. Known rejection reasons, parameter
names, and fixed topic hints from error messages are displayed, while arbitrary
response text stays private. Topic hints report what Duo's response mentions;
they do not establish the rejection's cause. If reporting
a failure, share this error message rather than the activation link or response
body. Restart the server after rebuilding to load updated enrollment behavior.
Activation fields are sent as a URL-encoded POST form with the matching content
type; only `customer_protocol=1` is sent in the query string.
HTTP 403 / Duo code 40301 during mobile activation does not identify the root
cause by itself. The compatibility profile uses the form fields and version
metadata inspected in the [official Android 4.123.0 app](https://dl.duosecurity.com/DuoMobile-latest.apk),
with a header that also identifies PasswordManager and its lack of Duo certificate
pinning. HTTPS certificate validation remains enabled. Mobile security measurements
and hardware attestation are not available and are not fabricated; an organization
requiring them may reject enrollment. Client compatibility and enrollment
restrictions both need to be considered. Switching
between HOTP and TOTP cannot resolve a failure before Duo returns the OTP secret.

#### Duo Push

Use a **fresh activation link** for push enrollment. The earlier `pm totp duo`
command discarded the private signing key, so its device cannot be upgraded in
place. Enroll a new device in Duo and replace the local authenticator:

```bash
pm duo enroll "work" --replace
pm duo watch "work" --interactive
# Or decide once, without copying an ID when exactly one request is pending:
pm duo approve "work"
pm duo deny "work"
# With multiple requests, select the exact ID printed by requests/watch:
pm duo requests "work"
pm duo deny "work" --request REQUEST_ID
```

Interactive watch displays each request and prompts in the same terminal: type
`a` then Enter to approve, `d` then Enter to deny, Enter to skip, or `q` then Enter
to quit. This choice confirms the displayed request; no second confirmation is
needed. A skipped request is not prompted again unless its context changes or it
disappears and returns. Verified Push asks for the login-page code after `a`;
Enter at the code prompt cancels the decision and ends monitoring. Use
`pm duo watch "work" --notify` for passive monitoring instead.
One-shot `approve`/`deny` still display the request and ask you to type the action
to confirm. Omitting `--request` with multiple pending requests fails without
answering any of them.

The enrollment prompt hides the activation link. Push credentials (the Duo host,
account and device identifiers, and RSA signing key) are stored inside the
**encrypted vault**, alongside the passcode authenticator. Push enrollment uses
Duo's `use_totp` response when present, otherwise HOTP; `--mode` overrides this.
`--replace` replaces the local OTP and push enrollment after the new activation
succeeds. It does not remove the old device from Duo. An error after activation
may have consumed the link; check device enrollment before retrying.

Select this device at login, then check or monitor requests. In the browser
extension, a detected Duo challenge opens a separate **Duo Push** window when a
pending request is available. Review the application, account and location, then
click **Approve** or **Deny** once. Verified Push requires typing the code from
the login page into the window; the extension never extracts or supplies that code.
**Dismiss** closes the window without answering and suppresses that same request
on the current page. Closing the login page, navigating away, locking the vault
or disconnecting the native host invalidates the window.

Attach Duo enrollment to the saved login whose URL matches the sign-in site.
Embedded Duo frames use the parent site's matching logins. A login selected in
the credential chooser, or recognized during credential submission, is remembered
for five minutes in the same tab to handle redirects to HTTPS Duo-hosted pages.
A Duo-hosted challenge can also find enrollments for its exact HTTPS Duo server,
including when SSO used a different saved login. Enrollment credentials and
account summaries stay in the background; this lookup does not release passwords.
Automatic detection polls about every five seconds while the challenge is visible,
for up to five minutes. Detection uses visible challenge text; unusual or localized
pages may need the manual **desktop account → Duo Push** panel instead. Requests and
decisions stay inside the extension; the website receives no request details.
Rebuild and restart the server, update the native host, and reload the extension
after updating, so login summaries include Duo enrollment availability.

In the desktop app, select the enrolled item and use its **Duo Push** panel for
manual request checks or monitoring.

On Android, **Duo Push requests** at the top of the vault list (or **Check Duo
Push requests** on an enrolled item) shows every pending request for your
enrolled accounts on one screen. Tap **Approve** or **Deny** on the request; the
buttons wake after a short pause, and the code field appears only for Verified
Push. **Check again** refreshes the list after you start a login. Monitoring polls while this
item is open; CLI monitoring runs until Ctrl+C, an error, or vault lock. It does
not register with Android/iOS notification services. `--notify` provides passive
desktop alerts using `notify-send`, if available. Polling does not reset auto-lock.

Each approval or denial requires an explicit choice after reviewing the
application, account, location, expiry and request ID. Approve only a login you
started. Verified Push requires you to type the code shown on the **login page**;
no code is extracted from the push payload or automatically supplied. Immediately
before responding, the server fetches the exact request again and checks that
its context and requirements have not changed. Expired or changed requests cannot
be answered using an earlier review. Review tokens are keyed and valid only for
the current unlock session; locking and reopening the vault requires a new review.
Duo network waits do not hold the vault lock. An enrollment that finishes after
locking, switching vaults, or changing its item is not saved; the activation link
may already have been consumed. A decision timeout has an unknown outcome;
check the login before retrying. Requests that require device biometrics, GPS,
proximity, passwordless device authentication or key rotation cannot be approved
by this client. Unknown verification requirements also block approval. Denial
remains available for supported pending-request shapes.

Duo Push uses an undocumented mobile API and may be rejected by organization
policy or future server changes. HTTPS validation is enabled, and requests use
RSA-SHA512 signatures through the AWS-LC backend also used by rustls. This client
cannot provide mobile hardware attestation.
An administrator must permit a compatible authentication method; enrollment does
not change organization policy.

`pm duo remove "work"` removes local push credentials and retains
passcodes; remove the device separately in Duo. Push credentials follow trash,
restore and purge operations. Encrypted backups and **plaintext portable JSON
exports** include them; CSV exports omit them, just as they omit OTP secrets.

Restoring an encrypted backup on another computer preserves the same Duo device
identity. Both copies should be able to fetch the same pending Push requests when
their vaults are unlocked and monitoring is enabled. Responding on either copy
resolves that request; it does not create a second enrolled device. Simultaneous
use on two computers has not been tested against live Duo.

Approving or denying a Push request does **not** advance the local HOTP counter.
The Verified Push number from the login page is separate from HOTP. Generating
an HOTP passcode advances only that vault copy's counter, and backup/restore does
not synchronize later changes between computers. Use one active copy for HOTP
passcode generation. Use fresh links for separate enrollments, and avoid
simultaneous enrollments for the same item.

RFC 4226 specifies a 128-bit minimum secret and recommends 160 bits. Some
providers, including GitHub, issue 80-bit secrets for compatibility. Provider
secrets from 80 bits upward are accepted, with a warning below 128 bits;
shorter secrets remain rejected.

Authenticator configurations are stored only inside the encrypted vault. They
remain attached to an entry in trash and after restoration, and are securely
removed when that trash entry is purged. Plaintext CSV exports omit authenticator
configurations and richer item metadata. Portable JSON exports preserve active
item metadata, history, and TOTP configurations; use an encrypted backup when
trash and the complete recovery state must also be preserved.

### Lock/Unlock

```bash
pm lock
pm unlock --timeout 15m
```

With several vaults, choose one by name. `pm vaults` lists each vault's
device-local name (shared with the desktop app) and its `.enc` file; it works
without a running server and does not decrypt anything. A key file finds its own
vault, so `--key` needs no selection:

```bash
pm vaults
pm vaults --rename 0123456789abcdef0123456789abcdef.enc --name Work
pm unlock --vault Work
pm unlock --key ./keys/vault.key
pm vaults delete Work          # permanently delete a whole vault (asks first)
```

`pm --json vaults` returns one object per vault, `{"file": "….enc", "name":
"Work", "default": true}`; earlier versions returned only the `.enc` file names,
so scripts should read `.data[].file`.

`--vault` accepts a name (ignoring case) or one `.enc` filename from the
application data directory; `--vault-file` is the older spelling. With several
vaults and no selection or default, `pm unlock` says so before asking for a
password. Scripts can supply the password on standard input:
`printf '%s\n' "$PASSWORD" | pm --password-stdin unlock --vault Work`.
Missing files, unreadable keys, invalid headers, unsupported versions, and invalid
authenticated records produce specific errors. A wrong password and modified
ciphertext cannot be distinguished by authentication alone. Omitting the selector
retains automatic vault discovery.

The timeout is based on inactivity: each authenticated vault operation resets it;
passive status polling does not.
Durations accept seconds or `s`, `m`, `h`, and `d` suffixes. New configurations
default to 15 minutes; a value of `0` disables inactivity locking.
After five wrong passwords in a row, the local service makes you wait before the
next attempt: one second, then two, doubling up to five minutes. This applies to
the CLI and the desktop app alike, and to deleting a vault
with its password. A correct password resets the count. Refused attempts are not
checked, so waiting is the only way through.

Locking clears vault memory without depending on storage writes. If automatic
clipboard cleanup fails, `pm status` reports a warning and the extension shows a
warning badge; the vault itself is already locked.

The server also locks on operating-system screen-lock and suspend/resume events,
even when the inactivity timeout is zero. Linux listens to logind lock hints and
sleep signals, plus GNOME/KDE/freedesktop screensaver notifications. It holds a
logind delay inhibitor while preparing for suspend, releasing it after vault
cleanup. When launched in a systemd user scope outside a login session, it uses
logind's automatic lookup of the user's display session to monitor lock hints.
Standalone `hyprlock`, `swaylock`, `i3lock`, and `xsecurelock` processes
owned by the same user are also checked every 250 ms, covering lockers that do
not publish a D-Bus hint. Windows uses session and power notifications; macOS uses
workspace sleep/session notifications and the distributed screen-lock notification.
Unavailable event sources appear in `pm status` and the browser status warning;
Linux connections retry automatically. Inactivity locking remains available.

### Change the Master Password or Key File

Unlock the vault first, then run:

```bash
# Prompt for and confirm a new master password
pm rekey

# Or create and switch to a new external key file
pm rekey --key /secure/removable-media/replacement.key
```

New vault, rekey, import, and backup passwords must contain at least 14
characters and pass a predictability check.

Existing key files must be regular files no larger than 1 MiB. Generated key
files contain 32 random bytes.

New key files must be outside the application data directory, so copying the
encrypted vault does not also copy its key. Relative paths are resolved from
the directory where `pm` is run.

Rekeying atomically replaces the ciphertext at the same random vault filename.
There is one vault file throughout the operation. An old key file is left in place,
but the successfully rekeyed vault no longer uses it. If replacement completes but
directory synchronization fails, the new key remains active and the command
reports that durability is uncertain. Keep both credentials until the operation
succeeds durably; after an interruption, verify which credential opens the vault.
Historical backups and filesystem snapshots still use their original credentials.

### Import/Export

Relative import, export, and backup paths are resolved from the directory where
you run the CLI, independently of where the background server was started.
Exports and backups must be saved outside the application's data and configuration
directories. `--force` cannot override this protection. CSV exports reject cells
that could be interpreted as spreadsheet formulas, including formula-leading
passwords; export to a `.json` file to preserve those values exactly. The rejected
CSV export leaves any existing destination unchanged.

For a complete backup that preserves entries, stable IDs, item types, additional
URLs, custom fields, password-age metadata, password history, trash, TOTP/HOTP
configurations and counters, and Duo Push credentials, use the encrypted backup
commands:

```bash
# Prompts for and confirms an independent backup password
pm backup create --path vault.pmbackup

# Existing files are protected unless replacement is explicit
pm backup create --path vault.pmbackup --force

# The server must be running with the current vault locked
pm lock
pm backup restore --path vault.pmbackup
pm unlock --vault-file ID_PRINTED_BY_RESTORE
```

Use `--key /absolute/path/to/backup.key` on both commands to use an existing
external key file instead of a password. Keep that key separately; it is not
embedded in the backup. Restore writes a new vault with an independent identity
and prints its filename. Select that ID when unlocking it with the backup
credential. Existing vaults are preserved; restoration does not infer a
destination from a matching password. `--force` applies to backup creation,
where it explicitly replaces an existing backup file.

Backup files use a versioned format and XChaCha20-Poly1305 authenticated
encryption with a fresh nonce and, for passwords, a fresh Argon2id salt. They
are written atomically with private file permissions. The format contains all
encrypted recovery material and is limited to 128 MiB when creating and restoring.

For interoperability with other password managers, plaintext import/export is
still available:

```bash
pm import --path backup.csv --new
pm export --path backup.csv          # asks you to type "export" first
pm import --path bitwarden.json --new
pm export --path backup.json --yes   # scripts confirm with --yes

# Plaintext exports do not overwrite files unless explicitly requested
pm export --path backup.json --force --yes
```

Preview an import without creating or changing entries, then choose how exact
name/username/URL conflicts are handled:

```bash
pm import --path backup.csv --preview
pm import --path backup.csv --conflicts skip
pm import --path backup.csv --conflicts replace
pm import --path backup.csv --conflicts keep-both
```

Bitwarden JSON imports preserve logins, secure notes, cards, identities, SSH keys,
all login URLs, TOTP, password history, and custom fields. Folder names become
tags and favorites keep their star. CSV imports read `folder`, `grouping`,
`tags`, and `favorite` columns the same way. Hidden fields, card security codes, and
sensitive identity numbers stay secret fields; secure-note bodies become primary
secrets rather than ordinary searchable notes. History follows the configured
retention limit.

Android-created passkeys are preserved by encrypted backups and portable JSON
exports as reserved secret fields. CSV export refuses vaults containing passkeys
because CSV cannot preserve their signing keys. The desktop browser extension
creates and uses passkeys (see [Passkeys in the browser](#passkeys-in-the-browser));
Android passkey creation and sign-in use the native credential provider. See
[Android setup](../android/README.md).

Both previews and completed imports report unsupported item counts and bounded,
secret-free warnings. These identify omitted passkeys, attachments, linked fields,
and unsupported matching/access policies. Unsupported authenticator configurations
and additional CSV/JSON properties are retained as secret fields when possible.
Encrypted Bitwarden exports must first be exported as unencrypted JSON. CSV
imports accept Bitwarden's login column aliases and typed rows; extra columns are
kept as secret fields. Review `--preview` warnings before importing.

Imports and previews against the current vault require it to be unlocked and
leave it unlocked. Use `--new --preview` to preview against an empty vault while
the server's vault is locked. Previews require a running server but do not prompt
for a new vault password or change the current lock state. A completed `--new`
import leaves the new vault locked.
`--key` is used only with `--new`, where it creates the new vault's external key.
Import files are limited to 128 MiB and 100,000 items.

`replace` preserves the existing stable ID and records a changed password in
history, resetting its password age. `keep-both` adds a new stable ID and appends
an `(imported)` suffix.

The format is detected from the input content; exports use a versioned portable
JSON envelope when the path ends in `.json`, otherwise CSV. Portable JSON
preserves active item types, additional URLs, custom fields, password-age
metadata, password history (bounded by the configured limit), and TOTP
configurations. Imported IDs are always remapped to safe local IDs. Supported inputs also include Chrome/Chromium
CSV, Firefox CSV, Bitwarden JSON, and 1Password CSV with compatible login columns.
Bitwarden imports preserve supported item types and their rich metadata as
described above. Generic CSV/JSON defaults to login items and accepts explicit
item types; extra properties are retained as secret fields with a report of
unsupported behavior. Portable JSON provides full fidelity for this application's
own metadata.
Conflicts compare the exact name, username, and primary URL, including duplicate
rows within one input file. They are skipped by default; `--conflicts` changes
that behavior. Password values are preserved exactly, including whitespace and
empty strings. Generic login items require a password field; typed imports use
their corresponding secret, such as a note body, card number, or private key.
Both export formats contain plaintext secrets; portable JSON can also contain
TOTP secrets and password history, so
exports should be protected or deleted after use. Export refuses to replace an
existing file unless `--force` is supplied.

### Check Password Strength

```bash
# Prompt privately (recommended)
pm passcheck

# Explicit arguments are useful for scripts but may remain in shell history
pm passcheck --password "mypassword123"
```

### Configure Settings

```bash
# Display the effective configuration
pm config

pm config --length 24 --stats true --clipboard-timeout 30 --unlock-timeout 15m
pm config --password-copy false
pm config --password-history-limit 20 --trash-retention-days 30
pm config --server-port 8787
```

Recovery settings are loaded when the server starts. Restart a running server
after changing them. A history limit or trash retention value of `0` disables
that behavior.

When an upgrade introduces a new setting, the first command that reads an older
configuration adds the setting to `config.toml` with its current default value.
Existing setting values are preserved.

The server listens only on the loopback interface and uses port `7878` by
default. The setting is stored as `port = 7878` under `[server]` in
`config.toml`. A global flag overrides it for one invocation:

```bash
pm --port 8787 start
pm --port 8787 status
pm --port 8787 kill
```

Pass the same override to every server-backed CLI command. The browser native
host reads the config file, so use `pm config --server-port PORT` instead of a
one-time flag when the extension must use the alternate port. Stop the running
server before changing its configured port, then start it again.

### Configuration and Data Locations

`config.toml` lives in the platform configuration directory; encrypted `.enc`
vaults, the session token, and the native-host installation live in the application
data directory. On Linux these default to `~/.config/password_manager` and
`~/.local/share/password_manager`, respecting `XDG_CONFIG_HOME` and
`XDG_DATA_HOME`. macOS and Windows use platform paths from the `directories` crate.

Set `PM_CONFIG_DIR` and `PM_DATA_DIR` to override the directories. Use absolute
paths and the same values for the server, CLI, and browser-launched native host.
A browser launched outside your shell may not inherit those overrides. Use the
same `PM_DATA_DIR` when installing or updating the native host.

Built-in defaults are a 20-character generated password, no generation statistics,
clipboard copying enabled for generated values and newly added login passwords,
a 15-second clipboard timeout, a 15-minute inactivity timeout, ten password-history
revisions, disabled trash expiration, and server port 7878. `pm config --reset`
restores all defaults. Invalid configuration files produce an error and are left
unchanged.

These are desktop/CLI defaults. Android uses independent
[mobile preferences](#android-preferences) and private app storage.

### Structured and Scripted Output

Public commands accept global `--json` and `--quiet` flags. JSON output
uses an object containing `ok` plus `data` for records or `error` for failures;
local display-only commands such as password generation use `output`. Mutation
responses also include an operation receipt. Transport,
vault, and availability failures exit with status 1; CLI or local-input errors
use status 2; missing records use status 3; and conflicts use status 4. Quiet
mode still prints errors. Retrieve only a primary secret without clipboard
activity with `get --password-only`:

```bash
pm --json view --sort name
pm --quiet lock
pm get --id 3 --password-only
```

With `--json`, invalid arguments also produce a JSON error and exit 2. These
errors identify the parser error kind without echoing rejected values. Help and
version requests keep their ordinary text output.

Password-only and custom-field retrieval preserve the stored value exactly in
JSON output and when standard output is redirected, including trailing spaces,
newlines, and empty values. Redirected secret output has no added newline.

If a mutation loses its reply after being sent, the CLI reports that it may
have completed and prints its operation ID. JSON failures include `uncertain`
and `operationId`. Inspect the vault and query the retained outcome before
retrying:

```bash
pm operation --id OPERATION_ID_FROM_THE_ERROR
```

This command only checks the outcome; it never retries the change. An `Unknown`
outcome (for example after server restart) does not establish that the original
change failed. Inspect vault state before deciding what to do next.

### Shell Completions

Dynamic completions query the installed `pm` for current commands, flags and
value choices on each Tab press. They run before application initialization,
without loading configuration, unlocking a vault, or contacting the server.
Add the line for your shell to its startup configuration:

```bash
# Bash: add to ~/.bashrc
source <(COMPLETE=bash pm)

# Zsh: add to ~/.zshrc
source <(COMPLETE=zsh pm)
```

```fish
# Fish: add to ~/.config/fish/completions/pm.fish
COMPLETE=fish pm | source
```

```elvish
# Elvish: add to ~/.elvish/rc.elv
eval (E:COMPLETE=elvish pm | slurp)
```

```powershell
# PowerShell: add to $PROFILE
$env:COMPLETE = 'powershell'
try { pm | Out-String | Invoke-Expression } finally { Remove-Item Env:\COMPLETE }
```

Replace any existing `pm` completion registration or source line with the dynamic
line, then open a new shell. Ensure the intended `pm` executable is on `PATH`
before that line runs. The dynamic interface uses Clap's `unstable-dynamic`
feature; generate registration at shell startup so it follows library upgrades.
In Bash, `complete -p pm` should name `_clap_complete_pm`. Refresh an existing
session with `source <(COMPLETE=bash pm)`.

Static completions remain available. Generate or replace a separate file for the
chosen shell using the intended installed executable:

```bash
# Bash: bash-completion can load this standard user location
mkdir -p ~/.local/share/bash-completion/completions
pm completions bash --output ~/.local/share/bash-completion/completions/pm

# Zsh: add ~/.zfunc to fpath before running compinit in ~/.zshrc
mkdir -p ~/.zfunc
pm completions zsh --output ~/.zfunc/_pm

# Fish: loaded automatically by Fish
mkdir -p ~/.config/fish/completions
pm completions fish --output ~/.config/fish/completions/pm.fish
```

Create the destination directory first. For PowerShell, generate a separate file
and add a dot-source line to your existing profile:

```powershell
pm completions powershell --output "$HOME/pm-completions.ps1"
# Add this line to $PROFILE:
. "$HOME/pm-completions.ps1"
```

These static files support `bash`, `zsh`, `fish`, `elvish`, and `powershell`.
Omitting `--output` or using `--output -` writes to standard output. Reload your
shell after setup. If a static Bash setup still completes filenames, check
`complete -p pm` and source the file from `~/.bashrc`:

```bash
source ~/.local/share/bash-completion/completions/pm
```

## Browser Extension

Use the desktop app or CLI to unlock and edit your vault. The extension popup
shows connection status, locks the vault, and while it is locked offers
**Unlock in desktop app**; the browser never asks for your master password to
unlock. Website pickers, credential-save prompts, signup generation, and Duo
decisions remain available; the extension has no full vault-management page or
browser generator-settings editor.

**Saving and updating passwords.** After you sign in or change a password on a
site, the save prompt offers to update a login saved for that site, or to save a
new one. If the right login was saved under a different address (an old domain,
or a separate sign-in host), choose **Update a different saved login…**, search
by name, username or website, and pick it. The new password replaces the old one,
and the site's address is added to the login so the site offers it from then on.
The search returns only names, usernames and addresses; no saved password reaches
the browser. On change-password forms the new password is recognised even when
the site labels its fields unusually: it is the value you typed twice.

**Keyboard shortcuts.** `Ctrl+Shift+L` (`⌘⇧L` on macOS) opens the account
picker for the focused login field, or for the first visible login field on the
page; `Ctrl+Shift+Y` (`⌘⇧Y`) opens the popup. Change them at
`chrome://extensions/shortcuts`. The picker still asks you to choose an account,
so a shortcut never fills anything by itself.

Lock and status requests use a separate native-host connection from site work
and Duo polling. Requests that expire while queued are never sent. If a sent save
loses its response, it may still complete. Inspect the affected item in the desktop
app, then use **Check outcome** in the extension popup. A pending operation stays
blocked; an unknown operation additionally requires the inspection checkbox and
explicit acknowledgement. Neither review nor acknowledgement replays the write.

The browser extension injects credential-handling code only into HTTPS pages.
It does not offer autofill or save prompts on plaintext HTTP pages.

### Passkeys in the browser

When a website asks to create a passkey or sign in with one, the extension opens
a small window naming the site. **Save passkey** stores a new passkey in the
unlocked vault (as a login item named `Passkey: SITE (USER)`); for sign-in, choose
the saved account and **Sign in**. **Use another passkey provider** hands the
request back to the browser (for example, to a security key or the operating
system's passkeys), and **Cancel** refuses it. Passkeys made here work on
Android, and Android-created passkeys work here, through sync or backups.

Sites can ask for *user verification*, proof that it is really you rather than
anyone at an unlocked computer. You never type a secret into the browser for
this. When a site asks (WebAuthn's default), the window offers **Confirm it's me
in the desktop app**. Leave it unchecked to continue with presence only, which
most sites accept; check it and the window waits while the desktop app shows
**Confirm it's you** for that site. Type your master password or passkey PIN
there and choose **Confirm**, and the site is told you were verified. **Refuse**,
or no answer within 90 seconds, leaves the browser window open to try again or
cancel. Sites that require verification always need this step. From a terminal,
`pm status` lists waiting requests and `pm passkey approve ID` or
`pm passkey deny ID` answers them.

A **passkey PIN** (at least 6 characters) is how a key-file vault confirms, and
it can be used instead of the master password in any vault. Set it in
**Settings → Security → Passkey PIN** or with `pm passkey set-pin`, and remove it
with **Remove PIN** or `pm passkey remove-pin`. It belongs to this device and
vault: it is not synced, and changing the vault's password or key retires it.
Wrong PINs are slowed down like wrong master passwords. A key-file vault without
a PIN reports presence only and cannot serve sites that require verification;
the window says so, and **Use another passkey provider** hands the request to the
browser.
The Android app verifies you with its unlock or fingerprint before every passkey
operation.

The extension only handles requests it can serve: ES256 passkeys on the device,
without security-key or cross-device hints and without extensions other than
`credProps`. Everything else, and the browser's passkey autofill suggestions
(conditional requests), goes straight to the browser. If no passkey for the site
is saved, sign-in requests also go to the browser. While the vault is locked the
window asks you to unlock in the desktop app first. Only top-level HTTPS pages are
covered; passkeys requested inside embedded frames use the browser.

### Firefox

Firefox 128 or later runs the same extension from a generated Firefox build.
Release archives include it as `extension-firefox/`; from a source checkout,
create it with:

```bash
node scripts/package_extension.cjs --browser firefox ~/pm-extension-firefox
pm native-host install --browser firefox
```

The Firefox build uses background scripts instead of a service worker and the
fixed add-on ID `password-manager@nelszack.dev`, so `--extension-id` is
optional for Firefox. The host is registered in `~/.mozilla/native-messaging-hosts`
on Linux, `~/Library/Application Support/Mozilla/NativeMessagingHosts` on macOS,
and under `HKCU\Software\Mozilla\NativeMessagingHosts` on Windows. Chrome-family
and Firefox registrations are independent, so both browsers can be registered.

For development, load the build with **about:debugging → This Firefox → Load
Temporary Add-on…** and choose its `manifest.json`; temporary add-ons are removed
when Firefox restarts. A permanent installation must be signed through
addons.mozilla.org (an unlisted, self-distributed signature is enough). Firefox
installed as a Snap or Flatpak cannot start native hosts outside its sandbox;
use a distribution or Mozilla package instead. Firefox 128 is required because
the extension binds every picker and save prompt to the exact page document and
origin the browser reports, and older versions do not report them.

1. Build or install `pm` at a stable path, then load the `extension` folder as
   an unpacked extension in Chrome, Chromium, or Helium on Linux, macOS, or
   Windows. For Firefox, see [Firefox](#firefox).
2. In the desktop app, open **Settings → Browser & service → Set up browser
   integration**, choose your browser, and select **Turn on browser
   integration**. From a terminal, the same step is:

   ```bash
   pm native-host install --browser chrome
   ```

   The manifest's public key fixes the extension ID, so no ID needs copying;
   pass `--extension-id` only for a repackaged extension. Use `--browser
   chromium` for Chromium or `--browser helium` for Helium. Reload the extension
   after installing the host. If the popup says "Not connected", it shows the
   command for your browser and a **Check again** button.

   On Windows, `--browser helium` automatically uses Helium's
   Chromium-compatible native-messaging registry location. Fully exit Helium,
   including any background processes, and reopen it after registration.
3. Start the password-manager server, then unlock it in the desktop app or the
   CLI.
4. Visit a login page and use the key button beside a credential field to
   choose an account. The extension can offer to save or update credentials
   when a login is submitted.

The service worker talks to `com.myproject.password_manager` through Chrome's
native-messaging API. The browser launches the registered native-host executable,
which forwards a small, validated command set to the authenticated local
server. The extension no longer requests localhost access or stores the server
session token. Page origins are derived from trusted browser sender metadata;
content scripts cannot select a different vault origin or request a TOTP code
for an unrelated entry. Pending save prompts are held briefly in service-worker
session storage and are isolated by tab and origin. On Linux and macOS the
installer creates a host link and writes
the browser manifest in the browser's per-user application-support directory.
On Windows it installs `pm-native-host.exe` and registers the manifest under
the current user's browser registry key, so administrator rights are not
required. Unix registrations link to the executable; Windows registration
copies it. If you move the executable or install a new release binary, run
`pm native-host update` using the new executable. This preserves browser
manifests and approved extension IDs. On Windows, fully close the browser first.

Autofill is form-aware: choosing an account fills only the username and current
password fields associated with that control. Other login forms and
new/confirmation-password fields on the page are left unchanged. Forms created
or revealed after page load are detected automatically.

New-password fields receive a generator button. By default it creates a 20-character
password locally with the browser's cryptographic random-number generator and
fills matching new/confirmation fields. The generated value is not sent across
the extension bridge unless the user submits and chooses to save it.

For entries configured with TOTP or HOTP, the extension also places an authenticator
button beside fields marked `autocomplete="one-time-code"` or clearly labelled
as OTP/2FA verification fields. Choose the account to fetch and fill a current
code. Only the generated code and its remaining lifetime are returned to the
extension; the encrypted OTP secret never leaves the vault server. Selecting an
HOTP authenticator consumes one counter, just like `pm totp show`.

Payment-card and identity fields also receive contextual picker buttons. The
actual selection happens in a separate extension-owned window that the webpage
cannot inspect or restyle. Only secret-free labels enter that window; after the
user selects one, the extension retrieves that single item from the unlocked
vault and fills controls in the same form. Locking or losing the native-host
connection invalidates open pickers, including requests still opening a window.
Closing, canceling, or expiring a picker releases the original page's pending
selection immediately. The picker displays the receiving site;
for an embedded frame from a different origin, it also displays the main page
and requires explicit confirmation before filling. The extension uses the
browser's `tabs` permission to read the main page's URL for this destination
check. Cardholder/email fall back to the item's `--username`, and the card
number comes from the card item's primary secret. Other values are read from
custom fields using common names, for example:

```bash
pm add --type payment-card --name "Personal Visa" --username "Alice Example" \
  --field "expiration month=09" --field "expiration year=2030" --secret-field cvv

pm add --type identity --name "Home identity" --username alice@example.com \
  --field "full name=Alice Example" --field "address line 1=123 Main St" \
  --field "city=Example City" --field "state=Example Region" --field "postal code=00000" \
  --field country=US --field "phone number=2025550100"
```

Supported standard browser fields include cardholder name, card number,
expiration, security code, name components, email, telephone, organization,
street-address lines, city, state/region, country, and postal code. Select boxes
are matched using either their option value or visible label. Payment and
identity secrets are never requested merely because a page loaded.

Credentials match the normalized saved origin: scheme, hostname, and port.
Bare domains mean HTTPS on port 443. Different ports and HTTP/HTTPS origins
require separate saved URLs. To deliberately share an entry with subdomains,
store its URL as a wildcard, such as `https://*.example.com:8443`; the scheme
and port must still match. Public-suffix wildcards such as `*.com`, `*.co.uk`,
and `*.github.io`, URLs with credentials, backslashes, and control characters
are rejected for matching. Existing ambiguous URLs remain stored but must be
corrected before browser filling can use them.

Save/update prompts use account summaries and never compare stored passwords
in a content script. They run after user interaction without delaying or
replaying the site's submission. The prompt is skipped when the vault already
holds the captured login (the desktop service compares it and returns only
summaries); with an older desktop service it may still appear, so cancel it when
no update is needed. Script-driven submissions without
user activation do not request account information.

Terminal displays escape control characters in entry metadata. Explicit raw
secret output to a pipe and plaintext exports preserve the stored values.

The badge and any open popup track native-host, server, and vault lock state
continuously, including changes made through the CLI and automatic locking.
While a popup or manager window is open, the service pushes each change as it
happens; older native hosts and services are polled every two seconds instead.
They also show a warning when the extension release, installed native host,
and running password-manager server are not the same version. Restart the
server and reinstall/reload the extension after an upgrade to clear it.
The popup can lock the vault and review uncertain operations. Recovery controls
accept requests only from the trusted popup (and save prompts for outcome checks);
website content scripts retain their site-scoped permissions.

## Clipboard behavior

CLI copies return after the clipboard is set, without waiting through the timeout.
A detached helper holds the clipboard until cleanup; secrets travel over stdin,
never command-line arguments. Server copies share one worker, and copying again
replaces its owned value and resets its deadline. Explicit and inactivity locking
clear the latest server-owned copy immediately. Cleanup preserves text copied by
another application. A timeout of `0` disables copying, as before.

Clipboard history managers may retain copies. CLI-generated copies have independent
timeouts and are not canceled by server locking. See [SECURITY.md](../SECURITY.md)
for the threat model and limits.
