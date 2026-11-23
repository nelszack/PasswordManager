# Sync with a self-hosted server

The server stores encrypted vault snapshots. Each device keeps its own local
copy and synchronizes while the vault is unlocked.

## Install the server separately

Follow [server installation and device enrollment](cloud-sync-admin.md).
The client does not deploy, build, or update remote servers. The server can run
behind any HTTPS reverse proxy or private-network HTTPS endpoint; the client needs its
HTTPS URL and a device credential issued by the administrator.

## Connect a device

Issue a separate token for each device and transfer it privately. On a desktop
or CLI device:

```bash
pm sync connect https://sync.example.com --token-file ./device-token
```

Omit `--token-file` to enter the token in a hidden prompt. Failed connection
attempts preserve the existing local connection and credential.

In the desktop app, **Settings → Sync** also exposes the
server URL and private device-credential input. Save the URL with your settings,
then save the credential. Server installation and updates are separate admin tasks.

On Android, open **Settings → Cloud sync settings / download vault**, enter the
complete HTTPS URL (including a nondefault port) and **Per-device credential**,
then choose **Save connection**. The app tests the credential before saving it.
The input clears as soon as you submit; this does not indicate that a saved
credential was deleted. After a failed first connection, paste it again. Leaving
it blank reuses a previously saved credential. Android protects the saved token
using Keystore; the desktop uses a private `sync-token` file.

## Enable an existing local vault

Unlock the vault and choose **Turn on sync** under Settings → Sync, or run `pm sync enable`.
On the desktop service, saved changes synchronize automatically while that vault
is unlocked, even after the desktop window closes. Repeat for each vault you want
synchronized. When automatic sync stops on a conflict, or on a cloud copy this
session cannot or should not apply, it shows a warning and does not download
the vault again until the local vault or the cloud version changes. Network and
server errors are retried with increasing delays, up to 15 minutes apart; a
local edit or a change notification retries at once.

On Android, unlock and open **Tools → Sync controls → Enable sync for this
vault**. The app checks sync on opening the vault and after supported mutations;
use **Synchronize now** for an explicit request. Android does not run the desktop
daemon or a continuous background sync service. Leaving management locks it.

## Download onto another device

Connect that device using its own credential, then choose **Refresh cloud vaults**
and **Download selected vault**. Unlock the download with its existing password
or separately transferred external key. From the terminal:

```bash
pm sync pull
pm unlock
```

A single cloud vault is selected automatically; multiple vaults require selection.
Locked or offline devices catch up after reconnecting and unlocking. Conflicting
edits preserve both copies. Use **Review conflicts** in Cloud sync to choose
local or cloud values per field, with encrypted recovery copies saved before
applying. See [conflict recovery](cloud-sync-admin.md#conflicts-and-password-changes).

See the [terminal walkthrough](cloud-sync-cli.md) for status and sync controls.

On Android, use **List cloud vaults** and **Download** from the connection page.
A comparison download is a separate vault with sync disabled. Review conflicts
from **Settings → Review sync conflicts** after unlocking.

## Connection troubleshooting

- **Unauthorized:** the server rejected the device token. Use the complete token
  issued by `--add-device`, rather than its label, revocation ID, vault password,
  or external key. The device name does not need to match the phone's name.
  Confirm that the credential was issued on this server and has not been revoked.
- **Error sending request:** inspect the underlying network/certificate cause in
  the app's error. Confirm the exact HTTPS hostname and port. If the server is only
  reachable over a private network or VPN, keep the device connected to it and
  confirm its access policy allows that server and port. The phone's `localhost` refers to the phone.
- **Blank Android credential input:** a successful connection stores the token
  securely and leaves the field blank. A failed connection retains the previous
  saved connection; it does not save the newly entered credential.
- **Offline or uncertain upload:** local changes may already be saved and the
  remote operation may have completed. Check sync state and conflicts before
  retrying. Sync is not a substitute for encrypted backups.
