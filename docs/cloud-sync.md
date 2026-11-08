# Sync with a self-hosted server

The server stores encrypted vault snapshots. Each device keeps its own local
copy and synchronizes while the vault is unlocked.

## Install the server separately

Follow [server installation and device enrollment](cloud-sync-admin.md).
The client does not deploy, build, or update remote servers. The server can run
behind Tailscale Serve or another private HTTPS proxy; the client needs its
HTTPS URL and a device credential issued by the administrator.

## Connect a device

Issue a separate token for each device and transfer it privately. On that device:

```bash
pm sync connect https://sync.example.com --token-file ./device-token
```

Omit `--token-file` to enter the token in a hidden prompt. Failed connection
attempts preserve the existing local connection and credential.

In the desktop app, **Settings → Connection → Cloud sync** also exposes the
server URL and private device-credential input. Save the URL with your settings,
then save the credential. Server installation and updates are separate admin tasks.

## Enable an existing local vault

Unlock the vault and choose **Enable for open vault**, or run `pm sync enable`.
Saved changes synchronize automatically while that vault is unlocked, even after
the desktop window closes. Repeat for each vault you want synchronized.

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
edits preserve both copies; see [conflict recovery](cloud-sync-admin.md#conflicts-and-password-changes).

See the [terminal walkthrough](cloud-sync-cli.md) for status and sync controls.
