# Use cloud sync from the terminal

Install the server and issue a token per device using the
[administration guide](cloud-sync-admin.md). Client-side SSH setup and remote
updates are not part of the application.

## Connect and enable a local vault

```bash
pm sync connect https://sync.example.com --token-file ./device-token
pm start
pm unlock
pm sync enable
```

Replace the URL and token path with those supplied for your server. Omit
`--token-file` for a hidden token prompt. Connection validation happens before
replacing saved credentials. Unlock each additional local vault and run
`pm sync enable` to synchronize it.

## Connect another device and download

Issue a separate credential for the new device, then run:

```bash
pm sync connect https://sync.example.com --token-file ./new-device-token
pm sync vaults
pm sync pull
pm unlock
```

Use the vault's existing password or external key. A single cloud vault is
selected automatically; otherwise choose a vault or pass its ID to `pull`.
Use `pm sync pull ID --copy` for a separate comparison copy with sync disabled.

## Check or pause sync

```bash
pm sync status
pm sync check
pm sync now
pm sync disable
```

Disabling sync retains local and remote copies. Server installation, device
revocation, updates, and recovery are covered in the administration guide.
