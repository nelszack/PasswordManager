# Set up cloud sync from the terminal

These commands control your Linux sync server remotely. Run them on the computer using
Password Manager. For the GUI, use the [setup walkthrough](cloud-sync.md).

You need Tailscale connected on both computers, SSH key/agent access to
the server, and Go 1.24 or newer on the computer doing setup or updates.
The server needs Linux on x86_64 or ARM64, systemd user services, and the
`tailscale` and `ss` tools. See [server requirements and permissions](cloud-sync-admin.md#guided-setup-requirements-and-permissions).

Replace `user@server` below with your server's SSH username and hostname,
or an alias from your SSH configuration.

## First computer: install the server

```bash
pm sync setup --ssh user@server
```

Wait for the command to report that the server is ready. It installs the server,
saves its address, and registers this computer using its Tailscale device name.

Unlock your local vault as usual. If it is already unlocked in the GUI, skip
these two commands:

```bash
pm start
pm unlock
```

Enable sync for the open vault:

```bash
pm sync enable
```

For each additional local vault, unlock that vault and run `pm sync enable`.

## New computer: connect and download

Run on the new computer:

```bash
pm sync connect --ssh user@server
pm sync pull
pm unlock
```

The new computer is named from Tailscale automatically. It does not need Go to
connect or download. If there is one cloud vault, `pull` selects it; if there
are several, it asks you to choose. Unlock using the vault's existing password
or separately transferred external key file.

## Update the server

After updating your local Password Manager application:

```bash
pm sync server update
```

The saved SSH destination is reused. You can supply `--ssh USER@HOST` explicitly.

## Check or pause sync

```bash
pm sync status
pm sync check
pm sync now
pm sync disable
```

`disable` stops syncing this local vault. Local and cloud copies are kept.

For custom names (`--name`), prebuilt binaries (`--binary`), manual token
connections, and recovery, see the [administration guide](cloud-sync-admin.md).
