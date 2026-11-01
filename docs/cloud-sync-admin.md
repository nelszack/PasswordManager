# Cloud sync administration

For normal setup, start with [Sync with a self-hosted server](cloud-sync.md).
For terminal commands, use the [CLI walkthrough](cloud-sync-cli.md).
This page covers manual installation, credentials, recovery, and storage.

## Guided setup requirements and permissions

Guided setup installs a service on a Linux x86_64 or ARM64 host over SSH.
The client doing setup or updates needs SSH and Go 1.24 or newer, or a matching
prebuilt server supplied with `--binary PATH`. Other clients only need SSH for
enrollment. Device names come from the local Tailscale CLI unless you supply
a name manually.

The server needs `systemctl --user`, `ss`, and a connected Tailscale CLI, with
HTTPS enabled for its tailnet. The SSH account must be able to manage Tailscale
Serve. If Serve reports an access-denied error, a server administrator can grant
that account operator permission. Run this **on the server as the SSH user**:

```bash
sudo tailscale set --operator="$(id -un)"
```

This is a one-time host permission change; Password Manager installs and runs
the sync service as that user. See [Tailscale operator permissions](https://tailscale.com/docs/reference/troubleshooting/linux/linux-operator-permission).
Guided setup chooses unused ports and preserves existing Serve routes. Use the
server URL it reports rather than assuming a particular port.

The server must remain online for peers to exchange updates. For a user service
to start at boot and continue after logout, the host may need lingering enabled.
An administrator can run the following **on the server as the SSH user**:

```bash
sudo loginctl enable-linger "$(id -un)"
```

See the [systemd loginctl reference](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html).
For a container or virtual machine, also arrange for that environment to start
and stay running. Guided setup does not manage its lifecycle. Its systemd user
session, Tailscale, and service must all be in the environment reached over SSH;
otherwise use manual hosting.

## Manual server installation

Build on a development machine so the server needs neither Go nor source
and build caches. The service targets Linux and uses only Go's standard library.
Choose `GOARCH=amd64` for an x86_64 server or `GOARCH=arm64` for an ARM64 server;
check `uname -m` on the host. Replace `user@server` with your SSH destination.

```bash
cd sync-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /tmp/pm-sync .
scp /tmp/pm-sync user@server:/tmp/pm-sync
```

On the server:

```bash
install -Dm755 /tmp/pm-sync ~/.local/bin/pm-sync
mkdir -p ~/.local/share/pm-sync
chmod 700 ~/.local/share/pm-sync
~/.local/bin/pm-sync --data ~/.local/share/pm-sync
```

The default listen address is `127.0.0.1:8788`. In a separate terminal on the
server, expose that loopback service with Tailscale Serve:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:8788
```

Use the HTTPS URL printed by that command, including `:8443`, on clients. This
uses a separate HTTPS port to accommodate other services; inspect existing Serve
configuration before choosing a port. If Tailscale runs in a different network
namespace, configure its proxy to reach the service instead. See the official
[Tailscale Serve reference](https://tailscale.com/docs/reference/tailscale-cli/serve).
Alternatively, place the service behind your own HTTPS reverse proxy and use
that URL when connecting clients. Manual connections do not require a Tailscale
hostname or SSH enrollment; use a separately issued device token as shown below.
Clients require HTTPS except for localhost development. They do not follow
redirects or use environment HTTP proxies.

For a background user service, install `sync-server/pm-sync.service` into
`~/.config/systemd/user/pm-sync.service` on the server. Stop the foreground
process first, then run:

```bash
systemctl --user daemon-reload
systemctl --user enable --now pm-sync.service
```

This starts with the user's systemd session. See the unattended startup notes
above if the server must run without an active login. Service logs contain
startup/errors, not vault contents or tokens.

## Manual device enrollment

On the server, generate a separate credential for each device:

```bash
~/.local/bin/pm-sync --data ~/.local/share/pm-sync \
  --add-device laptop --credential-file ~/laptop-sync-token
```

This creates a private token file and prints its path and revocation ID. Transfer
that file privately to the laptop. Tokens are never accepted as CLI arguments.
Then, on the laptop:

```bash
pm sync connect https://sync.example.com --token-file ./laptop-sync-token
```

Replace `https://sync.example.com` with your server's HTTPS URL. For Tailscale
Serve, use its reported URL, such as `https://server.example-tailnet.ts.net:8443`.

Omit `--token-file` to paste it into a hidden prompt. The client saves the token
in its private configuration directory as `sync-token`, separately from
`config.toml`. Treat transferred credential files as secrets. The server stores
only token hashes, labels, and creation dates. Every enrolled device has access
to all vaults on this personal server; multi-user vault access controls are not
implemented.

Revoke a device immediately, without restarting the server:

```bash
~/.local/bin/pm-sync --data ~/.local/share/pm-sync --revoke-device ID_PRINTED_DURING_ENROLLMENT
```

Enrollment is an administration command, not an unauthenticated network endpoint.
SSH enrollment transfers credentials automatically; there is currently no
single-use pairing-code exchange.

## Conflicts and password changes

An upload names the remote version it started from. The server atomically rejects
stale uploads. If both local and remote contents changed, neither copy is
replaced. Automatic merging and an interactive conflict-resolution workflow are
not implemented yet. To inspect the remote version without disturbing the local
vault:

```bash
pm sync pull CLOUD_VAULT_ID --copy
```

That creates a separate comparison copy with sync disabled. Keep encrypted
backups before manually reconciling conflicting credentials. Do not edit sync
checkpoint files to bypass conflict checks.

Changing a master password or external key uploads a new encrypted snapshot. An
already-unlocked peer cannot decrypt it with its old cached key; it preserves its
local vault and reports an error. Use `pull --copy` and unlock that copy with the
new credentials to access the changed vault. Seamless remote rekey handling is
not implemented yet.

The server cannot forge authenticated vault contents, but it can withhold or
replay old encrypted data. This first version does not provide cryptographic
protection against a malicious server rolling back an otherwise valid snapshot.

## Storage and recovery

The default quota is 256 MiB across vault files, retained snapshots, and upload
headroom. The service retains three snapshots per vault, including the current
one. Individual encrypted vaults are limited to 128 MiB. Set `--max-storage BYTES`
and `--keep COUNT` to change these limits. A new upload must fit before old
versions are pruned; this keeps the previous current version available if saving
fails. Quota and disk errors leave existing committed vaults intact.

Files live under `vaults/VAULT_ID/VERSION.vault`; `head.json` is the authoritative
current version. Device records live under `devices/`. Only one server process
can own a storage directory. Administrators can recover retained snapshots from
the filesystem; there is no network history/restore API yet.

Clients store nonsecret checkpoints next to each local vault as `.sync.json`,
containing its server origin, expected identity, remote version, ciphertext hash,
and enable state. An interrupted upload acknowledgement is reconciled by checking
whether the cloud bytes already equal the local bytes. In ambiguous cases the
client preserves both copies and reports a conflict.

Back up the server directory and keep separate encrypted client backups. Sync
replicates changes and does not replace backups.

## Validation

```bash
cd sync-server
go test -race ./...
go vet ./...
```

After building the Rust executable, run the actual two-device integration test:

```bash
cargo build --locked
python3 scripts/test_cloud_sync.py
```

This uses temporary profiles and loopback services and verifies initial download,
automatic updates, conflict preservation, comparison copies, and server restart.
Repository Rust/GUI checks and command-reference generation apply as usual.

## Device names

Guided setup and SSH connection run `tailscale status --json --peers=false`
on the device being registered. See the [Tailscale CLI reference](https://tailscale.com/docs/reference/tailscale-cli).
The label uses the first component of
`Self.DNSName`, so a name assigned in Tailscale takes precedence over the OS
hostname. `Self.HostName` is used when no DNS name is reported. Names are
recorded when a device credential is created; existing credential labels are
kept when that credential is reused.

If the local Tailscale CLI is unavailable, enter a device name under **Manual
connection options**, or use `--name NAME` with `sync setup` or `sync connect
--ssh`. The server SSH address and the local device's name are separate values.
