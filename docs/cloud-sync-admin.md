# Cloud sync administration

For normal setup, start with [Sync with a self-hosted server](cloud-sync.md).
For terminal commands, use the [CLI walkthrough](cloud-sync-cli.md).
This page covers manual installation, credentials, recovery, and storage.

## Hosting requirements

The server targets Linux and builds with Go 1.24 or newer. Clients connect to a
private HTTPS endpoint, such as Tailscale Serve. Install and update the server
separately; Password Manager no longer manages SSH destinations or remote services.
For a user service to run after logout, arrange an appropriate systemd user
session and unattended startup policy on the host.

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

This starts with the user's systemd session. Configure unattended startup on
the host if the server must run without an active login. Service logs contain
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
Transfer each device credential privately. There is no client-side SSH enrollment
or single-use pairing-code exchange.

## Conflicts and password changes

An upload names the remote version it started from. The server atomically rejects
stale uploads. If both local and remote contents changed, neither copy is
replaced. Review differences in **Settings → Connection → Cloud sync → Review
conflicts**. The desktop shows local and cloud labels side by side. Choose all
local, all cloud, or select a side for each differing field, then choose **Apply
selected values and sync**. Save or discard unfinished item edits first.

Names, usernames, URLs, creation times, and deletion states are shown; passwords,
notes, and protected groups remain redacted. Metadata (item type, additional
URLs, and custom fields), password history, authenticators,
and Duo credentials are selected as complete groups. The password-change time
follows the selected primary secret. No choice is preselected.
When an item exists on only one side, choosing the absent side removes it from
the resolved vault. Independently created items can share a numeric ID; review
creation times and item labels carefully. There is no automatic three-way merge.

The CLI exposes the same review and choices:

```bash
pm sync conflicts
pm sync resolve --review REVIEW_TOKEN \
  --choose 1:name:local --choose 1:password:remote --choose 1:history:remote
```

Use the exact field names and token printed by `conflicts`, supplying one
`--choose ITEM_ID:FIELD:local|remote` for every reported difference. The example
assumes only those three fields differ. If no fields differ but ciphertexts do,
`pm sync resolve --review REVIEW_TOKEN` reconciles them without field choices.

Resolution rejects stale reviews if either snapshot, the unlock session, or
connection changed. Refresh the review and choose again. Before applying,
the client saves both complete encrypted versions as separate local vault files
with synchronization disabled, and reports their filenames. These recovery copies
use the corresponding original password or external key and retain history and
trash. They remain until you explicitly delete them.

The resolved vault is saved locally and uploaded against the reviewed cloud
version. A later remote edit is preserved as another conflict; an offline upload
remains pending. Check current state before retrying an uncertain operation.
If another device changed the password/key so this session cannot decrypt the
cloud version, download an independent copy and unlock it with its current
credentials:

```bash
pm sync pull CLOUD_VAULT_ID --copy
```

Do not edit sync checkpoint files to bypass conflict checks.

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

The label supplied to the server's `--add-device` command identifies that device's
credential. Labels do not grant different access rights: every credential on this
personal server can access its encrypted vault snapshots.

## Updates

Build a replacement server binary, stop the service, replace the executable, and
restart it. Retain a known working binary for administrator-managed rollback.
The client does not ship server source or perform remote updates. Keep the server
storage directory and issued credentials when replacing the executable.
