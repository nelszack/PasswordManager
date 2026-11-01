# Sync with a self-hosted server

Your server stores encrypted copies of your vaults. Your devices
keep their own local copies and sync changes through it.

**Start on the computer where you currently use Password Manager.** You will
control the server from that computer. The server can be a spare computer,
virtual machine, or container that meets the requirements below and stays online
when you need to sync.

## Before you start

- Connect your computer and server to the same Tailscale network.
- The server needs Linux on x86_64 or ARM64, a working systemd user session,
  and the `tailscale` and `ss` command-line tools. For containers, these must
  be available inside the environment you access over SSH.
- Make sure you can log into the server using an SSH key or SSH agent.
  The examples use `user@server`: replace it with your server's SSH username
  and hostname, or use an alias from your SSH configuration.
- Have Go 1.24 or newer installed on your main computer. Setup uses it to build
  the server. The server itself does not need Go.

Guided setup uses Tailscale Serve for private HTTPS access. See the
[administration guide](cloud-sync-admin.md) for permission requirements,
unattended startup, or manual hosting behind a different HTTPS proxy.

Use the latest build of Password Manager, which includes the setup buttons.

## 1. Set up the server once

On your **main computer**:

1. Open Password Manager and unlock the vault you want to sync.
2. Open **Settings → Connection → Cloud sync**.
3. Enter your server's SSH address in **Server SSH address**, then click **Set up server**.
4. Wait for setup to finish. It may take a few minutes the first time.
5. Click **Enable for open vault**.

Setup installs the service under your SSH user's home directory, fills in the
server URL, and registers your main computer using **its Tailscale device name**
automatically.

Saved changes now sync automatically while this vault is
unlocked. The local background service handles sync even after you close the GUI.

To sync another local vault, open it and click **Enable for open vault**.
You only set up the server once.

## 2. Add another device

On the **new device**:

1. Open Password Manager, then **Settings → Connection → Cloud sync**.
2. Enter the same server SSH address used during setup.
3. Click **Connect to existing server**.
4. Select your cloud vault and click **Download selected vault**.
5. Unlock the downloaded vault with its existing master password or external key.

This device also gets its name from Tailscale automatically. Sync is already
enabled for the downloaded vault. Go is only needed on the computer that
builds or updates the server.

## 3. Update the server later

On a computer already connected to sync:

1. Update the Password Manager application to the version you want to use.
2. Open **Settings → Connection → Cloud sync** and click **Update server**.

The app remembers the server's SSH address. It replaces the server binary,
checks that it starts correctly, and restores the previous version if startup
fails. Your stored vaults and device credentials are kept.

## If something needs attention

- **Tailscale name could not be read:** Connect this device to Tailscale and make
  sure its command-line tool is available. You can also enter a name under
  **Manual connection options**.
- **SSH connection failed:** Check that your SSH key or agent can log into
  the address entered in **Server SSH address** without a password prompt.
- **Tailscale requests HTTPS approval or permission:** Complete that authorization
  on the server or in its Tailscale account, then retry setup. See
  [server permissions](cloud-sync-admin.md#guided-setup-requirements-and-permissions).
- **Sync conflict:** Both copies are preserved. See
  [conflict recovery](cloud-sync-admin.md#conflicts-and-password-changes).

The current version syncs the active vault while it is unlocked. Locked or
offline devices catch up after reconnecting and unlocking.

Prefer commands? Follow the [terminal walkthrough](cloud-sync-cli.md).
Manual installation and technical details are in the
[administration guide](cloud-sync-admin.md).
