# Documentation

Reviewed against `main` on 2026-11-21. Android delivery is a private development APK, version **0.3.0 (12)**;
desktop/CLI workspace version and local protocol version are independent.

| Start here | Contents |
| --- | --- |
| [Project overview](../README.md) | Supported clients, desktop installation and quick start. |
| [User guide](user-guide.md) | Desktop and terminal workflows, Android daily use, extension behavior and recovery. |
| [Android build and setup](../android/README.md) | Private APK builds/updates, fingerprint unlock, autofill, passkeys, sync and isolated tests. |
| [Mobile implementation and acceptance](mobile-implementation.md) | Implemented features, parity matrix, dated verification and remaining phone/provider checks. |
| [Command reference](commands.html) | Generated CLI commands/options; regenerate from Clap rather than editing generated HTML. |
| [CLI/desktop/Android feature map](gui-cli-parity.md) | Routes for shared operations and platform-specific differences. |
| [Cloud sync setup](cloud-sync.md) | Connect desktop/phone clients, enable/download vaults and troubleshoot credentials/connectivity. |
| [Cloud CLI walkthrough](cloud-sync-cli.md) | Terminal connection, download, status and conflict resolution. |
| [Cloud administration](cloud-sync-admin.md) | Server deployment, device enrollment/revocation, quotas, updates and recovery. |
| [Security policy](../SECURITY.md) | Threat model, Android trust boundaries, known limits and vulnerability reporting. |
| [Contributor guide](development.md) | Current architecture, build/testing, CI, Android development, releases and benchmarks. |
| [Fuzzing](../fuzz/README.md) | Parser targets, pinned toolchain, synthetic seeds and reproductions. |
| [Icons/assets](../assets/README.md) | Desktop/extension icon sources and regeneration. |
| [Architecture review](architecture-review.md) | Historical design findings and implementation follow-up. |
| [Performance review](performance-review.md) | Dated desktop/browser measurements and their limits. |

Local dependency patch notes live in `vendor/*/README.pm.md` and
[the font database bridge](../vendor/fontdb-compat/README.md). Upstream README and
changelog files remain upstream reference material.

Implementation, automated test evidence and interactive acceptance are recorded
separately. Android 13 cannot exercise the Android 14+ passkey provider. Full
real-provider Google MFA/Duo, current interactive fingerprint/invalidation,
two-device recovery and privately signed release upgrades still need the
acceptance checks documented in the mobile checklist. iPhone remains planned.
