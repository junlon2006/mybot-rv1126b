# Changelog

Changes to project-maintained code follow Semantic Versioning. Validation evidence is maintained in [one matrix](docs/validation/README.md); a release entry does not imply hardware acceptance.

## 0.3.3 — Unreleased

- Gate SDK startup on plausible system time after network readiness and AP exit, with a configurable 1–300-second monotonic timeout, defaulting to 30 seconds.
- Preserve OS time services by default; report timeout and helper failures through the UI and standard error, then exit with a nonzero status.
- Support an explicitly selected foreground time helper only when the clock is invalid and no existing time daemon is detected; cancel and reap its owned process group on network loss or shutdown.
- Bundle an opt-in BusyBox one-shot wrapper with validated NTP server configuration, without installing services or disabling TLS verification.
- Reset the wait window on network loss and reject successful helper exits that leave an invalid clock; the 2026 threshold remains a plausibility check, not proof of precise synchronization.

This system-time guard candidate requires hardware clock, service-ownership and NTP connectivity testing.

## 0.3.2 — Unreleased

- Play the bundled localized Wi-Fi guidance once per setup session, only after the AP and portal are ready; connection retries do not repeat it.
- Apply saved output volume to guidance, including mute, through the same playback adapter used by MyBot.
- Keep the prompt worker mutually exclusive with SDK audio; cancel and release playback when leaving AP setup or exiting before restarting MyBot.
- Report guidance failures without disabling the AP portal, and document target checks for complete playback, retry behavior and audio cleanup.

This AP voice-guidance candidate requires hardware audio and Wi-Fi regression testing.

## 0.3.1 — Unreleased

- Connect MyBot device-volume controls to a platform playback-gain adapter, applying output gain once without changing capture gain or system mixer settings.
- Persist volume across application and SDK restarts, including manual AP Wi-Fi setup, in a private atomic settings file.
- Preserve existing key, terminal and cloud controls with a 0–100 range and a default of 100, matching the previous output level.
- Fall back to the default with a warning for invalid settings; report save failures and retain the last working gain.

This persistent-volume candidate requires hardware audio and Cloud AEC regression testing.

## 0.3.0 — Unreleased

- Add native AP Wi-Fi setup with an open `mybot-xxxx` hotspot, captive DNS and a bilingual mobile page at `192.168.4.1`.
- Support nearby and hidden networks, asynchronous connection/retry, saved-network default/deletion, and up to 10 private profiles containing derived PSKs.
- Preserve an existing usable network; try cached profiles before AP setup, and persist candidates only after routed IPv4 connectivity is available.
- Add 3-second touch/Menu hold and terminal `w` for manual setup, stopping MyBot before AP entry and restarting it after completion.
- Add explicit Wi-Fi interface/force/disable CLI options, AP+STA preference with safe station ownership checks, and a bundled DHCP hook. Target-side network tools and driver support remain required.
- Add host controller/backend/protocol checks, input/UI coverage and a hardware verification guide.

This AP Wi-Fi setup candidate requires hardware testing; host and cross-build evidence does not establish target radio or DHCP behavior.

## 0.2.2 — Unreleased

- Group maintained code under `src/application/`, `src/platform/` and `src/ui/`, and pinned dependencies under `vendor/`.
- Synchronize CMake, build/check/package automation, dependency mappings and documentation with the new paths.
- Preserve public include namespaces, CMake targets, generated fonts and dependency bytes, including all 99 official RTSA files.
- Keep developer programs in `tools/` and automation in `scripts/` with explicit ownership.

This source-layout candidate requires its own hardware regression.

## 0.2.1 — Unreleased

- Manage MyBot, AOSL and LVGL as separate pinned source directories.
- Record directory migrations, explicit omissions, unique ownership and required build inputs in the dependency lock.
- Keep the Linux production subset, move integration documentation outside dependency sources, and preserve runtime sources and licenses.
- Vendor the complete official Agora RTSA 1.10.1 package as an essential independent dependency; pin target builds to its AArch64 library and include vendor documentation in application bundles.
- Enforce Conventional Commits with a repository hook, message template and CI validation.

This dependency-layout candidate requires its own hardware regression.

## 0.2.0 — Unreleased

- Organize application configuration, process guards, board defaults, Linux drivers/services and pure UI into explicit components.
- Add isolated CMake presets, explicit SDK preparation, dependency provenance checks and host CI entry points.
- Bind build configuration and binary identity to manifests, verify selected package profiles and keep generated artifacts outside source control.
- Add user/developer guides, contribution/support templates and release guidance; archive original migration records.
- Preserve the 0.1.1 CLI, identity/KV contract, 20 ms audio configuration and native pixel-glasses rendering as the compatibility baseline.

This governance candidate requires a new hardware regression. Optional video, audio-quality measurements and extended concurrent operation remain pending.

## 0.1.1 — 2026-11-13

- Render at native 640×480 and rotate for the physical screen.
- Generate target-size 18/20/40/64 px fonts and adjust layout while retaining pixel-glasses geometry.
- Add text bounds, glyph coverage and pixel-repetition regression checks.
- User confirmed the improved display meets requirements on the target device.

## 0.1.0 — 2026-11-13

- Initial MyBot 1.3.0 RV1126B Linux application: HTTPS pairing, bidirectional voice, persistent identity, evdev input and pixel-glasses UI.
- Optional V4L2/MPP JPEG uplink, AArch64 ABI checks and self-contained test bundles.
- User verified checksums and the default voice/UI business flow on hardware. Optional video and extended stability were not accepted by that result.
