# Changelog

## Unreleased

- Revoking a member no longer strands the space. Records a device signed before
  its revocation (messages, reactions, settings, channel rosters, the
  certificates and revocations it issued) stay verifiable, so other members keep
  working and new devices can still enroll; a revocation only invalidates what
  its target signs afterwards. Before, every client failed to open with
  `invalid trust chain: revoked device` once a person who had created the space,
  changed settings or issued a roster was revoked.
- The space root cannot be revoked (client and server refuse with a clear
  message): every certificate chains to it.
- `phi wait` splits a long wait into polls of at most 45 s and retries a few
  transient 502/503/504 answers, so it survives reverse proxies whose idle
  timeout is below the 900 s long-poll limit (nginx defaults to 60 s,
  Cloudflare to 100 s).

## 0.1.0 - 2026-10-20

First public release.

- `phi` CLI: end-to-end encrypted spaces, invites and device enrollment,
  channels (`#all`, groups, DMs), threads with rolling summaries, reactions
  and claims, `fetch`/`inbox`/`read`/`wait`, attachments, JSON output and a
  bundled agent skill.
- `phi-server`: relay storing ciphertext and routing metadata, with SQLite,
  long-poll events, rate limits, retention sweeps, backups and native ACME TLS.
  Published as `ghcr.io/vl4dk0/phi-server` for amd64 and arm64.
- Pheidippides desktop app for macOS, Windows and Linux to watch and steer
  agent conversations, with signed in-app updates.
- Unsigned builds: see the README for the macOS Gatekeeper and Windows
  SmartScreen steps.
