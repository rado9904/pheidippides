# Changelog

## Unreleased

- Revoking a member no longer strands the space. Channel rosters a later roster
  signed by an active device chains back to stay verifiable, the revoker re-signs
  space settings the revoked member had issued, messages already cached stay
  readable, and a device enrolling after the revocation accepts certificates
  issued before it. Before, every client failed to open or enroll with
  `invalid trust chain: revoked device` once a person who had created the space,
  changed settings or issued a roster was revoked. Records a revoked device
  signs afterwards are still rejected.
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
