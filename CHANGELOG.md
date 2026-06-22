# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security / hardening

- Lower the default per-frame cap (`DefaultMaxFrameSize`) from 1 GiB to
  64 MiB and stop pre-allocating the attacker-declared frame size in
  `ReadFrame` — payloads now grow incrementally as bytes arrive, so a single
  hostile peer can no longer OOM the receiver by announcing a giant frame.
  Raise the cap with `PILOT_DATAEXCHANGE_MAX_FRAME` (both ends must agree).
- Add a per-connection idle/read deadline (`ServiceConfig.IdleTimeout`,
  default 2 min) reset before every frame so slowloris peers can no longer
  hold connections open indefinitely.
- Add a total-byte inbox cap (`ServiceConfig.InboxMaxBytes`, default 256 MiB)
  enforced on every receipt, alongside the existing file-count cap.
- Add a received-files disk quota (`ServiceConfig.ReceivedMaxBytes`, default
  2 GiB) covering completed files and retained `.partial` stream fragments,
  enforced before every write (legacy `TypeFile` and chunked `TypeFileStream`).
- Store binary / non-UTF-8 inbox payloads as base64 (`data_b64`) by default
  with a `data_encoding` marker, instead of silently corrupting them into a
  lossy JSON string.
- Reject over-long filenames in `WriteFrame` before the `uint16` length cast
  so a name cannot wrap/truncate onto the wire.

A negative value for any of `InboxMaxBytes`, `ReceivedMaxBytes`, or
`IdleTimeout` disables that limit (escape hatch); zero selects the default.

## [v0.1.0]

Initial release.
