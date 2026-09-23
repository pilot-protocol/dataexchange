# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The inbox byte cap no longer deletes the whole inbox. With the default
  config (`InboxMaxBytes == 0`, meaning 256 MiB) the evictor compared the
  inbox size against the raw value 0, so the first time the inbox passed
  256 MiB every stored message was removed, including replies a waiting
  `pilotctl send-message --wait` was about to read. Both eviction paths now
  use the effective cap, evict oldest-first down to 90% of it, and never
  evict for a message that cannot fit at all.
- The byte cap is checked against a running total instead of listing and
  stat'ing the whole inbox on every incoming message. A message that another
  connection is still writing (admitted, but not yet acknowledged) is never
  evicted and never counted twice.
- When the byte cap is full the inbox now evicts the oldest messages to make
  room (as `InboxMaxBytes` was documented to do) instead of rejecting the
  new message.

### Added

- Optional request/reply correlation: `Frame.MessageID` and `Frame.ReplyTo`,
  carried on the wire in a new `TypeTagged` (10) wrapper and recorded in
  inbox JSON and `message.received` / `file.received` events as
  `message_id` / `reply_to`. Frames without them are byte-for-byte
  unchanged. `NewMessageID` and `ValidMessageID` helpers.
- `Client.Send`, which waits for the ACK and, when the receiver predates
  `TypeTagged`, re-sends the frame untagged so older peers still get it.
- Receiver-side duplicate suppression: an identical re-delivery of a stored
  frame that carried a `MessageID` is acknowledged (`... (duplicate)`) but
  not stored twice (`ServiceConfig.DedupeWindow`, default 10 min).
  `ServiceConfig.DedupeContentWindow` (off by default) extends this to
  frames without a `MessageID`.

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
