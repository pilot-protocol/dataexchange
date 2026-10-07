# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Governed delivery. The signed-envelope frames `TypeGoverned` (8) and
  `TypeGovernedFileStream` (9) carried decisions issued by the hosted control
  plane, which has been retired; the daemon stopped configuring the receiver
  gates in v1.14.0, so the code could no longer be reached. Removed: every
  exported `Governed*` identifier (the frame and stream-INIT envelopes and
  their codecs, the verifier and receipt-recorder interfaces, the payload
  hash helpers, `GovernedRetentionPolicy`), `DecisionFrameVerifier`,
  `Client.SendGoverned*`, `BuildStreamInitPayload`, and the `ServiceConfig`
  fields `RequireGoverned`, `GovernedVerifier`, `GovernedStreamVerifier`,
  `RequireGovernedReceipts`, `GovernedReceiptRecorder`,
  `GovernedContentInspector`, `RequireGovernedContentInspection`,
  `GovernedTransferQuota`, `GovernedRetentionPolicies`, `RetentionStateDir`
  and `RetentionSweepInterval`. The module no longer imports
  `github.com/pilot-protocol/common/decision`.
- Frame types 8 and 9 stay reserved and keep their constants and names. A
  receiver refuses them like any unsupported type: nothing is stored and the
  sender gets `ERR GOVERNED save failed: unsupported frame type 8` (or
  `ERR GOVERNED_FILESTREAM ... type 9`); the connection stays open.

### Fixed

- Several transfers of the same content at once no longer fail. The receiver
  names a transfer's `.partial` after the content hash so a retry can resume
  it; two peers sending the same file (or one sender on two connections)
  therefore wrote the same file, and all but the first failed at the final
  rename. The first transfer keeps the resumable `.partial`; a concurrent one
  gets a private file that is removed if it does not finish. A sender that
  stalls and retries still resumes: once the transfer holding the `.partial`
  has written nothing for two minutes (twice the sender's default wait for an
  ACK), the retry takes the file over, and the stalled transfer is refused
  any further write, its DONE, and the file itself if it starts over. A retry
  sooner than that starts over in a private file. A transfer refused at the
  start never takes a file over.
- A file that cannot fit on the receiver's disk is refused before any byte is
  sent. The byte quota is a fixed number and can be larger than the disk, so a
  transfer ran until the disk was full, failed, and left its bytes in
  `.partial` — where they kept the disk full and blocked incoming messages.
  The receiver now checks free space at the start (keeping 16 MiB in reserve),
  and if a write still hits a full disk it deletes that `.partial`.
- A streamed transfer declaring a size of 2^63 bytes or more is refused by the
  receiver's byte quota. The size was converted to a negative number and
  passed the check.
- A sender whose transfer is refused at the start (quota, disk full, too many
  transfers) reports the refusal. It was mistaken for a receiver too old to
  support streamed transfers, so the caller retried with the single-frame
  path and pushed the whole file at a peer that had just declined it.
- `WriteFrame` sends a frame of up to 64 KiB as one write. Header and payload
  as two writes made the payload wait on Nagle and the peer's delayed ACK.
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
- `Client.Send`, which waits for the ACK and delivers a tagged frame
  untagged, with `SendResult.Tagged == false`, when the tagged form cannot
  get through. That happens when the receiver predates `TypeTagged`: Send
  recognises both the `ERR UNKNOWN(10) ...` answer of dataexchange v0.2.2 and
  later and the `ACK UNKNOWN(10) <n> bytes` answer of v0.2.1 and older (every
  stable daemon through v1.13.9), which drop the frame while acknowledging
  it. It also happens when the header would push the frame over the max
  frame size.
- `MaxTaggedOverhead` (293 bytes) and `ErrTaggedFrameTooLarge`: the tagged
  header counts toward `MaxFrameSize`, and `WriteFrame` refuses a tagged
  frame that exceeds it, writing nothing, rather than send a frame the
  receiver would drop the connection over.
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
