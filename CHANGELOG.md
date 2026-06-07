# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-07

### Added
- **Reply-on-connection (`--auto-answer` receivers).** A new opt-in request type
  `TypeAutoAnswer` (6) lets a sender ask the receiver to answer on the *same*
  connection the sender opened, instead of relying on a dial-back. On a service
  configured with `ServiceConfig.AutoAnswer`, a `TypeAutoAnswer` request is
  dispatched via `ReplyHook`, the reply is written back on the connection as a
  `TEXT` frame, and the connection is closed after exactly one request + one
  reply. The request is **not** saved to the inbox (so a responder never also
  dial-backs it). This delivers the answer even when the sender is unreachable
  for an inbound dial (NAT, no public port, transient client).
- `Client.SendAutoAnswer(text)` — send a `TypeAutoAnswer` request.
- `Client.SetReadDeadline(t)` — bound the sender's read while waiting for the
  reply-on-connection (passthrough to the underlying `driver.Conn`).
- `TypeName(TypeAutoAnswer)` → `"AUTOANSWER"`.

### Behaviour / compatibility
- **Plain requests are unchanged.** `TypeText`/`TypeJSON`/`TypeBinary` requests
  always flow through the existing inbox path; the auto-answer loop runs *only*
  for `TypeAutoAnswer` on an `AutoAnswer` service. A `TypeAutoAnswer` request
  reaching a node that does not auto-answer falls back to a normal inbox save
  (so it still gets a dial-back). Setting `AutoAnswer` therefore never changes
  how a node serves ordinary senders.
- The receiver performs a **graceful close**: after writing the reply it waits
  for the sender to consume it and close, so an abortive teardown cannot drop an
  in-flight reply. Bounded by a per-request watchdog (`autoAnswerWindow`, 40s).

## [v0.1.0]

Initial release.
