# dataexchange

[![ci](https://github.com/pilot-protocol/dataexchange/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/dataexchange/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/dataexchange/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/dataexchange)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Data-exchange plugin for the Pilot Protocol daemon. Listens on port 1001
and persists inbound frames under `~/.pilot/`: files land in `received/`
and text/JSON/binary messages land in `inbox/`.

## Install

```go
import "github.com/pilot-protocol/dataexchange"
```

## Usage

```go
f := &dataexchange.Frame{Type: dataexchange.TypeJSON, Payload: body}
if err := dataexchange.WriteFrame(conn, f); err != nil {
    return err
}

// Register as a plugin on the daemon runtime:
rt.Register(dataexchange.NewService(dataexchange.ServiceConfig{}))
```

## Layout

| File | What it does |
|---|---|
| `dataexchange.go` | Wire format: `Frame`, `WriteFrame`, `ReadFrame`, `TraceFrame`, `TypeText/Binary/JSON/File/Trace/Governed/Tagged`, `TypeName`. |
| `tagged.go` | Optional request/reply correlation on the wire: `Frame.MessageID` / `Frame.ReplyTo` (`TypeTagged`), `NewMessageID`, `ValidMessageID`. |
| `client.go` | `Client` — `Dial`, `Send` (waits for the ACK, falls back for older receivers) and send helpers. |
| `governed.go` | Signed decision envelope, receiver-side verifier, and enforceable transport constraints. |
| `server.go` | `Server` — accept loop and handler dispatch. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_dataexchange`. |
| `inbox_budget.go` | Inbox caps: running byte total, oldest-first eviction to 90% of the byte cap, file-count cap. |
| `dedupe.go` | Receiver-side suppression of identical re-deliveries. |
| `service_disabled.go` | Stub `*Service` for `-tags no_dataexchange` builds. |

## Wire format

```
[4-byte type][4-byte length][payload]
```

For `TypeFile` the payload is prefixed with `[2-byte name length][name bytes]`.
For `TypeTrace` the payload is `[4-byte inner_type][8-byte sent_at_ns][inner payload]`.
For `TypeTagged` (10) the payload is
`[2-byte header_len][header: JSON object][4-byte inner_type][inner payload]`;
see [Request/reply correlation](#requestreply-correlation-for-service-authors).

Max frame size: 64 MiB by default (configurable at process start with
`PILOT_DATAEXCHANGE_MAX_FRAME` within its documented safe range).

## Inbox

Text, JSON and binary messages are written to `~/.pilot/inbox/` as one JSON
file each:

```json
{"type":"TEXT","from":"0:0000.0002.BBE4","bytes":5,"received_at":"2026-09-24T10:00:00.123456789Z",
 "data":"hello","data_encoding":"utf8","message_id":"4f1c…","reply_to":"9b2e…"}
```

`message_id` and `reply_to` appear only when the sender supplied them (see
below). Binary or non-UTF-8 payloads are stored as `data_b64` with
`"data_encoding":"base64"`.

Two caps bound the inbox, and both evict the **oldest** messages first:

- `ServiceConfig.InboxMaxFiles` (default 10000), checked every 64 messages.
- `ServiceConfig.InboxMaxBytes` (default 256 MiB), checked before every write
  against a running byte total (no directory scan per message). When a new
  message would not fit, the oldest messages are removed until the inbox plus
  the new message is at or below 90% of the cap, so recent replies survive
  and the next messages do not each trigger another eviction. A single
  message larger than the cap is rejected without evicting anything. A
  negative value disables the byte cap.

## Request/reply correlation (for service authors)

A data-exchange message is fire-and-forget: the sender gets an ACK that the
peer stored it, and any answer arrives later as a separate message in the
sender's inbox. To let a requester tell *which* request an answer belongs to,
a frame can carry two optional fields:

| Field (Go) | Inbox / event key | Meaning |
|---|---|---|
| `Frame.MessageID` | `message_id` | An ID the sender chose for this message. Use a fresh random value per message (`NewMessageID()`, 32 hex chars). |
| `Frame.ReplyTo` | `reply_to` | The `message_id` of the message this one answers. |

IDs are 1–128 characters of `A-Z a-z 0-9 - _ . :`. They are correlation
metadata only: they are not authenticated (a governed frame's signature does
not cover them), so never use them for authorization.

**If you run a service** (an agent that answers requests): when a request's
inbox record (or `message.received` event) has a `message_id`, send your
answer with `ReplyTo` set to that value. If you answer in several messages,
set it on each. Give each answer its own `MessageID` too if you want the
requester's daemon to drop duplicate copies of it (for example when you
retry a send or it arrives over two network paths). Requests without a
`message_id` come from older clients: answer them as before.

```go
c, err := dataexchange.Dial(drv, requester)
if err != nil { return err }
defer c.Close()
res, err := c.Send(&dataexchange.Frame{
    Type:      dataexchange.TypeJSON,
    Payload:   answer,
    MessageID: dataexchange.NewMessageID(),
    ReplyTo:   request.MessageID, // the request's "message_id"
})
```

**If you send requests**: generate a `MessageID`, send with `Client.Send`,
then wait for an inbox record from that peer whose `reply_to` equals it.
Services that predate this field answer without `reply_to`; for those, fall
back to matching on the sender alone.

**Compatibility.** Frames without either field use the original wire format,
byte for byte. A frame with either field travels as `TypeTagged`. Receivers
that predate it answer `ERR UNKNOWN(10) ...` and store nothing; `Client.Send`
detects that answer, re-sends the same frame without the fields on the same
connection, and reports `SendResult.Tagged == false`, so a new sender can
always talk to an old receiver. (A raw `WriteFrame` of a tagged frame does
not do this fallback — use `Client.Send`.) The fields can accompany text,
JSON, binary, file, governed and trace frames; on `TypeFileStream` frames
they are ignored.

Wire layout of a tagged frame, for other languages:

```
[4-byte type = 10][4-byte length][payload]
payload = [2-byte header_len, 1..1024][header_len bytes: JSON object]
          [4-byte inner_type][inner payload, exactly as the inner type sends it]
header  = {"message_id":"…","reply_to":"…"}   (both optional; unknown keys are ignored)
```

**Duplicate deliveries.** The receiver remembers every stored frame that
carried a `MessageID` for `ServiceConfig.DedupeWindow` (default 10 minutes).
An identical re-delivery — same sender, `MessageID`, `ReplyTo`, type,
filename and bytes — is acknowledged with the original ACK plus
` (duplicate)` (`SendResult.Duplicate`) and is not stored again. Frames
without a `MessageID` are always stored, as before, unless the operator sets
`ServiceConfig.DedupeContentWindow` (off by default) to also drop
byte-identical copies from the same sender inside a short window.

## Governed delivery

`TypeGoverned` wraps one text, JSON, binary, or single-frame file delivery in
the sender's signed `decision.Intent` and signed `decision.Decision`. The
intent payload hash binds the frame type, filename, and exact bytes; the
receiver verifies the signatures, tenant authority state, local deterministic
ceiling, exact local destination, and any applicable transport constraints
before it writes to disk. A workflow-approved action uses the same short-lived
execution Decision as an ordinary allowed action—there is no reusable
transport permit.

Large resumable files use `TypeGovernedFileStream`: the signed envelope binds
the exact `TypeFileStream` INIT (filename, declared length, full SHA-256,
chunk size, and transfer ID). Required receivers admit later chunks only for
that verified transfer on the same connection. Compute the file hash first,
call `BuildStreamInitPayload`, sign an Intent using
`GovernedStreamPayloadHash`, then call `SendGovernedFileStream`.

For a required typed-disclosure profile, build a `decision.DisclosureBinding`
whose content hash, byte length, filename, and stream transfer ID match the
file, bind its canonical hash in the signed Intent, and use
`SendGovernedWithDisclosure` or `SendGovernedFileStreamWithDisclosure`. A
`DecisionFrameVerifier` with `RequireDisclosure` rejects governed messages,
single-frame files, and resumable stream INITs that omit this evidence.
When a receipt recorder is configured, typed deliveries require its V2
disclosure-evidence method; the resulting signed receipt binds the canonical
disclosure hash without retaining the file or message body.

Set `ServiceConfig.GovernedVerifier` to `DecisionFrameVerifier` (or an
equivalent local verifier). Once all senders have been upgraded, set
`ServiceConfig.RequireGoverned` to reject unsigned legacy deliveries. Roll out
in that order: upgraded receiver with verification available, upgraded
senders, then required mode. An older receiver does not understand
`TypeGoverned`; a required receiver intentionally rejects `TypeTrace` and
raw `TypeFileStream` INIT frames. Governed stream INITs are supported.

For auditable enterprise ingress, configure `GovernedReceiptRecorder` and set
`RequireGovernedReceipts`. The service writes the received message/file first,
then requires the recorder to durably capture the exact signed Intent and
Decision before it emits the success ACK or delivery event. If recording fails,
the staged file is removed and the sender receives an error rather than a
successful but unreceipted delivery.

### Local content inspection

`ServiceConfig.GovernedContentInspector` is an optional receiver-local hook
that runs after the signed envelope and local policy ceiling are verified but
before a message/file is released. Set
`RequireGovernedContentInspection` to make startup fail unless the hook is
present; an inspection error removes a staged file or rejects the message.
`decision.PresidioInspector` is the included OSS adapter for bounded text,
JSON, XML, YAML, and form content. It rejects unsupported binary/document
types rather than truncating or silently skipping them. The inspector is local
to the receiver; neither the decision authority nor the sender's authority
receives plaintext for this check.

Typed disclosure binding V2 adds a tenant-defined `retention_class` to the
same Intent hash. A signed policy can select allowed classes; the receiver sees
the bound metadata. Configure `GovernedRetentionPolicies` to map those classes
to local expiry durations. The service writes an owner-only retention journal
before a governed message/file becomes accepted (and before a streamed file's
final rename), then removes the content after expiry across restarts. An
unknown, V1, or unconfigured class is rejected when retention is enabled.
This is deletion retention, not a legal-hold or WORM-storage implementation.

### Per-agent transfer quotas

`ServiceConfig.GovernedTransferQuota` admits a bounded number of bytes and/or
actions for each signed `Intent.AgentID` in a fixed local window. It is charged
only after governed verification, including the declared bytes of a verified
stream INIT; a peer address cannot select or reset another agent's budget.
Quota is deliberately charged for an admitted attempt even if later local DLP
or receipt persistence rejects it, so repeatedly failing submissions cannot
turn the scanner into an unmetered denial-of-service target.

The v1 action mapping is:

| Frame | Intent action |
|---|---|
| text | `data.send.text` |
| JSON | `data.send.json` |
| binary | `data.send.binary` |
| file | `file.share` |

## Build tags

| Tag | Effect |
|---|---|
| `no_dataexchange` | Compiles a no-op stub whose `Start` does nothing. Useful for integration tests that don't want inbox files written. |

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
