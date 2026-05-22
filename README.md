# dataexchange

Pilot Protocol data-exchange plugin. Listens on port 1001 and stores
incoming frames in `~/.pilot/{received,inbox}` — files in `received/`,
text/json/binary messages in `inbox/`.

## Layout

| File | What it does |
|---|---|
| `dataexchange.go` | Wire format. `Frame`, `WriteFrame`, `ReadFrame`, `TraceFrame`, `TypeText/Binary/JSON/File/Trace`, `TypeName`. |
| `client.go` | `Client` — `Dial`, send helpers. |
| `server.go` | `Server` — accept loop + handler dispatch (used by tests and embedders). |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_dataexchange`. |
| `service_disabled.go` | Stub `*Service` when build tag `no_dataexchange` is set. |

## Wire format

```
[4-byte type][4-byte length][payload]
```

For `TypeFile` the payload is prefixed with `[2-byte name length][name bytes]`.
For `TypeTrace` the payload is `[4-byte inner_type][8-byte sent_at_ns][inner payload]`.

Max frame size: 256 MiB.

## Import paths

```go
import "github.com/pilot-protocol/dataexchange"

f := &dataexchange.Frame{Type: dataexchange.TypeJSON, Payload: body}
_ = dataexchange.WriteFrame(conn, f)
```

The daemon's `cmd/daemon/main.go` registers the plugin via:

```go
rt.Register(dataexchange.NewService(dataexchange.ServiceConfig{}))
```

## Disabling

Pass `-tags no_dataexchange` to `go build` to compile a stub service
whose `Start` is a no-op. Useful for integration tests that don't want
inbox files written.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4 (the protocol repo) pulls it
in via `require github.com/pilot-protocol/dataexchange v0.1.0`. During
co-development the protocol repo uses `replace ../dataexchange`.
