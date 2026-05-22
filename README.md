# dataexchange

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
| `dataexchange.go` | Wire format: `Frame`, `WriteFrame`, `ReadFrame`, `TraceFrame`, `TypeText/Binary/JSON/File/Trace`, `TypeName`. |
| `client.go` | `Client` — `Dial` and send helpers. |
| `server.go` | `Server` — accept loop and handler dispatch. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_dataexchange`. |
| `service_disabled.go` | Stub `*Service` for `-tags no_dataexchange` builds. |

## Wire format

```
[4-byte type][4-byte length][payload]
```

For `TypeFile` the payload is prefixed with `[2-byte name length][name bytes]`.
For `TypeTrace` the payload is `[4-byte inner_type][8-byte sent_at_ns][inner payload]`.

Max frame size: 256 MiB.

## Build tags

| Tag | Effect |
|---|---|
| `no_dataexchange` | Compiles a no-op stub whose `Start` does nothing. Useful for integration tests that don't want inbox files written. |
