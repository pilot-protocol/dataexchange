module github.com/pilot-protocol/dataexchange

go 1.25.10

require (
	github.com/pilot-protocol/common v0.2.0
	github.com/pilot-protocol/eventstream v0.1.0
)

require github.com/TeoSlayer/pilotprotocol v0.0.0 // indirect

replace github.com/TeoSlayer/pilotprotocol => ../web4

replace github.com/pilot-protocol/common => ../common
