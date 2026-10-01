# Web Registry service boundary prototype

This local prototype serves one `did:sage:web` record and accepts controller
writes from a separate mTLS endpoint. Both handlers use the same open, durable
Go core journal. Each public response is generated from the latest committed
state at the service clock; no cached positive record is served.

The administrator handler requires a verified client certificate and a
configured leaf-certificate fingerprint to controller mapping. It accepts
one bounded, closed JSON request with `candidate`, `expected_version`, and
`operation` strings, and passes the authenticated actor into the core write
transaction. The public handler checks the exact configured host and path and
returns only the core-generated JSON envelope.

This is a local design artifact, not a deployed service or a REG-08 conformance
claim. It does not yet provide listener configuration, controller-authorized
operator delegation, production clock assurance, trusted filesystem recovery,
deployment storage attestation, or remote atomic writes. The `go.mod` uses a
temporary local core replacement solely for development. Select the service
repository and dependency revision before publishing it.

Run the bounded unit and real TLS runtime tests with:

```sh
go test -race ./registry
go vet ./registry
```
