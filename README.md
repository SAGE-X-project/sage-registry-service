# Web Registry service boundary prototype

This service serves one `did:sage:web` record and accepts controller writes
from a separate mTLS endpoint. Both handlers use the same open, durable Go
core journal. Each public response is generated from the latest committed
state at the service clock; no cached positive record is served.

The administrator handler requires a verified client certificate and a
configured leaf-certificate fingerprint to controller mapping. It accepts
one bounded, closed JSON request with `candidate`, `expected_version`, and
`operation` strings, and passes the authenticated actor into the core write
transaction. The public handler checks the exact configured host and path and
returns only the core-generated JSON envelope.

The executable takes one JSON configuration file. All certificate, key and
journal paths must be absolute. The configured `source` and `admin_host` must
match the respective server certificates. The first start uses `create: true`;
later starts use `create: false` with the existing journal. A failed or
uncertain journal commit deliberately retains its lock for operator review.

```json
{
  "public_listen": "127.0.0.1:8443",
  "admin_listen": "127.0.0.1:9443",
  "public_cert_file": "/secure/public-cert.pem",
  "public_key_file": "/secure/public-key.pem",
  "admin_cert_file": "/secure/admin-cert.pem",
  "admin_key_file": "/secure/admin-key.pem",
  "client_ca_file": "/secure/client-ca.pem",
  "client_actors": {"<SHA-256 of controller leaf certificate in hex>": "controller"},
  "journal_path": "/var/lib/sage-registry/registry.log",
  "did": "did:sage:web:agents.example.com:billing-bot",
  "source": "https://agents.example.com",
  "admin_host": "admin.example.com",
  "create": true
}
```

Run `sage-registry-service CONFIG.json`. The process prints one JSON line
with the bound public and administrator addresses after opening the journal.
The public GET path is `/.well-known/sage/agents/<agent-id>`; the administrator
POST path is `/admin/registry`. Administrator JSON has exactly three string
members: `candidate` (canonical unpadded base64url of the complete proposed
record envelope), `expected_version`, and `operation`. Successful writes
return 204. The service uses bounded HTTP/1.1 framing and TLS 1.3.

This is a deployment candidate, not a REG-08 conformance claim. It does not
yet provide controller-authorized operator delegation, production clock
assurance, trusted filesystem recovery, or remote atomic writes. Public
deployment identity and storage ownership must be independently observed.
The service pins the merged Go core revision in `go.mod`.

Run the bounded unit and real TLS runtime tests with:

```sh
go test -race ./registry
go vet ./registry
```
