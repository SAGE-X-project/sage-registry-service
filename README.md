# Web Registry service binding

This service serves one `did:sage:web` record and accepts controller and
delegated operator writes from a separate mTLS endpoint. Both handlers use the
same open, durable Go core journal. Each public response is generated from the latest committed
state at the service clock; no cached positive record is served.

The administrator handler requires a verified client certificate and a
configured leaf-certificate fingerprint to controller or operator identifier
mapping. Grant, revoke and lifecycle writes use the same serialized journal
transaction. The public handler checks the exact configured host and path and
returns only the core-generated JSON envelope.
The controller can grant only an operator identifier already present in the
certificate-to-actor mapping. Revocation remains possible after that mapping
is removed, so a stale grant can be cleared.

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
  "client_actors": {
    "<SHA-256 of controller leaf certificate in hex>": "controller",
    "<SHA-256 of operator leaf certificate in hex>": "operator"
  },
  "inspector_clients": ["<SHA-256 of inspector leaf certificate in hex>"],
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
POST path is `/admin/registry`. Every command includes the exact configured
`registry` HTTPS origin, `did`, `operation`, and `expected_version` strings.
Lifecycle commands (`create`, `activate`, `add-key`, `revoke-key`,
`update-services`, `deactivate`) additionally include `candidate`, the
canonical unpadded base64url of the complete proposed record envelope.
Management commands (`authorize-operator`, `revoke-operator`) instead include
`target_operator` and `scope`; they cannot include `candidate`. No other
members, repeated members or non-string values are accepted. The management
command increments the public record version and records the grant change
atomically. Successful writes return 204. The read-only Inspector endpoint is
`GET /admin/registry/inspection` on the same mTLS listener. Only separately
configured `inspector_clients` certificate fingerprints can access it; these
certificates cannot also be writers. It returns the committed version, active
grants, ordered complete history and tombstone state. The service uses bounded
HTTP/1.1 framing and TLS 1.3.

This is a deployment candidate, not a REG-08 conformance claim. Production
clock assurance, trusted filesystem recovery, and remote atomic writes remain
to be provided. Public deployment identity and storage ownership must be
independently observed.
The service pins the merged Go core revision in `go.mod`.

Run the bounded unit and real TLS runtime tests with:

```sh
go test -race ./registry
go vet ./registry
```
