# Rust Verusd RPC Server

This repository contains a Rust library for creating a Verus RPC server. The library is designed to be simple to use, yet flexible enough to handle the needs of a variety of applications.

## Getting Started

To get started with this library, you'll need to have Rust installed on your machine. If you don't have Rust installed, you can download it from the [official website](https://www.rust-lang.org/tools/install).

### Prerequisites

- Rust programming language
- Git

### Installation

1. Clone the repository to your local machine:

```bash
git clone https://github.com/VerusCoin/rust_verusd_rpc_server.git
```

2. Navigate into the project directory:

```bash
cd rust_verusd_rpc_server
```

3. Build the project:

```bash
cargo build
```

### Usage

1. Configure the server in `Conf.toml` and credentials in `Secrets.toml` (copy
   `Secrets.example.toml` as a starting point).

   - `method_whitelist` is an additional exact method gate. An empty list falls
     back to the built-in allowlist; the checked-in configuration contains the
     22 RPCs used by Verus Mobile, including identity registration.
     `getblock` accepts omitted verbosity, booleans, or integer `0`/`1`.
   - `auth_enabled = true` requires a non-empty `[api_keys]` table in
     `Secrets.toml`; startup fails when it is missing or invalid.
   - `address_blocklist` and `txid_blocklist` live in `Secrets.toml`. An empty
     address blocklist performs no address extraction or identity-name lookup.
     The transaction blocklist applies to `getrawtransaction` and `gettxout`.
   - `resolve_identity_names_for_blocklist` defaults to `false`. With a
     non-empty address blocklist, `getidentity`, `getidentitycontent`, and
     `getidentityhistory` must use direct i-addresses. Root `updateidentity` requests are rejected
     because their target cannot be verified locally. Set it to `true` to
     resolve those selectors, root targets, and other identity-valued
     `updateidentity` fields through the daemon before comparison. This setting
     affects only internal blocklist checks, not the public `getvdxfid` RPC.
     Successful internal resolutions are cached server-wide by exact daemon
     selector, up to 4096 entries; different selectors may cache the same
     i-address, and malformed or failed resolutions are never cached.
     Address-index RPCs always require direct addresses; R-address inputs
     remain valid where the daemon accepts them.
   - `require_canonical_identity_leaf_names` defaults to `false`. Set it to
     `true` to require every `updateidentity.name` to be an unchanged canonical
     leaf name of at most 64 UTF-8 bytes; dotted and `@`-qualified selectors,
     control characters, leading/trailing or repeated spaces, and names that
     would be truncated are rejected. This check is independent of blocklists.
     With a non-empty address blocklist, parented names outside the locally
     derivable canonical subset are still rejected because their target cannot
     be checked safely. A derivable parented request must include the matching
     `identityaddress`.
   - `getcurrencyconverters` accepts 1–10 positional currency identifiers, each
     a non-empty string of at most 256 UTF-8 bytes, or a single embedded JSON
     invoice query. Embedded queries retain strict field validation and reject
     duplicate object keys; malformed queries cannot fall back to identifiers.
   - Template-only `sendcurrency` outputs accept optional `refundto` using the
     same bounds as other optional identifiers: `null` or a non-empty string
     of at most 256 UTF-8 bytes.
   - The public JSON-RPC endpoint is `POST /` and does not enable browser CORS.
     It accepts a single command or an ordered array of 1–20 commands. See
     [Batched requests](#batched-requests) for limits and failure semantics.
   - `localhost_http_port` enables a separate plaintext testing listener on
     both `127.0.0.1` and `::1`. The checked-in value, `8001`, accepts requests
     at `http://127.0.0.1:8001/`, `http://localhost:8001/`, and
     `http://[::1]:8001/`. Omit the setting to disable this listener.
     Authentication, the method whitelist, input validation, and blocklists
     apply exactly as they do on the primary listener. Browser CORS is limited
     to exact HTTP(S) origins on `localhost`, `127.0.0.1`, and `::1`; it does
     not allow credentials or expose the primary endpoint to browser origins.
   - Keep the backing daemon configured with `-enablefileencryption=0`.

   Set `logging = true` while debugging to log request metadata, item outcomes,
   timing, and response sizes. Request parameters and response bodies are not
   logged; sensitive authentication headers are redacted.

2. Run the server:

```bash
cargo run
```

### Deployment version

Query `GET /version` on either listener to identify the running server release:

```bash
curl http://127.0.0.1:8000/version
```

```json
{"version":"2.0.0"}
```

The version is compiled from `package.version` in `Cargo.toml`, using SemVer
`MAJOR.MINOR.PATCH` (release `v2.0.0`). Bump that value for future releases,
rebuild, and restart the deployment. It is the proxy's deployment version;
the daemon version and `X-VRPC-API-Version: 2` authentication protocol are
separate.

This endpoint requires no authentication, performs no daemon requests, and
returns `Content-Type: application/json` and `Cache-Control: no-store`.
Only `GET` is supported; other methods return HTTP 405 with `Allow: GET`.
The optional localhost listener retains its existing local-origin CORS policy
and supports `GET /version` preflight. The primary listener does not enable CORS.

### Batched requests

Set `batching_enabled = true` or `false` in `Conf.toml` and restart the server.
The setting defaults to `true` when omitted and applies to both listeners.
When disabled, otherwise-valid batches return one HTTP 200 error with code `-32600` and message
`Batching is disabled`, before policy lookups or command execution. Single
commands remain enabled, and authentication and resource limits still apply.
The setting must be a TOML boolean; invalid types fail startup.

Send an array of the same command objects accepted individually to `POST /`:

```json
[
  {"method": "getinfo", "params": []},
  {"method": "getblockhash", "params": [100]}
]
```

The response is an array in the same order, with one `{"result": ...}` or
`{"error": {"code": ..., "message": ...}}` object per item. Single-command
responses retain their existing shape. Caller-supplied IDs are ignored, as for
single commands; missing IDs do not suppress responses. This is an ordered
extension of this API, not a change to JSON-RPC notification behavior.

Every item passes the existing parameter allowlist, configured method whitelist,
and blocklists. Invalid items, including nested batches and non-object entries,
receive an error in their original position and are never forwarded. The valid
subset is reconstructed and sent as one native daemon batch, in input order.
Optional identity resolution during validation can add `getvdxfid` calls.
The inspected Verus daemon processes native batches sequentially; deployment on
another daemon implementation must verify that guarantee.

Authentication signs the **exact complete array body** once, using the existing
version 2 headers and one fresh salt. Reordering items or changing whitespace
after signing invalidates the token. All items belong to the same authenticated
application.

The server uses fixed conservative limits, shared across both listeners and all
connections:

| Resource | Limit |
| --- | --- |
| Commands per batch | 20 |
| Incoming body | 2 MiB, read within 5 seconds |
| Buffered/processing envelopes and retained responses | 32 |
| Active backend envelopes | 16 globally, 8 per application |
| Logical operations | 200/second globally, 100/second per application, with bursts of the same sizes |
| Uncached policy lookups per envelope | 40; each also consumes an operation token |
| Aggregate received daemon response bodies | 8 MiB, including policy lookup replies |
| Serialized client response | 8 MiB |
| Backend I/O deadline | 15 seconds shared by validation lookups and command dispatch |

Unauthenticated operation uses one shared anonymous application bucket. Limits
apply to single commands too. Admission fails immediately with HTTP 429 and
`Retry-After: 1`; no client command has executed on that path. Obtain a new
timestamp/salt/signature when retrying an authenticated rejected envelope. The
application admission registry is capped at 1,024 authenticated applications.
The replay cache is capped at 131,072 live signatures, divided equally among
configured applications; reaching capacity also returns HTTP 429 instead of
evicting signatures that still prevent replays.
Library users must share one `Arc<VerusRPC>` across connections to share these
limits; the provided executable does so.

Malformed JSON returns a parse error. Empty or oversized batches return one
invalid-request error before backend work. Per-item validation and daemon errors
use HTTP 200, as with individual commands. Missing backend replies become errors
in the corresponding positions; untrustworthy batch replies or transport
failures produce errors for the dispatched subset. A response-size overflow
retains small known errors and replaces unavailable results with errors.

**Batches are not transactions.** Individual errors do not stop later commands;
earlier effects are not rolled back, and other daemon activity can interleave.
Later items cannot reference earlier results as parameters. A timeout, lost
connection, or unavailable response can leave execution outcomes unknown. The
server never automatically retries or falls back to individual calls. Clients
must reconcile state before retrying mutations. Closing the HTTP request does
not cancel work already accepted by the daemon; proxy byte/deadline limits do
not limit daemon-side execution or memory allocation.

Usage snapshots retain their existing HTTP-envelope `counts` and add `rpc_items`
totals since process start: `attempted`, `forwarded`, `rejected`, and
`policy_lookups`. Item counts cover structurally accepted envelopes, including
admission and per-item rejections. `forwarded` counts items handed to backend
dispatch, not confirmed execution or success. Logging includes each item's
position so mixed success/error batches can be diagnosed without logging bodies.

Daemon transport uses HTTP (normally loopback), supports bounded persistent
connections, and does not follow redirects or retry failed requests. Library
constructors now return `BackendError` instead of `jsonrpc::simple_http::Error`.

### Contributing
Contributions are welcome! Please feel free to submit a pull request.
