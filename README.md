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
     20 RPCs used by Verus Mobile.
   - `auth_enabled = true` requires a non-empty `[api_keys]` table in
     `Secrets.toml`; startup fails when it is missing or invalid.
   - `address_blocklist` and `txid_blocklist` live in `Secrets.toml`. An empty
     address blocklist performs no address extraction or identity-name lookup.
   - `resolve_identity_names_for_blocklist` defaults to `false`. With a
     non-empty address blocklist, `getidentity` and `getidentitycontent` must
     use direct i-addresses, and root `updateidentity` requests are rejected
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
   - Embedded `getcurrencyconverters` JSON rejects duplicate object keys.
   - The public JSON-RPC endpoint is `POST /` and does not enable browser CORS.
   - `localhost_http_port` enables a separate plaintext testing listener on
     both `127.0.0.1` and `::1`. The checked-in value, `8001`, accepts requests
     at `http://127.0.0.1:8001/`, `http://localhost:8001/`, and
     `http://[::1]:8001/`. Omit the setting to disable this listener.
     Authentication, the method whitelist, input validation, and blocklists
     apply exactly as they do on the primary listener. Browser CORS is limited
     to exact HTTP(S) origins on `localhost`, `127.0.0.1`, and `::1`; it does
     not allow credentials or expose the primary endpoint to browser origins.
   - Keep the backing daemon configured with `-enablefileencryption=0`.

   Set `logging = true` only while debugging; verbose logging includes request
   parameters.

2. Run the server:

```bash
cargo run
```

### Contributing
Contributions are welcome! Please feel free to submit a pull request.
