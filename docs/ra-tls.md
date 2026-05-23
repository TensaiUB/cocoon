# RA-TLS (Remote Attestation over TLS)

## Overview

RA-TLS embeds TDX attestation directly into TLS certificates, enabling both encryption and remote attestation in a single handshake.

**Traditional TLS:** Server has certificate signed by trusted CA, proves DNS identity.

**RA-TLS:** Server has self-signed certificate with TDX quote embedded, proves code identity.

## Why RA-TLS?

In COCOON, verification is **bidirectional** (mutual authentication):
- **Client → Proxy:** Client verifies proxy is running the correct TDX image
- **Proxy → Worker:** Proxy verifies worker is running the correct TDX image
- **Worker → Proxy:** Worker verifies proxy is running the correct TDX image

Both parties present RA-TLS certificates and verify each other during the TLS handshake.

## Certificate Format

Implementation in [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - function `generate_tdx_self_signed_cert`.

### Structure

Self-signed X.509 certificate (depth 0) with Ed25519 key:

```
X.509 Certificate
├── Subject: CN=cocoon-worker, O=TDLib Development, ...
├── Issuer: (same as subject - self-signed)
├── Public Key: Ed25519 (32 bytes)
├── Signature: Ed25519 self-signature
├── Validity: 1 day (short-lived)
└── Extensions:
    ├── [Standard]
    │   ├── Basic Constraints: CA:FALSE (critical)
    │   ├── Key Usage: digitalSignature (critical)
    │   ├── Extended Key Usage: serverAuth, clientAuth (critical)
    │   ├── Subject Key Identifier: hash
    │   └── Subject Alternative Name: DNS:localhost, IP:127.0.0.1, ...
    └── [Custom - TDX Attestation]
        ├── [1.3.6.1.4.1.12345.1] TDX_QUOTE → Binary TDX quote (~5-10 KB)
        └── [1.3.6.1.4.1.12345.2] TDX_USER_CLAIMS → Serialized user claims
```

### Custom OIDs

We use private enterprise OID space `1.3.6.1.4.1.12345.*`:

- `1.3.6.1.4.1.12345.1` - **TDX_QUOTE**: Raw TDX quote bytes
- `1.3.6.1.4.1.12345.2` - **TDX_USER_CLAIMS**: Serialized user claims

Both extensions are marked as **critical** so non-aware TLS implementations will reject them (fail-safe).

### User Claims

Currently minimal (see [`tee/cocoon/tdx.h`](../tee/cocoon/tdx.h) and [`tdx.cpp`](../tee/cocoon/tdx.cpp)):

```
struct UserClaims {
  PublicKey public_key;  // Certificate's Ed25519 public key (32 bytes)
}
```

Serialization: just the raw public key bytes (32 bytes).

Future extensions could include: timestamp, GPU attestation, config hash, version, etc.

## Certificate Generation

### Process

1. Generate Ed25519 keypair
2. Build UserClaims with public key
3. Hash claims (SHA-512 → 64 bytes)
4. Generate TDX quote with reportdata = claims_hash
5. Create X.509 certificate with quote and claims in extensions
6. Sign certificate with private key

Implementation in `generate_tdx_self_signed_cert` enforces that `user_claims.public_key` matches the certificate's public key (prevents quote reuse attacks).

### Using `gen-cert` Tool

See [`tee/cocoon/gen-cert.cpp`](../tee/cocoon/gen-cert.cpp):

```bash
# No attestation (development)
./gen-cert --name dev --tee none

# Fake attestation (testing without TEE hardware)
./gen-cert --name test --tee fake_tee

# Real TDX attestation (production, must run inside TEE)
./gen-cert --name worker --tee tee --force
```

Outputs:
- `<name>_cert.pem` - Certificate with embedded quote
- `<name>_key.pem` - Ed25519 private key
- `<name>_image_hash.b64` - TEE image hash (base64)

## Certificate Verification

Implementation in [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - struct `Verifier`.

During TLS handshake, the custom verify callback performs the following checks:

### Verification Steps

1. **Allow self-signed certificates at depth 0**
   - Accept `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` error
   - Accept `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION` error
   - We expect self-signed certs with custom extensions

2. **Reject certificates at depth > 0**
   - Only self-signed (depth 0) allowed
   - No certificate chains

3. **Verify critical extensions unknown to OpenSSL**
   - Skip non-critical extensions
   - Skip extensions OpenSSL natively supports (Basic Constraints, Key Usage, etc.)
   - For critical extensions unknown to OpenSSL: only allow TDX_QUOTE and TDX_USER_CLAIMS
   - Reject any other unknown critical OID

4. **Extract TDX extensions**
   - Extract TDX_QUOTE (may be absent for "any" policy)
   - Extract TDX_USER_CLAIMS

5. **Extract and validate public key**
   - Must be Ed25519 (32 bytes)
   - Reject other key types

6. **Build UserClaims from certificate**
   - Currently: just set `public_key` from certificate
   - Future: deserialize additional fields from TDX_USER_CLAIMS extension

7. **Validate quote and claims via policy**
   - Call `policy->validate(quote, user_claims)`
   - Policy checks measurements, image hash, etc.

If all checks pass → connection allowed.

## Policy System

Implementation in [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - struct `DefaultPolicy`.

### Built-in Policies

- **`any`** - No attestation required (no TdxInterface)
- **`fake_tee`** - Accept fake quotes for testing
- **`tee`** - Require real TDX with default checks
- **`tee` with constraints** - Require specific measurements

### Policy Constraints

Policies can specify allowed values for:
- `allowed_mrtd` - Allowed firmware measurements
- `allowed_rtmr` - Allowed runtime measurement sets (all 4 RTMRs)
- `allowed_image_hashes` - Allowed image hashes (derived from MRTD+RTMRs)
- `allowed_collateral_root_hashes` - Allowed Intel root key IDs

Empty lists mean "allow any" for that field.

### Policy Validation

See [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - function `DefaultPolicy::validate_tdx_attestation`. Policy checks:

1. **Reportdata matches user claims** - Verify `attestation.reportdata == SHA-512(user_claims)`
2. **MRTD in allowlist** - Check firmware measurement (if policy specifies)
3. **RTMRs in allowlist** - Check all four runtime measurements (if policy specifies)
4. **Image hash in allowlist** - Check derived image hash (if policy specifies)
5. **Collateral root hash in allowlist** - Check Intel DCAP root key ID (if policy specifies)

All checks must pass for validation to succeed.

## Image Hash Calculation

Implementation in [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - function `AttestationData::image_hash`.

Image hash is SHA-256 of attestation data (MRTD + RTMRs + other measurements), **excluding reportdata**.

**Why exclude reportdata?**
- Reportdata changes per certificate (contains hash of public key)
- Image hash should be constant for the same image
- Image hash identifies the code, not the specific instance

This hash is used in policy validation and stored in the root contract.

## Using `router`

The `router` tool ([`tee/cocoon`](../tee/cocoon)) provides transparent RA-TLS proxying. See [README](../tee/cocoon/README.md) for detailed usage.

### SOCKS5 Proxy

Applications make outbound connections through proxy:

```bash
./router --cert worker --socks5 1080@tdx
```

Proxy verifies remote servers have valid TDX attestation before forwarding traffic.

### Reverse Proxy

Accept inbound connections and verify clients:

```bash
./router --cert proxy --rev 9000:localhost:8080@tdx
```

Remote clients must present valid TDX certificates to connect.

### Defining Policies

Policies can be defined with `--policy` flag:

```bash
./router --cert worker \
  --policy strict:tdx:abc123... \
  --socks5 1080@strict
```

Or use JSON config file. See `router --generate-config` for examples.

## TLS Configuration

Implementation in [`tee/cocoon/tdx.cpp`](../tee/cocoon/tdx.cpp) - function `create_ssl_ctx`.

### Protocol and Ciphers

- **TLS 1.3 minimum** - Better security, simpler handshake, modern ciphers
- **Cipher suites:** `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` only

### Session Management

- **No session tickets** (`SSL_OP_NO_TICKET`) - Each connection performs full RA verification
- **No session resumption** - Intentional: we want fresh attestation verification per connection
- Verification results are cached (see Attestation Caching section)

### Mutual TLS

Both client and server modes verify peer certificates:
- Client mode: Verifies server certificate
- Server mode: Verifies client certificate, requires client to present certificate

Both parties must present valid RA-TLS certificates - full mutual authentication.

## Security

### Certificate Binding

**Critical:** The certificate's public key MUST be included in user claims.

The implementation in `generate_tdx_self_signed_cert` enforces this. Without this binding, attackers could steal quotes from good VMs and attach them to their own certificates.

**How it works:**
- Quote's reportdata = SHA-512(user_claims)
- User claims contain the public key
- Different public key → different reportdata → verification fails

### Bidirectional Verification Support

Both parties may verify each other's TDX attestations:
- Proxy verifies worker's quote and image hash
- Worker verifies proxy's quote and image hash

This prevents workers connecting to malicious proxies and proxies accepting fake workers.

### Quote Replay Protection

TDX quotes lack timestamps (hardware doesn't know time). Mitigations:
- Short certificate lifetimes (1 day)
- Can include timestamp in user claims (verified by policy)
- Daily regeneration

### PCCS and Intel Root Key Verification

Quote verification requires "collaterals" from Intel via PCCS (Provisioning Certificate Caching Service).

**Two key points:**
1. **Must use PCCS** - Intel's rules require fetching collaterals via PCCS (not directly)
2. **Untrusted PCCS is fine** - We verify Intel's root key ID

**How it works:**

During quote verification (`RealTdxInterface::validate_quote`), we extract the Intel root key ID from the verification result. Our policy checks this ID against an embedded whitelist of known Intel root keys (see default value in [`router.cpp`](../tee/cocoon/router.cpp)).

This prevents:
- Fake PCCS providing collaterals signed by compromised/fake root certificates
- MITM attacks on collateral fetching

PCCS can only cache and serve collaterals, but cannot forge valid quotes because we verify the root key ID.

### TLS Extensions vs X.509 Extensions

Alternative approach: Use TLS protocol extensions and generate a fresh attestation for each connection (like draft-fossati-tls-attestation).

**Why we use X.509 extensions instead:**

1. **Performance:** TLS extensions require generating a new quote per connection (~50ms overhead). X.509 allows reusing the same certificate/quote for multiple connections.

2. **Implementation simplicity:** Easier to implement with standard X.509 APIs and existing TLS libraries.

**Time verification:**

With TLS extensions, each connection generates a fresh attestation, so you know it's recent. With reusable certificates (our approach), the attestation could be up to 1 day old.

We handle time verification differently:

- **Certificate generation:** Bounded by blockchain time (certificates cannot be created in the future)
- **Runtime verification:** Parties verify time similarity via pings during communication

This provides sufficient freshness guarantees without regenerating quotes per connection.

## Next Steps

- For TDX fundamentals: [TDX and Images](tdx-and-images.md)
- For persistent keys: [Seal Keys](seal-keys.md)
- For router usage details: [README](../tee/cocoon/README.md)
- For deployment: [Deployment](deployment.md)
