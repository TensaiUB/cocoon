# Persistent Key Derivation (Seal Protocol)

## Problem

TDX guests need persistent keys that:

1. **Survive reboots** - Same key after VM restart
2. **Tied to code** - Different image → different key
3. **Hardware-backed** - Cannot be extracted by host
4. **Isolated per config** - Malicious config can't access good config's key

**Challenge:** TDX 1.5 doesn't have native sealed storage (coming in future TDX 2.0 via `TDG.MR.KEY.GET`).

**Solution:** Use SGX enclave on the host to derive keys based on TDX attestation.

## Architecture

```
TDX Guest (Worker)          Host                SGX Enclave
      |                      |                        |
      | 1. Generate EC P-256 keypair                 |
      |                      |                        |
      | 2. Get TDX report (reportdata = SHA256(pubkey))
      |                      |                        |
      | 3. getPersistentKey(tdx_report, pubkey)      |
      |--------------------->|                        |
      |                      | 4. ecall_gen_key()    |
      |                      |----------------------->|
      |                      |                        | 5. Verify tdx_report (local MAC)
      |                      |                        | 6. Derive key from sealing_key + tee_info
      |                      |                        | 7. Encrypt key with pubkey (ECDH)
      |                      |                        | 8. Generate SGX quote
      |                      |                        |
      |                      | 9. encrypted_key, sgx_quote
      |                      |<-----------------------|
      | 10. persistentKey(sgx_quote, encrypted_key)  |
      |<---------------------|                        |
      | 11. Verify SGX quote                          |
      | 12. Decrypt key (ECDH)                        |
      | 13. Use key for encrypted storage             |
```

## Protocol Specification

Implementation: [`tee/cocoon/tdx/sgx-enclave/seal-client.cpp`](../tee/cocoon/tdx/sgx-enclave/seal-client.cpp), [`seal-server.cpp`](../tee/cocoon/tdx/sgx-enclave/seal-server.cpp), [`Enclave.cpp`](../tee/cocoon/tdx/sgx-enclave/Enclave.cpp).

### Transport

- **Protocol:** Binary over VSOCK (virtual socket)
- **Framing:** 4-byte length prefix, one request → one response
- **Serialization:** TL (Type Language)
- **Connection:** TDX guest (any CID) ↔ Host (CID 2) ↔ SGX enclave

### TL Schema

```tl
getPersistentKey#317a821c tdx_report:bytes public_key:bytes key_name:bytes = PersistentKey;
persistentKey#163a179a sgx_quote:bytes encrypted_secret:bytes = PersistentKey;
```

### Message Format

**Request (`getPersistentKey`):**
- `tdx_report` - TDX report structure (`sgx_report2_t`, 1024 bytes)
  - reportdata = `SHA256(public_key) || 32 zero bytes`
- `public_key` - EC P-256 public key (64 bytes, X||Y coordinates in little-endian)
- `key_name` - String identifying key purpose (e.g., "worker-wallet")

**Response (`persistentKey`):**
- `sgx_quote` - SGX quote from Intel QE (Quoting Enclave)
  - reportdata = `SHA256(public_key) || SHA256(encrypted_secret)`
- `encrypted_secret` - 96 bytes total:
  - Bytes 0-63: Enclave's EC P-256 public key
  - Bytes 64-95: AES-128-CTR ciphertext (encrypted persistent key)

## Protocol Flow

### Step 1: TDX Guest Generates Request

Implementation in [`seal-client.cpp`](../tee/cocoon/tdx/sgx-enclave/seal-client.cpp) - class `GetPersistentKeyClient`.

1. Generate ephemeral EC P-256 keypair
2. Calculate reportdata = `SHA256(public_key) || 32 zero bytes` (64 bytes total)
3. Request TDX report from hardware with this reportdata
4. Serialize request with TDX report, public key, and key name
5. Send to host via VSOCK

**Key insight:** The TDX report's MAC can only be verified locally (on the same CPU). This proves the request came from the TDX guest on this specific machine.

### Step 2: Host Forwards to SGX Enclave

Implementation in [`seal-server.cpp`](../tee/cocoon/tdx/sgx-enclave/seal-server.cpp) - class `GetPersistentKeyServer`.

1. Receive and deserialize request from VSOCK
2. Call SGX enclave via ECALL: `ecall_gen_key(target_info, tdx_report, public_key, key_name, ...)`
3. Enclave returns: `encrypted_secret` and `sgx_report`
4. Call Intel QE to generate SGX quote from SGX report
5. Serialize response with SGX quote and encrypted secret
6. Send back to guest via VSOCK

**Host is untrusted:** It just forwards messages, it cannot decrypt or forge keys.

### Step 3: SGX Enclave Generates Key

Implementation in [`Enclave.cpp`](../tee/cocoon/tdx/sgx-enclave/Enclave.cpp) - function `ecall_gen_key`.

#### 3.1. Validate TDX Report

1. Verify TDX report structure (type=0x81, version, etc.)
2. Verify reportdata = `SHA256(public_key) || 32 zero bytes`
3. Verify TDX report MAC using `sgx_verify_report2()`
   - **Critical:** MAC verification proves TDX and SGX are on same CPU
   - Only the CPU that generated the report can verify its MAC

#### 3.2. Derive Persistent Key

1. Get SGX sealing key with policy `SGX_KEYPOLICY_MRENCLAVE`
   - Sealing key is unique to this enclave's code hash
   - Changes if enclave code changes

2. Combine sealing key with TDX measurements:
   ```
   persistent_key = SHA256(
     sealing_key ||          # 16 bytes - SGX enclave identity
     tee_info_hash ||        # 48 bytes - TDX measurements (MRTD, RTMRs)
     tee_tcb_info_hash ||    # 48 bytes - TDX TCB level
     SHA256(key_name)        # 32 bytes - Key purpose identifier
   )
   ```

3. Result: 32-byte key unique to (SGX enclave code, TDX image, TDX config, key name)

**Why include key_name:** It allows for deriving multiple independent keys for different purposes (wallet, storage, etc.) from the same base measurements.

#### 3.3. Encrypt Persistent Key

1. Generate ephemeral EC P-256 keypair (enclave_private, enclave_public)
2. Perform ECDH: `shared_secret = ECDH(enclave_private, client_public)`
3. Derive encryption keys: `key_iv_hash = SHA256(shared_secret)`
   - AES key = first 16 bytes of key_iv_hash
   - IV = next 16 bytes of key_iv_hash
4. Encrypt: `ciphertext = AES-128-CTR(persistent_key, key, iv)`
5. Build encrypted_secret = `enclave_public (64 bytes) || ciphertext (32 bytes)` (96 bytes total)

#### 3.4. Generate SGX Report

Create SGX report with reportdata binding this exchange:
- First 32 bytes: `SHA256(client_public)` - proves we're responding to this specific request
- Next 32 bytes: `SHA256(encrypted_secret)` - proves integrity of encrypted data

### Step 4: TDX Guest Verifies and Decrypts

Implementation in [`seal-client.cpp`](../tee/cocoon/tdx/sgx-enclave/seal-client.cpp) - class `GetPersistentKeyClient`.

#### 4.1. Verify SGX Quote

1. Receive response and deserialize
2. Verify SGX quote using Intel DCAP libraries
3. Extract `MR_ENCLAVE` from quote
4. **Verify MR_ENCLAVE matches expected value** (critical security check!)
   - This proves the correct SGX enclave code generated the key
   - Without this check, host could run malicious enclave

#### 4.2. Verify Report Data

Check SGX quote's reportdata = `SHA256(client_public) || SHA256(encrypted_secret)`:
- First part proves this response is for our request (not replayed)
- Second part proves encrypted_secret integrity (not tampered)

#### 4.3. Decrypt Persistent Key

1. Extract from encrypted_secret:
   - Enclave's public key (first 64 bytes)
   - Ciphertext (last 32 bytes)
2. Perform ECDH: `shared_secret = ECDH(client_private, enclave_public)`
3. Derive decryption keys: `key_iv_hash = SHA256(shared_secret)`
4. Decrypt: `persistent_key = AES-128-CTR-decrypt(ciphertext, key, iv)`

Result: 32-byte persistent key, same key on every reboot (if same image/config).

## Key Properties

The persistent key depends on:

- **SGX sealing key** - Changes if SGX enclave code changes (MRENCLAVE policy) and is bound to physical CPU
- **tee_info_hash** - TDX measurements (includes MRTD, RTMRs, config hash)
- **tee_tcb_info_hash** - TDX TCB/firmware version
- **key_name** - Purpose identifier (allows multiple keys)

**Result:** Different (CPU, SGX enclave, TDX image, TDX config, key name) → different key.

## Co-location Proof

**Question:** How do we know SGX and TDX are on the same physical machine?

**Answer:** TDX report MAC verification (`sgx_verify_report2`).

The TDX report contains a MAC computed with a platform-specific key (REPORT_KEY) that:
1. Never leaves the CPU
2. Derived from CPU's hardware fuses
3. Only knowable by the same physical CPU

When SGX successfully verifies the TDX report MAC, it proves:
- TDX and SGX are on the same physical CPU
- TDX report is authentic (not forged)
- No network communication needed (local verification)

**Critical dependency:** Must verify SGX enclave's `MR_ENCLAVE`. Otherwise, host could run a fake enclave that doesn't verify the MAC.

## Security

### What We Achieve

- **Persistent keys:** Same key after reboot (if same image)
- **Code binding:** Different image → different key
- **Config isolation:** Malicious config gets different key
- **Hardware backing:** Key derived in SGX, cannot be extracted
- **Co-location proof:** TDX and SGX verified to be on the same CPU
- **Multiple keys:** Different key_name → different keys

### Limitations

- **Key loss:** If the CPU fails, key is lost forever (hardware-bound, no backup possible)
- **Side channels:** Advanced attacks on SGX/TDX might leak keys

**Note:** Replay attacks are prevented - each request uses a fresh ephemeral public key, so old TDX reports cannot be reused.

### Mitigation of key loss

We use custom payment channels, so there is a fallback (timeout) in case the key is lost.

In case of workers, we may use a key known to the owner of the workers.

## Usage

### Components

Three components work together:

1. **seal-client** (TDX guest) - Requests key: `seal-client`
2. **seal-server** (Host) - Forwards requests: `seal-server`
3. **seal-enclave** (SGX) - Generates keys: `seal-enclave.signed.so`

Implementations in [`tee/cocoon/tdx/sgx-enclave/`](../tee/cocoon/tdx/sgx-enclave/).

### Setup

Host runs seal-server, TDX guest runs seal-client over VSOCK. QEMU configuration includes VSOCK device.

### During Boot

Called by [`reprodebian/cocoon-init/cocoon-init`](../reprodebian/cocoon-init/cocoon-init):

1. `seal-client` requests key
2. Key used for LUKS encryption and wallet derivation
3. Same image+config always produces the same key (deterministic)

## Design Decisions

### TDX Report (Not Quote)

We use TDX report (not quote) in the request because:
- Contains MAC verifiable locally by SGX (no network needed)
- Fast generation (~1ms vs ~50ms for quote)
- SGX can verify with `sgx_verify_report2()`

Response uses SGX quote because TDX guest needs to verify SGX attestation (has DCAP libraries).

### Custom Protocol (Not TLS)

SGX enclaves have limited library support. Custom binary protocol over VSOCK is simpler than using TLS in SGX.

## Future: Native TDX Sealing

TDX 2.0 will provide `TDG.MR.KEY.GET` instruction for native sealed storage - it is simpler (no SGX needed) with same security properties.

## Next Steps

- For TDX details: [TDX and Images](tdx-and-images.md)
- For encrypted storage usage: [TDX and Images](tdx-and-images.md)
- For wallet management: [Smart Contracts](smart-contracts.md)
