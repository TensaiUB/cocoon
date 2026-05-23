# COCOON Architecture

## Overview

COCOON is a decentralized AI inference platform built on the TON blockchain, enabling GPU owners to earn cryptocurrency by serving AI models in trusted execution environments (TEE).

**Key Goals:**

1. Anyone with a suitable GPU server should be able to rent it out and be compensated
2. Requests and responses remain private, known only to the client
3. Clients can verify that responses come from the requested model
4. All payments happen securely through the TON blockchain

## Components

COCOON consists of three parts: client, proxy, and worker. The client pays for requests and sends them to the proxy. The proxy selects a suitable worker and forwards the request. The worker executes requests on GPU. Both proxy and worker run inside TEE, ensuring all data (prompts, responses) remains private and cannot be accessed by server owners.

### Worker

**Role:** Executes AI inference requests inside TEE-protected VMs.

- Runs AI models (e.g., LLMs via vllm) inside confidential virtual machines
- Protected by TEE (currently Intel TDX, AMD SEV-SNP)
- Ensures all requests are kept private and the correct model is used
- Receives payment from proxies for completed work
- Minimal setup required: install image, provide config (model name, TON config, wallet address)

### Proxy

**Role:** Routes requests from clients to workers

- Protected by TEE (currently Intel TDX, AMD SEV-SNP)
- Selects appropriate workers based on model type, load and reputation
- Accepts payment from clients
- Pays workers for completed requests
- Takes commission on each transaction
- Significantly fewer proxies than workers in the network

**Current deployment:** Proxies are operated by the COCOON team for simplicity.

**Future:** Anyone will be able to run their own proxy (just like workers), creating a fully decentralized network.

### Client

**Role:** Library for sending inference requests.

- Sends requests to proxies
- Validates proxy TEE attestations to ensure requests are sent only to trusted proxies
- Pays proxies for completed requests

**Note:** The client library is designed to run on servers (backend infrastructure). For example, the Telegram backend would run multiple client instances to handle user requests.

For direct device/app usage (mobile apps, desktop apps), a separate lightweight library is being developed (WIP).

### Smart Contracts

#### Root Contract (On-Chain Registry)
**Role:** Stores allowed image and model hashes, addresses of proxies and other network-wide settings.

**Current deployment:** Currently managed by the COCOON team for simplicity.
**Future:** DAO will govern this smart contract.

#### Payment Contracts
**Role:** Stores payment information for clients and proxies. Similar to payment channels.

## Request Workflow

1. **Client establishes RA-TLS connection with proxy**, verifying proxy's TEE attestation against root contract
2. **Proxy establishes RA-TLS connection with selected worker**, verifying worker's TEE attestation
3. **Client sends inference request** (with prepayment) → **Proxy forwards to worker** → **Worker processes in TEE**
4. **Worker returns response** → **Proxy pays worker** via smart contract → **Proxy returns response to client**

All communication is encrypted via RA-TLS. Attestations are verified at connection time, not per request. Only the client can see prompts and responses.

## Security Properties

### Image Verification

Each TEE VM's identity is defined by its **image hash**, which includes:

1. **Base image** - The root filesystem and all binaries (measured by TEE)
2. **Static config** - Configuration that affects security/correctness (measured by TEE)

**Runtime config** (not measured) affects behavior but not safety or correctness. Examples:

- Model name and download location
- Root smart contract address
- Network endpoints

### Root Contract (On-Chain Registry)

The **root smart contract** on the TON blockchain serves as the trusted registry containing:

1. **List of proxy IPs** - Known proxy endpoints
2. **Allowed image hashes** - Valid proxy and worker TEE measurements
3. **Supported model hashes** - Verified AI model hashes
4. **Config parameters** - Network-wide settings (pricing, limits, etc.)
5. **Smart contract code** - Code for worker and proxy contracts

Anyone can verify against this on-chain registry.

**Governance:** Currently centralized (COCOON team manages updates). Future: decentralized governance via DAO.

### Attestation and Communication

**RA-TLS** ensures we communicate with the correct VMs:

- All connections verify TEE attestations via RA-TLS
- Handled transparently by `router` - inner VM services don't need attestation logic
- Each party verifies that the remote party's image hash matches the expected values

### GPU Verification

- The GPU is verified by the VM itself during boot (via attestation script)
- Not explicitly verified by remote parties (included in user claims if needed)
- **Security note:** A malicious host could disable the GPU, but cannot affect correctness of successful computations
- Failed GPU verification prevents the VM from starting

### Performance and Availability

**TEE does not guarantee performance:**

- Slow or hanging workers are handled via a **reputation system**
- Proxies track worker response times and success rates
- Clients can choose proxies and verify service quality
- Reputation scores are stored on-chain for transparency

## Network Topology

```
Multiple Clients
      ↓
Few Proxies (e.g., 10-100)
      ↓
Many Workers (e.g., 1000+)
```

Workers connect to proxies. Proxies track worker reputation and load-balance requests.

## Next Steps

- For TDX details: [TDX and Images](tdx-and-images.md)
- For network protocol: [RA-TLS](ra-tls.md)
- For payment system: [Smart Contracts](smart-contracts.md)

