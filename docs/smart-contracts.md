# Smart Contracts and Payment System

## Overview

COCOON uses the TON blockchain for:
1. **Worker registration** - Workers register with the network
2. **Payment settlement** - Clients pay proxies, proxies pay workers
3. **Reputation tracking** - On-chain reputation scores
4. **Registry** - Root contract that maintains a list of allowed images, models, proxies

## Architecture

```
Client Wallet
    ↓ (pay for inference)
Proxy Contract
    ↓ (pay for work)
Worker Contract
    ↓ (withdraw earnings)
Owner Wallet
```

## Root Contract (Registry)

The root smart contract on TON blockchain contains:
- List of proxy IPs
- Allowed image hashes (valid TEE measurements)
- Supported model hashes
- Network configuration parameters
- Smart contract code for workers and proxies

Governance: Currently centralized (COCOON team), future: DAO.

## Proxy Contract

The proxy smart contract is used for all payments associated with one specific proxy instance. No two instances can share one common private key, so every proxy instance will generate its own instance of a proxy contract.

The proxy contract is used:
- to hold all payments of all clients to this specific proxy
- to notify the proxy of an incoming payment / change of a client or a worker configuration
- to process client and worker requests for payment or withdrawal of funds
- as a way for a proxy to independently commit its state to the blockchain and to mitigate some attacks associated with copying or reverting the state of a proxy

It should also be noted that changing one of the core parameters (like ***price per token***) will result in a redeployment of a proxy contract. The old contract will stay alive until a safe closure, i.e. completion of all payments and withdrawals and finally contract closure.

## Client Contract

The client contract is specific to one proxy and one client. It is used to track:
- the current balance of the client
- how much was already charged from this client
- how big the client's stake is

Paid funds are kept in the associated proxy contract. The client can always top up the balance, increase its stake or withdraw from its balance. The only restriction is that after withdrawal, the balance can not be less than the amount staked.

### Stake

The stake is used by a proxy to determine how often the client should be charged. As a general guideline, it should not be lower than the amount of tokens used per 10 minutes. On the other hand, staked TON cannot be returned immediately when the proxy is down, so it makes sense not to increase the amount unnecessarily.

### Closing the Contract

The client can always initiate closure of the contract to get back all funds including the stake. In a normal situation, the proxy will see a withdrawal request and grant it immediately. 

If the proxy is down or has network issues, then the part of the balance above the staked amount will be returned immediately, but the client will have to wait for ***client close delay*** seconds (we expect it to be about one day) to get the stake back. In this case, the stake will be returned from the proxy's stake and not the actual balance, so if parameters are set incorrectly and proxy's stake is too low, the client may lose some of its stake.

Note that in this case, nobody will be able to get these funds as they will remain frozen on the contract, so there is no way for a proxy to abuse this system. As soon as the proxy eventually gets back online, the remaining part of the stake will be paid back.

## Worker Contract

The worker contract is specific to one proxy and one worker. It is used to track how many tokens were already paid to this worker. It's the simplest contract in the system.

## Payment Flow

The proxy signs all payment requests. So the proxy's private key must not be available outside of the enclave as it could compromise the payment system's integrity. The proxy keeps track of the payments and commits this data to the local database.

### Blockchain Commits

The proxy also commits some related information to the blockchain so that it's impossible to rollback the database. When a worker connects, the proxy compares its information with the worker's reported earnings, and if it detects parts of the database missing, it will refuse to work further.

When the proxy commits information to the blockchain, it sends clients and workers signed messages that can be used to charge/pay if the client/worker wants. Since a blockchain operation is associated with relatively high commissions (~0.01 TON per operation), normally they don't immediately commit these messages to the blockchain. 

Notably, a client normally commits this message if it has used a substantial part of its stake (e.g., 50%). A worker can do it even more rarely, such as when it has earned N TON (e.g., 10).

### Closing the Contract

If a client wants to close the contract, the proxy will sign a last charge message, which then can be used to refund all the funds. The worker doesn't ever need to close the contract, as the worker has nothing to gain from this procedure.

If a proxy is down for a long time, the client can still get at least part of the stake by the means described in the client contract section. 

Notably, a proxy can return its stake and collect the remaining fees only after closing all client and worker contracts. So if a proxy is down, its owner cannot access its funds without paying out everything it should.

## TON Integration

COCOON uses the `tonlib` C++ library directly (not HTTP API) for:
- Querying account states
- Sending external messages
- Monitoring transactions
- Block streaming

**Why tonlib?**
- Full node verification (doesn't trust third parties)
- Cryptographic proof of state

## Wallet Management

Workers derive wallet keys from TEE persistent keys (see [Seal Keys](seal-keys.md)).

Mitigation for key loss: Custom payment channels with timeout fallback.

## Next Steps

- For wallet key derivation: [Seal Keys](seal-keys.md)
- For deployment: [Deployment](deployment.md)
- For architecture: [Architecture](architecture.md)
