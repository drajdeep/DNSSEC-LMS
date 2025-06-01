


# LMS (Leighton-Micali Signatures) Implementation Documentation

## Overview
This document details the implementation of a hash-based post-quantum signature scheme based on RFC 8554 (LMS) for DNSSEC applications. The system combines:
- LM-OTS (One-Time Signatures)
- Merkle tree authentication
- SHA-256 truncated to 192-bit for efficiency

## Table of Contents
1. [System Parameters](#system-parameters)
2. [Key Components](#key-components)
3. [Core Algorithms](#core-algorithms)
4. [Signature Generation](#signature-generation)
5. [Verification Process](#verification-process)
6. [File Format](#file-format)
7. [Security Analysis](#security-analysis)
8. [DNSSEC Integration](#dnssec-integration)

---

## System Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `N`       | 24    | Hash output size (bytes) = 192-bit |
| `W`       | 16    | Winternitz parameter (base-65536) |
| `P`       | 16    | Signature elements = (8*N/W) + 4 |
| `H`       | 6     | Merkle tree height → 64 leaves |
| `LEAVES`  | 64    | 2^H one-time key pairs |

**Design Choices:**
- **192-bit hashes**: Truncated SHA-256 balances security and performance
- **W=16**: Optimizes for signature size (P=16) vs computation (65k hashes)
- **Merkle H=6**: Supports 64 signatures per root key

---

## Key Components

### 1. LM-OTS Key Pair
```c
typedef struct {
    uint8_t sk[P][N];   // Private key (16x24B random values)
    uint8_t pk[P][N];   // Public key (each sk[i] hashed 65,535 times)
} WOTS_Keypair;
```

### 2. Merkle Tree Structure
- **Leaves**: SHA-192 hashes of LM-OTS public keys
- **Nodes**: 127 total (64 leaves + 63 internal nodes)
- **Root**: Ultimate public key (24 bytes)

---

## Core Algorithms

### 1. Hash Function
```c
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);      // Standard SHA-256
    memcpy(out, full, N);         // Truncate to 192-bit
}
```
*Rationale*: SHA-256 provides cryptographic strength while truncation reduces storage.

### 2. LM-OTS Public Key Generation
```python
for i in 0..15:
    pk[i] = sk[i]
    for j in 0..65534:
        pk[i] = SHA192(pk[i])
```
*Security*: One-wayness relies on preimage resistance of SHA-192.

### 3. Merkle Tree Construction
```python
# Bottom-up construction
for level from (H-1) downto 0:
    for node in level:
        parent = SHA192(left_child || right_child)
```
*Efficiency*: O(N) space with 2^(H+1)-1 nodes.

---

## Signature Generation

### Inputs
- LM-OTS private key (`sk`)
- Message: `(LM-OTS-PK || DNSKEY record)`

### Steps:
1. **Hash Message** → 192-bit digest
2. **Split Digest**:
   - 12× 16-bit chunks (message)
   - 4× 16-bit chunks (checksum)
   ```c
   checksum = Σ(65535 - chunks[0..11])
   ```
3. **Generate Signature**:
   ```c
   for i in 0..15:
       sig[i] = hash^chunks[i](sk[i])
   ```

---

## Verification Process

1. **Recover Public Key**:
   ```c
   for i in 0..15:
       tmp = sig[i]
       for j in 0..(65535 - chunks[i]):
           tmp = SHA192(tmp)
       pk[i] = tmp
   ```
2. **Rebuild Leaf**:
   ```c
   leaf = SHA192(pk[0] || pk[1] || ... || pk[15])
   ```
3. **Recompute Root**:
   ```c
   current = leaf
   for level in 0..5:
       sibling = auth_path[level]
       current = (position % 2 == 0) ? 
                 SHA192(current || sibling) : 
                 SHA192(sibling || current)
   ```
4. **Validate**: `current == stored_root`

---

## File Format (`lms_signature.bin`)

| Offset (bytes) | Size       | Content                  |
|----------------|------------|--------------------------|
| 0              | 384        | 16×24B signature elements|
| 384            | 144        | 6×24B auth path nodes    |
| 528            | 24         | Merkle root              |
| 552            | 384        | 16×24B LM-OTS public key |

**Total Size**: 936 bytes

---

## Security Analysis

### 1. Attack Resistance
| Attack Type          | Mitigation |
|----------------------|------------|
| Collision Attacks    | 192-bit hash strength |
| Preimage Attacks     | SHA-256 security |
| Signature Forgery    | Checksum in WOTS+ |
| Key Reuse           | One-time keys + Merkle tree |

### 2. Quantum Resistance
- Security relies on hash function strength
- No known quantum algorithm breaks SHA-256/192

---

## DNSSEC Integration

### Signature Flow
1. **Signer**:
   - Generates Merkle tree of LM-OTS keys
   - Signs `(OTS-PK || ZSK)` with selected OTS key
   - Publishes root in DNSKEY RR

2. **Verifier**:
   - Receives signature + auth path
   - Rebuilds root using ZSK from DNS
   - Validates against published root

### Advantages
- **Post-quantum secure**
- **Small signatures** (936B vs 4KB for RSA-4096)
- **Key rotation** via Merkle leaves

