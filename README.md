# LMS as KSK in Post-Quantum DNSSEC

This repository provides an implementation of the Modified Leighton-Micali Signature (LMS) scheme as a Key Signing Key (KSK) for Post-Quantum DNSSEC. It simulates the LMS signing and verification process using LM-OTS keypairs and a Merkle tree, outputs a DNSKEY-signed zone signature, and includes benchmarking metrics for performance and resource usage.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Usage](#usage)
- [Benchmarking](#benchmarking)
- [Signature Size](#signature-size)
- [Code Structure](#code-structure)

---

## Overview

The LMS (Leighton-Micali Signature) scheme is a hash-based post-quantum digital signature system standardized by NIST. In DNSSEC, a Key Signing Key (KSK) signs Zone Signing Keys (ZSKs) to ensure the authenticity of DNS records. This implementation:

- Generates LM-OTS keypairs (private/public).
- Constructs a Merkle tree over LM-OTS public key hashes.
- Signs a combined message of an LM-OTS public key and a sample ZSK DNSKEY record.
- Outputs an LMS signature file (`lms_signature.bin`) containing signature elements, authentication path, Merkle root, and LM-OTS public key.
- Verifies the signature from the file using the provided LM-OTS public key and Merkle path.
- **LMS signature format is customized to fit within the UDP safe limit (1232 bytes)** to avoid TCP fallback and DNS fragmentation.

---

## Features

- **LM-OTS key generation** with Winternitz parameter *W = 32*.
- **Merkle tree** of height *H = 10* (1024 leaves).
- **SHA-192** as the hash function (first 24 bytes of SHA-256).
- **Signature file** stores all required components.
- **Verification file** validates the signature without regenerating public keys.
- **Benchmarking** of time and memory usage for each step.

---

## Prerequisites

- GCC with C99 support
- OpenSSL development libraries (for SHA-256)
- Unix-like environment (for `/proc/self/status` memory usage)

---

## Build Instructions

```sh
gcc ksk_lms.c -o ksk_lms -lssl -lcrypto -lm
gcc lms_verify.c -o lms_verify -lssl -lcrypto -lm
```

---

## Usage

### Signing:

```sh
./ksk_lms
```

Generates:

- Console output of each step (keypair generation, Merkle tree, digest, signature)
- `lms_signature.bin` containing the binary LMS signature components

### Verifying:

```sh
./lms_verify
```

Verifies the generated LMS signature and prints:

- Message digest
- Reconstructed vs. expected Merkle root
- Time and memory usage
- Signature validity result

---

## Benchmarking

Measured on a standard desktop environment:

### Signing Phase

| Step                                    | Time (s) | Memory Usage (RSS KB)   |
| --------------------------------------- | -------- | ----------------------- |
| LM-OTS Keypair Generation               | 162.9968 | \~5,532                 |
| Merkle Tree Construction                | 0.0004 =0.4ms   | (no significant change) |
| Message Digest Hashing                  | \~0.0000 | (no significant change) |
| LM-OTS Signature Generation             | 0.0709   | (no significant change) |
| **Total Time**: 2 minutes 42.81 seconds |          |                         |

### Verification Phase

| Step                | Time (s) | Memory Usage (RSS KB) |
| ------------------- | -------- | --------------------- |
| Message Digest Hash | \~0.0001 | \~5124                |
| Merkle Root Rebuild | \~0.0008 | \~5124                |
| **Total Time**      | 0.0009 =0.9ms   | \~5124                |

---

## Signature Size

The generated signature file `lms_signature.bin` contains:

- **P = 8** signature elements, each *N = 24* bytes → 8 × 24 = 192 bytes
- **H = 10** authentication path nodes, each *N = 24* bytes → 10 × 24 = 240 bytes
- **Merkle root** → 24 bytes
- **LM-OTS public key** → 8 × 24 = 192 bytes

**Total size** = 192 + 240 + 24 + 192 = **648 bytes**

---

## Code Structure

### Constants

- `N`: Hash length (24 bytes, truncated SHA-256)
- `H`: Merkle tree height (10)
- `LEAVES`: Number of leaves (2^H = 1024)
- `W`: Winternitz parameter (32)
- `P`: Number of LM-OTS chains (8)

### Key Functions

- `generate_random_bytes()` – Fills buffer with pseudo-random bytes
- `hash_sha192()` – SHA-256 truncated to 192 bits
- `wots_gen_pk()` – Derives LM-OTS public key by repeated hashing
- `wots_pk_to_leaf()` – Hashes concatenated LM-OTS public key to Merkle leaf
- `build_merkle_tree()` – Constructs Merkle tree and authentication path
- `compute_merkle_root()` – Used during verification to rebuild root
- `print_memory_usage()` – Reports current process memory (VmRSS)

---

## License

This project is for research and educational purposes. No warranty is provided.

