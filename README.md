# LMS as KSK in Post-Quantum DNSSEC

This repository provides an implementation of the Leighton-Micali Signature (LMS) scheme as a Key Signing Key (KSK) for Post-Quantum DNSSEC. It simulates the LMS signing process using LM-OTS keypairs and a Merkle tree, outputs a DNSKEY-signed zone signature, and includes benchmarking metrics for performance and resource usage.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Usage](#usage)
- [Benchmarking](#benchmarking)
- [Signature Size](#signature-size)
- [Code Structure](#code-structure)

## Overview

The LMS (Leighton-Micali Signature) scheme is an evolution of hash-based signatures providing post-quantum security. In DNSSEC, a Key Signing Key (KSK) signs Zone Signing Keys (ZSKs) to ensure the authenticity of DNS records. This implementation:

- Generates LM-OTS keypairs (private/public).
- Constructs a Merkle tree over LM-OTS public key hashes.
- Signs a combined message of an LM-OTS public key and a sample ZSK DNSKEY record.
- Outputs an LMS signature file (`lms_signature.bin`) containing signature elements, authentication path, Merkle root, and LM-OTS public key.

## Features

- **LM-OTS key generation** with Winternitz parameter _W = 32_.
- **Merkle tree** of height _H = 10_ (64 leaves).
- **SHA-192** as the hash function (first 24 bytes of SHA-256).
- **Benchmarking** of time and memory usage for each step.

## Prerequisites

- GCC with C99 support
- OpenSSL development libraries (for SHA-256)
- Unix-like environment (for `/proc/self/status` memory reading)

## Build Instructions

```sh
gcc ksk_lms.c -o ksk_lms -lssl -lcrypto -lm
```

## Usage

```sh
./ksk_lms
```

This will generate:

- Console output of each step (keypair generation, Merkle tree build, digest, signature).
- `lms_signature.bin` containing the binary signature components.

## Benchmarking

Measured on a standard desktop environment:

| Step                           | Time (s)    | Memory Usage (RSS KB) |
|--------------------------------|-------------|------------------------|
| LM-OTS Keypair Generation      | 162.9968    | ~5,532                |
| Merkle Tree Construction       | 0.0004      | (no significant change) |
| Message Digest Hashing         | ~0.0000     | (no significant change) |
| LM-OTS Signature Generation    | 0.0709      | (no significant change) |

Overall time: **2 Minutes 42.81 Seconds**

## Signature Size

The generated signature file `lms_signature.bin` contains:

- **P = 8** signature elements, each _N = 24_ bytes → 8 × 24 = 192 bytes
- **H = 10** authentication path nodes, each _N = 24_ bytes → 10 × 24 = 240 bytes
- **Merkle root**, 24 bytes
- **LM-OTS public key**, 8 × 24 = 192 bytes

**Total size** = 192 + 240 + 24 + 192 = **648 bytes**

## Code Structure

- **`N`**: Hash length (24 bytes, truncated SHA-256)
- **`H`**: Merkle tree height (10)
- **`LEAVES`**: Number of leaves (2^H = 1024)
- **`W`**: Winternitz parameter (32)
- **`P`**: Number of LM-OTS chains (8)

Key functions:

- `generate_random_bytes()`: Fills buffer with pseudo-random data.
- `hash_sha192()`: Computes truncated SHA-256 (24 bytes).
- `wots_gen_pk()`: Derives public key from private key by iterated hashing.
- `wots_pk_to_leaf()`: Hashes concatenated public key elements to form Merkle leaf.
- `build_merkle_tree()`: Builds full tree and authentication path for a target leaf.
- `print_memory_usage()`: Reads `/proc/self/status` to report RSS memory.


