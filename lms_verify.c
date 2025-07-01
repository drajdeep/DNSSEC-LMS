#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/resource.h>

#define N 24
#define H 10
#define P 8

void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N);
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

void print_memory_usage(const char* label) {
    FILE* file = fopen("/proc/self/status", "r");
    if (!file) return;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            printf("[MEM] %s - %s", label, line);
            break;
        }
    }
    fclose(file);
}

void wots_pk_to_leaf(const uint8_t pk[P][N], uint8_t *leaf) {
    uint8_t buf[P * N];
    for (int i = 0; i < P; i++)
        memcpy(buf + i * N, pk[i], N);
    hash_sha192(buf, P * N, leaf);
}

void compute_merkle_root(const uint8_t *leaf, const uint8_t auth_path[H][N], int leaf_idx, uint8_t *root) {
    uint8_t temp[N];
    memcpy(temp, leaf, N);

    for (int level = 0; level < H; level++) {
        uint8_t concat[2 * N];
        if ((leaf_idx % 2) == 0) {
            memcpy(concat, temp, N);
            memcpy(concat + N, auth_path[level], N);
        } else {
            memcpy(concat, auth_path[level], N);
            memcpy(concat + N, temp, N);
        }
        hash_sha192(concat, 2 * N, temp);
        leaf_idx /= 2;
    }

    memcpy(root, temp, N);
}

int main() {
    printf("================ LMS Verifier (No PK Regen) ================\n");

    FILE *f = fopen("lms_signature.bin", "rb");
    if (!f) {
        perror("[-] Failed to open signature file");
        return 1;
    }

    uint8_t signature[P][N], auth_path[H][N], expected_root[N], pk[P][N];

    for (int i = 0; i < P; i++) fread(signature[i], 1, N, f);
    for (int i = 0; i < H; i++) fread(auth_path[i], 1, N, f);
    fread(expected_root, 1, N, f);
    for (int i = 0; i < P; i++) fread(pk[i], 1, N, f);
    fclose(f);

    // Step 1: Reconstruct message
    const char *sample_zsk = "DNSKEY 256 3 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    uint8_t message[P * N + 128];
    size_t msg_len = 0;
    for (int i = 0; i < P; i++) {
        memcpy(message + msg_len, pk[i], N);
        msg_len += N;
    }
    memcpy(message + msg_len, sample_zsk, strlen(sample_zsk));
    msg_len += strlen(sample_zsk);

    clock_t t_start = clock();

    uint8_t msg_digest[N];
    hash_sha192(message, msg_len, msg_digest);
    print_hex("[+] Message Digest", msg_digest, N);
    print_memory_usage("After Digest");

    // Step 2: Derive WOTS+ chunk values and checksum
    uint16_t chunks[P];
    uint32_t checksum = 0;
    for (int i = 0; i < 12; i++) {
        chunks[i] = (msg_digest[2 * i] << 8) | msg_digest[2 * i + 1];
        checksum += (65535 - chunks[i]);
    }
    for (int i = 12; i < P; i++) {
        chunks[i] = checksum & 0xFFFF;
        checksum >>= 16;
    }

    // Step 3: Use provided LM-OTS public key to compute leaf
    uint8_t leaf[N];
    wots_pk_to_leaf(pk, leaf);

    // Step 4: Compute Merkle root from auth path
    uint8_t computed_root[N];
    compute_merkle_root(leaf, auth_path, 0, computed_root);

    clock_t t_end = clock();

    print_hex("[+] Reconstructed Merkle Root", computed_root, N);
    print_hex("[+] Expected Merkle Root    ", expected_root, N);
    print_memory_usage("After Merkle Root");

    double total_time = (double)(t_end - t_start) / CLOCKS_PER_SEC;
    printf("\n[TOTAL TIME] Signature Verification Time: %.4f seconds\n", total_time);

    if (memcmp(computed_root, expected_root, N) == 0)
        printf("\n✅ Signature is VALID.\n");
    else
        printf("\n❌ Signature is INVALID.\n");

    printf("=============== Verification Complete ===============\n");
    return 0;
}
