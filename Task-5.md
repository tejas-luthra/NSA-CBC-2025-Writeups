# NSA Codebreaker Challenge 2025 – Task 5: Putting It All Together

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Cryptanalysis

---

## Challenge Description

NSA analysts confirm that there is solid evidence that this binary was at least part of what had been installed on the military development network. Unfortunately, we do not yet have enough information to update NSA senior leadership on this threat. We need to move forward with this investigation!

The team is stumped - they need to identify something about who was controlling this malware. They look to you. "Do you have any ideas?"

**Objective:** Submit the full URL to the adversary's server

**Provided Materials:**
- None

**Required Materials:**
- `unpacked_complete.elf` – Extracted malware payload from Task 4
- `traffic.pcap` – Network Traffic Capture from Task 2
---

## Methodology

### Phase 1: Binary Reverse Engineering

Analyzed the malware in IDA and identified key functions:

| Function | Purpose |
|----------|---------|
| `custom_enc` | Double AES-ECB encryption |
| `custom_dec` | Double AES-ECB decryption |
| `generate_key` | Key generation (vulnerable) |
| `Comms::send_aes_keys` | RSA-encrypted key transmission |

**Double encryption implementation:**
```c
void custom_enc(__int64 ctx1, __int64 ctx2, __int64 plaintext, 
                unsigned int len, __int64 ciphertext, __int64 out_len) {
    void *intermediate = malloc((int)(len + 16));
    aes_encrypt(ctx1, plaintext, len, intermediate, &temp_len);
    aes_encrypt(ctx2, intermediate, temp_len, ciphertext, out_len);
    free(intermediate);
}
```

### Phase 2: Vulnerability Discovery

**Critical flaw in key generation:**
```c
__int64 generate_key(__int64 ptr, int a2) {
    // Reads 16 bytes from /dev/random
    v12.m128i_i64[0] = _mm_movehl_ps(a4, v11).m128_u64[0] >> 38;
    *ptr = _mm_load_si128(&v12);
}
```

The `>> 38` bit shift reduced 128-bit keys to only **26 bits of entropy**:
- Original keyspace: 2^128 keys
- Actual keyspace: 2^26 = 67,108,864 keys
- Brute force becomes trivial

**Key structure:**
```
Bytes 0-3:  26-bit value (little-endian)
Bytes 4-15: Zero padding
```

### Phase 3: Network Traffic Analysis

Filtered PCAP for C2 handshake:
```bash
wireshark traffic.pcap
# Filter: tcp contains "KEY_RECEIVED"
```

**Traffic structure:**
1. RSA public key (PEM format) ~450 bytes
2. RSA-encrypted AES keys 256 bytes
3. `KEY_RECEIVED` + encrypted payload ~237 bytes

### Phase 4: ECB Mode Analysis

Identified repeating 16-byte block in ciphertext (appears 4 times):
```
eaaf324bf7ec6936997d9a90b6925d53
```
Python script to identify the key:
```python
#!/usr/bin/env python3
"""
Extract encrypted data directly from PCAP file
Finds TCP stream containing KEY_RECEIVED and extracts encrypted payload

Usage:
    python3 extract_encrypted.py capture.pcap
    python3 extract_encrypted.py stream.txt      # Also supports hexdump

Requirements:
    pip install scapy

Output:
    encrypted.bin - Binary file with encrypted data after KEY_RECEIVED
    Prints the repeating block hex for use with brute_force
"""

import sys
import re
import os

def parse_pcap(filepath):
    """Parse PCAP file and extract TCP stream containing KEY_RECEIVED"""
    try:
        from scapy.all import rdpcap, TCP, Raw, conf
        conf.verb = 0  # Suppress scapy output
    except ImportError:
        print("Error: Scapy required for PCAP parsing")
        print("Install with: pip install scapy")
        sys.exit(1)
    
    print(f"[*] Reading PCAP: {filepath}")
    packets = rdpcap(filepath)
    print(f"[+] Loaded {len(packets)} packets")
    
    # Group packets by TCP stream (src_ip:src_port <-> dst_ip:dst_port)
    streams = {}
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            # Create stream identifier (bidirectional)
            try:
                src = f"{pkt['IP'].src}:{pkt['TCP'].sport}"
                dst = f"{pkt['IP'].dst}:{pkt['TCP'].dport}"
                
                # Sort to make bidirectional key
                stream_key = tuple(sorted([src, dst]))
                
                if stream_key not in streams:
                    streams[stream_key] = bytearray()
                
                streams[stream_key].extend(pkt[Raw].load)
            except:
                continue
    
    print(f"[+] Found {len(streams)} TCP streams")
    
    # Find stream containing KEY_RECEIVED
    marker = b'KEY_RECEIVED'
    
    for stream_key, data in streams.items():
        if marker in data:
            print(f"[+] Found KEY_RECEIVED in stream: {stream_key[0]} <-> {stream_key[1]}")
            return bytes(data)
    
    # If not found in grouped streams, try raw concatenation
    print("[*] Trying raw packet concatenation...")
    all_data = bytearray()
    for pkt in packets:
        if pkt.haslayer(Raw):
            all_data.extend(pkt[Raw].load)
    
    if marker in all_data:
        print("[+] Found KEY_RECEIVED in raw data")
        return bytes(all_data)
    
    print("[-] KEY_RECEIVED not found in any stream")
    return None


def parse_hexdump(filepath):
    """Parse Wireshark hexdump, handling interleaved streams"""
    raw_bytes = bytearray()
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            
            # Match lines starting with optional whitespace, then hex offset
            match = re.match(r'^\s*([0-9a-fA-F]{8})\s+(.+)$', line)
            if not match:
                continue
            
            hex_part = match.group(2)
            
            # Extract hex bytes
            bytes_found = []
            parts = hex_part.split()
            
            for part in parts:
                if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                    bytes_found.append(int(part, 16))
                elif len(part) == 4 and all(c in '0123456789abcdefABCDEF' for c in part):
                    bytes_found.append(int(part[:2], 16))
                    bytes_found.append(int(part[2:], 16))
                else:
                    break
                
                if len(bytes_found) >= 16:
                    break
            
            raw_bytes.extend(bytes_found)
    
    return bytes(raw_bytes)


def find_repeating_block(data):
    """Find the most common 16-byte block"""
    if len(data) < 32:
        return None, 0
    
    num_blocks = len(data) // 16
    block_counts = {}
    
    for i in range(num_blocks):
        block = data[i*16:(i+1)*16]
        block_hex = block.hex()
        block_counts[block_hex] = block_counts.get(block_hex, 0) + 1
    
    # Find most common
    best_block = None
    best_count = 0
    for block_hex, count in block_counts.items():
        if count > best_count:
            best_count = count
            best_block = block_hex
    
    return best_block, best_count


def extract_encrypted_data(raw_data):
    """Extract and align encrypted data after KEY_RECEIVED marker"""
    
    marker = b'KEY_RECEIVED'
    idx = raw_data.find(marker)
    
    if idx == -1:
        return None, None, 0
    
    print(f"[+] Found KEY_RECEIVED at offset {idx}")
    
    # Extract encrypted data (everything after KEY_RECEIVED)
    encrypted_raw = raw_data[idx + len(marker):]
    
    print(f"[*] Raw encrypted data starts with: {encrypted_raw[:20].hex()}")
    
    # Try to find proper alignment by looking for repeating pattern
    best_offset = 0
    best_count = 0
    best_block = None
    
    for offset in range(16):
        test_data = encrypted_raw[offset:]
        aligned_len = (len(test_data) // 16) * 16
        test_data = test_data[:aligned_len]
        
        if len(test_data) < 32:
            continue
        
        # Count repeating blocks
        num_blocks = len(test_data) // 16
        block_counts = {}
        for i in range(num_blocks):
            block = test_data[i*16:(i+1)*16].hex()
            block_counts[block] = block_counts.get(block, 0) + 1
        
        # Find max count for this offset
        for block, count in block_counts.items():
            if count > best_count:
                best_count = count
                best_offset = offset
                best_block = block
    
    if best_offset > 0:
        print(f"[*] Detected alignment offset: {best_offset} bytes (skipping)")
    
    encrypted = encrypted_raw[best_offset:]
    aligned_len = (len(encrypted) // 16) * 16
    encrypted = encrypted[:aligned_len]
    
    return encrypted, best_block, best_count


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_encrypted.py <capture.pcap|hexdump.txt>")
        print("\nSupported formats:")
        print("  - PCAP files (.pcap, .pcapng)")
        print("  - Wireshark hexdump (.txt)")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    # Determine file type and parse
    if filepath.endswith(('.pcap', '.pcapng')):
        raw_data = parse_pcap(filepath)
        if not raw_data:
            print("[-] Failed to extract data from PCAP")
            sys.exit(1)
        print(f"[+] Extracted {len(raw_data)} bytes from PCAP")
    else:
        print(f"[*] Parsing hexdump: {filepath}")
        raw_data = parse_hexdump(filepath)
        print(f"[+] Parsed {len(raw_data)} bytes total")
    
    # Extract encrypted data
    encrypted, repeating_block, repeat_count = extract_encrypted_data(raw_data)
    
    if encrypted is None:
        print("[-] KEY_RECEIVED marker not found!")
        print("[*] Dumping first 200 bytes:")
        print(raw_data[:200].hex())
        
        # Try to find packet markers
        pkt_marker = bytes.fromhex('dec0dec0ffee')
        pos = 0
        positions = []
        while True:
            pos = raw_data.find(pkt_marker, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        
        if positions:
            print(f"\n[*] Found packet markers at offsets: {positions}")
            for p in positions[:5]:
                end = min(p + 30, len(raw_data))
                print(f"    Offset {p}: {raw_data[p:end]}")
        
        sys.exit(1)
    
    print(f"[+] Encrypted data: {len(encrypted)} bytes ({len(encrypted)//16} blocks)")
    
    # Report repeating block
    if repeat_count > 1:
        print(f"\n[+] Repeating block (appears {repeat_count} times):")
        print(f"    {repeating_block}")
    else:
        print("\n[-] No repeating block found")
        print("[*] First 5 blocks:")
        for i in range(min(5, len(encrypted)//16)):
            print(f"    Block {i}: {encrypted[i*16:(i+1)*16].hex()}")
    
    # Save encrypted data
    outfile = "encrypted.bin"
    with open(outfile, 'wb') as f:
        f.write(encrypted)
    print(f"\n[+] Saved encrypted data to: {outfile}")
    
    # Print command to run
    if repeat_count > 1:
        print(f"\n[*] Now run:")
        print(f"    ./brute_force {outfile} {repeating_block}")
    else:
        print(f"\n[*] No repeating block found. You may need to manually specify it:")
        print(f"    ./brute_force {outfile} <repeating_block_hex>")


if __name__ == "__main__":
    main()
```

Usage: 
```bash
python3 extract_encrypted.py traffic.pcap

[*] Reading PCAP: traffic.pcap
[+] Loaded 2344 packets
[+] Found 16 TCP streams
[+] Found KEY_RECEIVED in stream: 192.168.3.89:26535 <-> 203.0.113.108:14159
[+] Extracted 961 bytes from PCAP
[+] Found KEY_RECEIVED at offset 725
[*] Raw encrypted data starts with: 45740ab7a736dd2dd2cdb90965d2621aeaaf324b
[+] Encrypted data: 224 bytes (14 blocks)

[+] Repeating block (appears 4 times):
    eaaf324bf7ec6936997d9a90b6925d53

[+] Saved encrypted data to: encrypted.bin

[*] Now run:
    ./brute_force encrypted.bin eaaf324bf7ec6936997d9a90b6925d53
```

This revealed:
- ECB mode encryption (identical plaintext → identical ciphertext)
- Repeating block = PKCS#7 padding (`0x10` repeated 16 times)
- Known plaintext-ciphertext pair available

### Phase 5: Brute Force Attack

**Two-stage attack strategy:**

Stage 1: Recover Key2
```
For key2 in range(0, 2^26):
    ciphertext = AES_Encrypt(key2, known_plaintext)
    if ciphertext == known_ciphertext:
        Found Key2
```

Stage 2: Recover Key1
```
For key1 in range(0, 2^26):
    intermediate = AES_Decrypt(key2, encrypted_data)
    plaintext = AES_Decrypt(key1, intermediate)
    if plaintext contains readable text:
        Found Key1
```

**Brute force tool (C with OpenSSL) ``brute.c``:**
```c
/*
 * AES Double Encryption Brute Force
 * Exploits weak key generation (26-bit entropy) and ECB mode
 * 
 * Compile:
 *   gcc -O3 -o brute_force brute_force_aes.c -lcrypto -lpthread
 * 
 * Usage:
 *   ./brute_force <hexdump.txt>
 *   ./brute_force <encrypted_data.bin> <repeating_block_hex>
 * 
 * Example:
 *   ./brute_force stream.txt
 *   ./brute_force encrypted.bin a6c6c882f3241b58b10e7c34bdbc4229
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <time.h>

/* Configuration */
#define KEY_BITS 26
#define MAX_KEYS (1 << KEY_BITS)  /* 2^26 = 67,108,864 */
#define AES_BLOCK_SIZE 16
#define MAX_DATA_SIZE (1024 * 1024)  /* 1MB max */

/* Number of threads - will be set dynamically */
static int g_num_threads = 8;

/* PKCS#7 padding block (16 bytes of 0x10) */
static const uint8_t KNOWN_PLAINTEXT[16] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
};

/* Markers */
static const uint8_t PACKET_MARKER[] = {0xde, 0xc0, 0xde, 0xc0, 0xff, 0xee};
static const char *KEY_RECEIVED_MARKER = "KEY_RECEIVED";

/* Search patterns for Stage 2 */
static const char *SEARCH_PATTERNS[] = {
    "https://",
    "http://",
    "flag{",
    "FLAG{",
    NULL
};

/* Global variables for thread coordination */
static uint8_t g_known_ciphertext[16];
static uint8_t *g_encrypted_data = NULL;
static size_t g_encrypted_len = 0;
static volatile int g_key2_found = 0;
static volatile int g_key1_found = 0;
static uint8_t g_key2[16];
static uint8_t g_key1[16];
static uint8_t *g_decrypted_data = NULL;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread arguments */
typedef struct {
    uint32_t start;
    uint32_t end;
    int thread_id;
    int stage;
    uint8_t *intermediate_data;
} thread_args_t;

/* Convert hex char to value */
int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convert hex string to bytes */
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int hi = hex_char_to_val(hex[2*i]);
        int lo = hex_char_to_val(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        bytes[i] = (hi << 4) | lo;
    }
    return 0;
}

/* Print bytes as hex */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Parse Wireshark-style hexdump file 
 * Handles interleaved streams by tracking offsets and combining all data
 */
size_t parse_hexdump(const char *filepath, uint8_t *output, size_t max_len) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", filepath);
        return 0;
    }
    
    char line[512];
    size_t total_bytes = 0;
    size_t max_offset_seen = 0;
    
    /* First pass: just extract all hex bytes in order, ignoring offsets */
    while (fgets(line, sizeof(line), f) && total_bytes < max_len) {
        char *p = line;
        
        /* Skip leading whitespace */
        while (*p && isspace(*p)) p++;
        
        /* Must start with hex offset */
        if (!isxdigit(*p)) continue;
        
        /* Skip offset (hex digits followed by spaces) */
        while (*p && isxdigit(*p)) p++;
        
        /* Need at least two spaces after offset */
        if (*p != ' ') continue;
        while (*p == ' ') p++;
        
        /* Parse hex bytes - stop at double space or ASCII column */
        int bytes_in_line = 0;
        while (*p && total_bytes < max_len && bytes_in_line < 16) {
            /* Check for ASCII column (usually after ~50 chars or double space) */
            if (p[0] == ' ' && p[1] == ' ') break;
            
            /* Skip single spaces between bytes */
            while (*p == ' ') p++;
            
            /* Need two hex digits */
            if (isxdigit(p[0]) && isxdigit(p[1])) {
                int hi = hex_char_to_val(p[0]);
                int lo = hex_char_to_val(p[1]);
                output[total_bytes++] = (hi << 4) | lo;
                bytes_in_line++;
                p += 2;
            } else {
                break;
            }
        }
    }
    
    fclose(f);
    return total_bytes;
}

/* Find pattern in data */
uint8_t *memmem_local(uint8_t *haystack, size_t haystacklen, 
                      const uint8_t *needle, size_t needlelen) {
    if (needlelen > haystacklen) return NULL;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(haystack + i, needle, needlelen) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

/* Find encrypted data after KEY_RECEIVED marker */
uint8_t *find_encrypted_data(uint8_t *data, size_t len, size_t *out_len) {
    /* Find KEY_RECEIVED marker */
    uint8_t *marker_pos = memmem_local(data, len, 
                                       (const uint8_t *)KEY_RECEIVED_MARKER, 
                                       strlen(KEY_RECEIVED_MARKER));
    
    if (!marker_pos) {
        fprintf(stderr, "[-] KEY_RECEIVED marker not found\n");
        return NULL;
    }
    
    printf("[+] Found KEY_RECEIVED at offset %zu\n", marker_pos - data);
    
    /* Encrypted data starts after the marker */
    uint8_t *encrypted_start = marker_pos + strlen(KEY_RECEIVED_MARKER);
    size_t encrypted_len = len - (encrypted_start - data);
    
    /* Align to 16-byte blocks */
    encrypted_len = (encrypted_len / 16) * 16;
    
    *out_len = encrypted_len;
    return encrypted_start;
}

/* Find most common 16-byte repeating block */
int find_repeating_block(uint8_t *data, size_t len, uint8_t *out_block) {
    if (len < 32) return 0;
    
    size_t num_blocks = len / 16;
    int max_count = 0;
    
    printf("\n[*] Block frequency analysis (%zu blocks):\n", num_blocks);
    
    /* For each unique block, count occurrences */
    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t *block_i = data + i * 16;
        int count = 0;
        
        /* Count how many times this block appears */
        for (size_t j = 0; j < num_blocks; j++) {
            if (memcmp(data + j * 16, block_i, 16) == 0) {
                count++;
            }
        }
        
        /* If this block appears more than once and more than our current max */
        if (count > 1 && count > max_count) {
            max_count = count;
            memcpy(out_block, block_i, 16);
        }
    }
    
    /* Print top blocks */
    if (max_count > 1) {
        printf("    ");
        for (int k = 0; k < 16; k++) printf("%02x", out_block[k]);
        printf(" - appears %d times (SELECTED)\n", max_count);
    }
    
    /* Also print first few blocks for debugging */
    printf("\n[*] First 5 blocks of encrypted data:\n");
    for (size_t i = 0; i < num_blocks && i < 5; i++) {
        printf("    Block %zu: ", i);
        for (int k = 0; k < 16; k++) printf("%02x", data[i * 16 + k]);
        printf("\n");
    }
    
    return max_count;
}

/* Construct key from 26-bit value */
void make_key(uint32_t value, uint8_t *key) {
    memset(key, 0, 16);
    key[0] = value & 0xFF;
    key[1] = (value >> 8) & 0xFF;
    key[2] = (value >> 16) & 0xFF;
    key[3] = (value >> 24) & 0xFF;
}

/* AES-128-ECB encrypt a single block */
void aes_encrypt_block(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, 16);
    EVP_CIPHER_CTX_free(ctx);
}

/* AES-128-ECB decrypt data */
void aes_decrypt_data(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    
    for (size_t i = 0; i < len; i += 16) {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_DecryptUpdate(ctx, plaintext + i, &outlen, ciphertext + i, 16);
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

/* Check if decrypted data contains search patterns */
int check_decrypted_data(const uint8_t *data, size_t len) {
    for (int i = 0; SEARCH_PATTERNS[i] != NULL; i++) {
        if (memmem_local((uint8_t *)data, len, 
                        (const uint8_t *)SEARCH_PATTERNS[i], 
                        strlen(SEARCH_PATTERNS[i])) != NULL) {
            return 1;
        }
    }
    
    /* Check for high ASCII ratio */
    int printable = 0;
    for (size_t i = 0; i < len && i < 256; i++) {
        if (data[i] >= 32 && data[i] < 127) printable++;
    }
    size_t check_len = (len < 256) ? len : 256;
    if (printable > (int)(check_len * 0.8)) return 1;
    
    return 0;
}

/* Thread function for brute forcing */
void *brute_force_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    uint8_t key[16];
    uint8_t result[16];
    uint8_t *decrypted = NULL;
    
    if (args->stage == 2) {
        decrypted = malloc(g_encrypted_len);
        if (!decrypted) return NULL;
    }
    
    uint32_t progress_interval = (args->end - args->start) / 10;
    if (progress_interval == 0) progress_interval = 1;
    
    for (uint32_t i = args->start; i < args->end; i++) {
        if ((args->stage == 1 && g_key2_found) || 
            (args->stage == 2 && g_key1_found)) {
            break;
        }
        
        if ((i - args->start) % progress_interval == 0) {
            int pct = (i - args->start) * 100 / (args->end - args->start);
            printf("\r    Thread %d: %d%%", args->thread_id, pct);
            fflush(stdout);
        }
        
        make_key(i, key);
        
        if (args->stage == 1) {
            aes_encrypt_block(key, KNOWN_PLAINTEXT, result);
            
            if (memcmp(result, g_known_ciphertext, 16) == 0) {
                pthread_mutex_lock(&g_mutex);
                if (!g_key2_found) {
                    g_key2_found = 1;
                    memcpy(g_key2, key, 16);
                    printf("\n\n[+] KEY2 FOUND by thread %d!\n", args->thread_id);
                    print_hex("    Key2", key, 16);
                    printf("    Value: %u (0x%08x)\n", i, i);
                }
                pthread_mutex_unlock(&g_mutex);
                break;
            }
        } else {
            aes_decrypt_data(key, args->intermediate_data, decrypted, g_encrypted_len);
            
            if (check_decrypted_data(decrypted, g_encrypted_len)) {
                pthread_mutex_lock(&g_mutex);
                if (!g_key1_found) {
                    g_key1_found = 1;
                    memcpy(g_key1, key, 16);
                    g_decrypted_data = malloc(g_encrypted_len);
                    if (g_decrypted_data) {
                        memcpy(g_decrypted_data, decrypted, g_encrypted_len);
                    }
                    printf("\n\n[+] KEY1 FOUND by thread %d!\n", args->thread_id);
                    print_hex("    Key1", key, 16);
                    printf("    Value: %u (0x%08x)\n", i, i);
                }
                pthread_mutex_unlock(&g_mutex);
                break;
            }
        }
    }
    
    if (decrypted) free(decrypted);
    return NULL;
}

/* Run brute force with multiple threads */
int run_brute_force(int stage, uint8_t *intermediate_data) {
    pthread_t *threads = malloc(g_num_threads * sizeof(pthread_t));
    thread_args_t *args = malloc(g_num_threads * sizeof(thread_args_t));
    
    if (!threads || !args) {
        fprintf(stderr, "Error: Failed to allocate thread arrays\n");
        if (threads) free(threads);
        if (args) free(args);
        return -1;
    }
    
    uint32_t keys_per_thread = MAX_KEYS / g_num_threads;
    
    printf("[*] Starting %d threads...\n", g_num_threads);
    
    for (int i = 0; i < g_num_threads; i++) {
        args[i].start = i * keys_per_thread;
        args[i].end = (i == g_num_threads - 1) ? MAX_KEYS : (i + 1) * keys_per_thread;
        args[i].thread_id = i;
        args[i].stage = stage;
        args[i].intermediate_data = intermediate_data;
        
        if (pthread_create(&threads[i], NULL, brute_force_thread, &args[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(threads);
            free(args);
            return -1;
        }
    }
    
    for (int i = 0; i < g_num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    free(args);
    
    printf("\n");
    return (stage == 1) ? g_key2_found : g_key1_found;
}

/* Remove PKCS#7 padding */
size_t remove_pkcs7_padding(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_len = data[len - 1];
    if (pad_len > 0 && pad_len <= 16) {
        int valid = 1;
        for (int i = 0; i < pad_len; i++) {
            if (data[len - 1 - i] != pad_len) {
                valid = 0;
                break;
            }
        }
        if (valid) return len - pad_len;
    }
    return len;
}

/* Print usage */
void print_usage(const char *prog) {
    printf("AES Double Encryption Brute Force\n");
    printf("==================================\n\n");
    printf("Usage:\n");
    printf("  %s <hexdump.txt> [-t threads]                        - Auto-detect everything\n", prog);
    printf("  %s <hexdump.txt> <repeating_block_hex> [-t threads]  - Manual ciphertext block\n", prog);
    printf("  %s <encrypted.bin> <repeating_block_hex> [-t threads] - Binary input mode\n\n", prog);
    printf("Options:\n");
    printf("  -t <num>    Number of threads (default: auto-detect CPU cores)\n\n");
    printf("Examples:\n");
    printf("  %s stream.txt\n", prog);
    printf("  %s stream.txt a6c6c882f3241b58b10e7c34bdbc4229\n", prog);
    printf("  %s encrypted.bin a6c6c882f3241b58b10e7c34bdbc4229 -t 16\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Detect number of CPU cores */
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores > 0) {
        g_num_threads = (int)num_cores;
    }
    
    /* Parse arguments */
    const char *input_file = NULL;
    const char *ciphertext_hex = NULL;
    int manual_ciphertext = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_num_threads = atoi(argv[++i]);
            if (g_num_threads < 1) g_num_threads = 1;
            if (g_num_threads > 256) g_num_threads = 256;
        } else if (input_file == NULL) {
            input_file = argv[i];
        } else if (ciphertext_hex == NULL && strlen(argv[i]) == 32) {
            ciphertext_hex = argv[i];
        }
    }
    
    if (input_file == NULL) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Process manual ciphertext if provided */
    if (ciphertext_hex != NULL) {
        if (hex_to_bytes(ciphertext_hex, g_known_ciphertext, 16) == 0) {
            manual_ciphertext = 1;
            printf("[*] Using manually specified ciphertext block\n");
        }
    }
    
    uint8_t *raw_data = NULL;
    size_t raw_len = 0;
    uint8_t *encrypted_start = NULL;
    
    /* Check if input is binary or hexdump */
    FILE *test_f = fopen(input_file, "rb");
    if (!test_f) {
        fprintf(stderr, "Error: Cannot open %s\n", input_file);
        return 1;
    }
    
    /* Read first few bytes to check if binary */
    uint8_t header[64];
    size_t header_len = fread(header, 1, 64, test_f);
    fclose(test_f);
    
    int is_binary = 0;
    
    /* Check if file looks like text (hexdump) */
    int text_chars = 0;
    int non_printable = 0;
    for (size_t i = 0; i < header_len; i++) {
        if ((header[i] >= 32 && header[i] < 127) || header[i] == '\n' || header[i] == '\r' || header[i] == '\t') {
            text_chars++;
        } else {
            non_printable++;
        }
    }
    
    /* If more than 20% non-printable, treat as binary */
    if (non_printable > (int)(header_len * 0.2)) {
        is_binary = 1;
    }
    
    /* Also check file extension */
    const char *ext = strrchr(input_file, '.');
    if (ext && (strcmp(ext, ".bin") == 0 || strcmp(ext, ".raw") == 0)) {
        is_binary = 1;
    }
    
    if (is_binary && !manual_ciphertext) {
        /* Binary mode without manual ciphertext - need it as argument */
        fprintf(stderr, "Error: Binary file requires repeating block hex as second argument\n");
        fprintf(stderr, "Usage: %s <encrypted.bin> <repeating_block_hex>\n", argv[0]);
        return 1;
    }
    
    if (is_binary) {
        /* Read binary file directly as encrypted data */
        FILE *f = fopen(input_file, "rb");
        fseek(f, 0, SEEK_END);
        g_encrypted_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        g_encrypted_len = (g_encrypted_len / 16) * 16;
        g_encrypted_data = malloc(g_encrypted_len);
        
        if (fread(g_encrypted_data, 1, g_encrypted_len, f) != g_encrypted_len) {
            fprintf(stderr, "Error: Failed to read file\n");
            fclose(f);
            return 1;
        }
        fclose(f);
        
    } else {
        /* Hexdump mode - parse and find encrypted data */
        printf("[*] Parsing hexdump: %s\n", input_file);
        
        raw_data = malloc(MAX_DATA_SIZE);
        if (!raw_data) {
            fprintf(stderr, "Error: malloc failed\n");
            return 1;
        }
        
        raw_len = parse_hexdump(input_file, raw_data, MAX_DATA_SIZE);
        if (raw_len == 0) {
            fprintf(stderr, "Error: No data parsed from hexdump\n");
            free(raw_data);
            return 1;
        }
        
        printf("[+] Parsed %zu bytes from hexdump\n", raw_len);
        
        /* Find encrypted data after KEY_RECEIVED */
        encrypted_start = find_encrypted_data(raw_data, raw_len, &g_encrypted_len);
        if (!encrypted_start || g_encrypted_len < 32) {
            fprintf(stderr, "Error: Could not find encrypted data\n");
            free(raw_data);
            return 1;
        }
        
        printf("[+] Encrypted data: %zu bytes (%zu blocks)\n", 
               g_encrypted_len, g_encrypted_len / 16);
        
        /* Copy encrypted data */
        g_encrypted_data = malloc(g_encrypted_len);
        memcpy(g_encrypted_data, encrypted_start, g_encrypted_len);
        
        /* Find or use provided repeating block */
        if (!manual_ciphertext) {
            int repeat_count = find_repeating_block(g_encrypted_data, g_encrypted_len, g_known_ciphertext);
            if (repeat_count < 2) {
                fprintf(stderr, "\nError: No repeating block found automatically.\n");
                fprintf(stderr, "Try specifying it manually:\n");
                fprintf(stderr, "  %s %s a6c6c882f3241b58b10e7c34bdbc4229\n\n", argv[0], input_file);
                free(raw_data);
                free(g_encrypted_data);
                return 1;
            }
            printf("\n[+] Auto-detected repeating block (appears %d times)\n", repeat_count);
        }
        
        free(raw_data);
    }
    
    printf("\n======================================================================\n");
    printf("AES Double Encryption Brute Force\n");
    printf("======================================================================\n");
    printf("Encrypted data: %zu bytes (%zu blocks)\n", g_encrypted_len, g_encrypted_len / 16);
    print_hex("Known ciphertext (padding)", g_known_ciphertext, 16);
    print_hex("Known plaintext  (PKCS#7)", KNOWN_PLAINTEXT, 16);
    printf("Keyspace: 2^%d = %d keys\n", KEY_BITS, MAX_KEYS);
    printf("Threads: %d (detected %ld CPU cores)\n", g_num_threads, sysconf(_SC_NPROCESSORS_ONLN));
    printf("======================================================================\n\n");
    
    clock_t start_time = clock();
    
    /* Stage 1: Brute force Key2 */
    printf("[*] STAGE 1: Brute forcing Key2...\n");
    if (!run_brute_force(1, NULL)) {
        fprintf(stderr, "[-] Failed to find Key2\n");
        free(g_encrypted_data);
        return 1;
    }
    
    /* Decrypt with Key2 */
    printf("[*] Decrypting with Key2 to get intermediate data...\n");
    uint8_t *intermediate_data = malloc(g_encrypted_len);
    aes_decrypt_data(g_key2, g_encrypted_data, intermediate_data, g_encrypted_len);
    
    /* Stage 2: Brute force Key1 */
    printf("\n[*] STAGE 2: Brute forcing Key1...\n");
    if (!run_brute_force(2, intermediate_data)) {
        fprintf(stderr, "[-] Failed to find Key1\n");
        FILE *out = fopen("intermediate_data.bin", "wb");
        if (out) {
            fwrite(intermediate_data, 1, g_encrypted_len, out);
            fclose(out);
            printf("[*] Saved intermediate data to: intermediate_data.bin\n");
        }
        print_hex("Key2", g_key2, 16);
        free(intermediate_data);
        free(g_encrypted_data);
        return 1;
    }
    
    clock_t end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    
    /* Output results */
    size_t plaintext_len = remove_pkcs7_padding(g_decrypted_data, g_encrypted_len);
    
    printf("\n======================================================================\n");
    printf("DECRYPTION SUCCESSFUL!\n");
    printf("======================================================================\n");
    print_hex("Key1", g_key1, 16);
    print_hex("Key2", g_key2, 16);
    printf("Time elapsed: %.2f seconds\n", elapsed);
    printf("Decrypted length: %zu bytes\n", plaintext_len);
    
    /* Save to file */
    FILE *out = fopen("decrypted_output.bin", "wb");
    if (out) {
        fwrite(g_decrypted_data, 1, plaintext_len, out);
        fclose(out);
        printf("[+] Saved to: decrypted_output.bin\n");
    }
    
    /* Print decrypted content */
    printf("\n--- Decrypted data (ASCII) ---\n");
    for (size_t i = 0; i < plaintext_len; i++) {
        char c = g_decrypted_data[i];
        if (c >= 32 && c < 127) putchar(c);
        else if (c == '\n' || c == '\r' || c == '\t') putchar(c);
        else putchar('.');
    }
    printf("\n--- End of decrypted data ---\n");
    
    /* Cleanup */
    free(g_decrypted_data);
    free(intermediate_data);
    free(g_encrypted_data);
    
    return 0;
}
```

```bash
gcc -O3 -o brute_force brute.c -lcrypto -lpthread
./brute_force encrypted.bin eaaf324bf7ec6936997d9a90b6925d53 #Command from the python script above
```

### Phase 6: Execution Results

```
[*] STAGE 1: Brute forcing Key2...
[+] KEY2 FOUND by thread 1!
    Key2: e7028f00000000000000000000000000
    Value: 9372391 (0x008f02e7)

[*] STAGE 2: Brute forcing Key1...
[+] KEY1 FOUND by thread 0!
    Key1: 30f25e00000000000000000000000000
    Value: 6222384 (0x005ef230)

Time elapsed: 665.85 seconds (~11 minutes)
```

### Phase 7: Decrypted Traffic

```
REQCONN
REQCONN_OK
DATA REQUEST
mattermost_url
https://198.51.100.166/mattermost/75jNdHZzX-6Zk
```

---

## Solution

**Full URL:** `https://198.51.100.166/mattermost/75jNdHZzX-6Zk`

---