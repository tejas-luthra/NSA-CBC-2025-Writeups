# NSA Codebreaker Challenge 2025 – Task 4: Unpacking Insight

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Malware Analysis

---

## Challenge Description

Once back at NSA the team contacts the NSA liaison at FBI to see if they have any information about what was discovered in the configuration data. FBI informs us that the facility registered to host that domain is on a watchlist for suspected criminal activity. With this tip, the FBI acquires a warrant and raids the location. Inside the facility, the server is discovered along with a suspect. The suspect is known to the FBI as a low-level malware actor. During questioning, they disclose that they are providing a service to host malware for various cybercrime groups, but recently they were contacted by a much more secretive and sophisticated customer. While they don't appear to know anything about who is paying for the service, they provide the FBI with the malware that was hosted.

Back at NSA, you are provided with a copy of the file. There is a lot of high level interest in uncovering who facilitated this attack. The file appears to be obfuscated.

You are tasked to work on de-obfuscating the file and report back to the team.

**Objective:** Submit the file path the malware uses to write a file

**Provided Materials:**
- `suspicious` – Obfuscated 64-bit ELF executable

---

## Methodology

### Phase 1: Initial Analysis

```bash
file suspicious
# ELF 64-bit LSB executable, x86-64, dynamically linked
```

### Phase 2: Discovering Anti-Debug Mechanisms

Initial attempt to run under GDB:
```bash
gdb ./suspicious
(gdb) run
```

**Result:** Immediate SIGSEGV (segmentation fault) at address `0x55555555765a`

Examining the crash location using GEF (GDB Enhanced Features):
```
0x55555555765a    mov DWORD PTR ds:0x0, 0x0
```

This instruction deliberately writes to NULL (address 0x0) to crash when debugger is detected. 

**Note:** I highly recommend using [GEF](https://github.com/hugsy/gef) for enhanced GDB analysis - it provides color-coded instruction listings, register values, and stack views automatically.

### Phase 3: Identifying Anti-Debug Chain

Simply NOPing the crash proved insufficient. Through static analysis in IDA, I examined the anti-debug chain and discovered two protection mechanisms:

**Mechanism 1: ptrace Detection (sub_3590)**

Located at address `0x3590`, uses `ptrace(PTRACE_TRACEME)` to detect debuggers:

```c
__int64 sub_3590()
{
    __int64 result;
    
    if ( ptrace(PTRACE_TRACEME, 0, 1, 0) != -1 ||
         (result = (unsigned int)*__errno_location(), (_DWORD)result != 1) )
    {
        ptrace(PTRACE_DETACH, 0, 1, 0);
        return 0;  // No debugger
    }
    return result;  // Debugger detected (returns non-zero)
}
```

**How it works:**
- When a process is already traced by a debugger, `PTRACE_TRACEME` fails
- Failure sets `errno = EPERM (1)`
- Function returns non-zero if debugger detected, triggering anti-debug chain

**Mechanism 2: TracerPid Check (sub_3470)**

Located at address `0x3470`, reads `/proc/self/status` to check TracerPid field:

```c
_BOOL8 sub_3470()
{
    // Opens /proc/self/status
    if ( !(unsigned int)sub_56A0(&stream, "r", "/proc/self/status") )
    {
        while ( getline(&haystack, &n, stream) != -1 )
        {
            if ( strstr(haystack, "TracerPid") )
            {
                if ( strtok(v0, delim) )
                {
                    v4 = strtok(0, delim);
                    if ( v4 )
                    {
                        v2 = *v4 != 48;  // Returns true if TracerPid != '0'
                        // ...
                    }
                }
            }
        }
    }
    return v2;
}
```

**How it works:**
- Reads `/proc/self/status` which contains TracerPid field
- When debugger attached, TracerPid = PID of debugging process
- Function returns true when TracerPid != '0' (debugging detected)

### Phase 4: Binary Patching

**Patch Strategy:**

To bypass both anti-debug checks, patch each function to immediately return 0 (no debugger detected):
- Replace function prologue with: `xor eax, eax; ret`
- Assembly: `31 c0 c3`
- This makes function return 0 without executing detection logic

Created `patch.py`:
```python
#!/usr/bin/env python3
with open('suspicious', 'rb') as f:
    data = bytearray(f.read())

# Patch anti_debug_ptrace_check at 0x3594
# Replace function start with: xor eax,eax; ret
data[0x3594:0x3597] = b'\x31\xc0\xc3'
print("Patched ptrace check")

# Patch anti_debug_tracerpid_check at 0x3474  
data[0x3474:0x3477] = b'\x31\xc0\xc3'
print("Patched TracerPid check")

with open('suspicious_patched', 'wb') as f:
    f.write(data)

print("Saved: suspicious_patched")
```

**Note:** Patch addresses (`0x3594` and `0x3474`) are offset by +4 from function start addresses (`0x3590` and `0x3470`) to skip the `endbr64` instruction present in binaries compiled with Intel CET (Control-flow Enforcement Technology).

Execute patch:
```bash
python3 patch.py
# Patched ptrace check
# Patched TracerPid check
# Saved: suspicious_patched
```

### Phase 5: Dynamic Analysis with GDB

Since the challenge asks for "the file path the malware uses to write a file," I set a catchpoint on the `write` system call:

```bash
gdb ./suspicious_patched
```

```
gef➤  catch syscall write
Catchpoint 1 (syscall 'write' [1])
gef➤  run
```

The program first hit an anti-debug trap that wasn't fully patched:
```asm
0x55555555765a    mov DWORD PTR ds:0x0, 0x0  ; NULL pointer write
```

Continue past this:
```
gef➤  continue
```

### Phase 6: Analyzing the Write System Call

Hit the write syscall breakpoint. On x86-64 Linux, write system call arguments are:
- `rdi` = file descriptor (where to write)
- `rsi` = buffer pointer (what to write)  
- `rdx` = byte count (how much to write)

Examine registers:
```
gef➤  info registers rdi rsi rdx
rdi            0x3                 0x3
rsi            0x555555590390      0x555555590390
rdx            0xcee8              0xcee8
```

**Analysis:**
- Writing to file descriptor 3
- 0xcee8 (52,968) bytes from address 0x555555590390
- Large size suggests unpacked payload

### Phase 7: Identifying the File Descriptor

Check what file descriptor 3 represents:
```bash
gef➤  shell ls -la /proc/$(pgrep suspicious)/fd/
total 0
dr-x------ 2 kali kali  4 Jan 14 20:35 .
dr-xr-xr-x 9 kali kali  0 Jan 14 20:35 ..
lrwx------ 1 kali kali 64 Jan 14 20:35 0 -> /dev/pts/8
lrwx------ 1 kali kali 64 Jan 14 20:35 1 -> /dev/pts/8
lrwx------ 1 kali kali 64 Jan 14 20:35 2 -> /dev/pts/8
lrwx------ 1 kali kali 64 Jan 14 20:35 3 -> '/memfd: (deleted)'
```

**Key finding:** FD 3 points to `/memfd: (deleted)` - a memory-backed file created with `memfd_create()`. This is a fileless malware technique that unpacks payload into memory without writing to disk.

### Phase 8: Extract the Unpacked Payload

While paused in debugger, dump the payload from memory:
```bash
gef➤  dump binary memory ./extracted.elf 0x555555590390 0x555555590390+0xcee8
```

Verify extraction:
```bash
file extracted.elf
# ELF 64-bit LSB pie executable, x86-64, dynamically linked
```

### Phase 9: Analyze Extracted Payload in IDA

Opened `extracted.elf` in IDA for static analysis.

**Identifying the Main Function:**

Located the `run` function at address `0x8D65`:

```asm
.text:0000000000008D65 run proc near
.text:0000000000008D8F    lea  rcx, aSkibidi    ; "skibidi"
.text:0000000000008D96    mov  rsi, rcx
.text:0000000000008D99    mov  rdi, rax
.text:0000000000008D9C    call sub_7C8E
```

**Critical discovery:** The string `"skibidi"` was immediately visible - this looked like an encryption key being passed to an initialization function.

**Tracing the Encryption Scheme:**

The binary made multiple calls to decryption functions:
- `sub_8574` - First decryption check
- `sub_8666` - Second decryption check
- `sub_8795` - Third decryption check
- `sub_8A0F` - Fourth decryption check
- `sub_7F5D` - Final payload decryption

Each function referenced encrypted byte arrays in the data section.

**Identifying RC4 Encryption:**

Analyzed the initialization function `sub_7C8E` and recognized the classic RC4 Key Scheduling Algorithm (KSA):

```c
void init_rc4(uint8_t *S, uint8_t *key, int keylen) {
    for (int i = 0; i < 256; i++) {
        S[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        swap(&S[i], &S[j]);
    }
}
```

**Key insight:** The RC4 state was initialized **once** with "skibidi" and then used sequentially to decrypt multiple strings. This means decryption order is critical.

**Locating Encrypted Data:**

Examined the data section to find all encrypted byte arrays:

```
unk_D580: PDF path (38 bytes)
unk_D5B0: Environment variable (17 bytes)
unk_D5C8: File to read (13 bytes)
unk_D5D5: Search string 1 (5 bytes)
unk_D5E0: Search string 2 (10 bytes)
unk_D5F0: Command (31 bytes)
unk_D60F: Command mode (1 byte)
unk_D610: Command search (4 bytes)
unk_D618: IP address (12 bytes)
unk_D630: HTTP request (20 bytes)
unk_D644: Filename part 1 (5 bytes)
unk_D649: Filename part 2 (1 byte)
unk_D650: Filename part 3 (16 bytes)
```

### Phase 10: Extract Encrypted Bytes

Used IDA to extract the hex values of encrypted data.

**IDA Python method:**
```python
import idc

addrs = [
    (0xD580, 38, 'PDF path'),
    (0xD5B0, 17, 'Env var'),
    (0xD5C8, 13, 'File to read'),
    (0xD5D5, 5, 'Search 1'),
    (0xD5E0, 10, 'Search 2'),
    (0xD5F0, 31, 'Command'),
    (0xD60F, 1, 'Command mode'),
    (0xD610, 4, 'Command search'),
    (0xD618, 12, 'IP addr'),
    (0xD630, 20, 'HTTP req'),
    (0xD644, 5, 'Filename 1'),
    (0xD649, 1, 'Filename 2'),
    (0xD650, 16, 'Filename 3')
]

for addr, size, desc in addrs:
    data = idc.get_bytes(addr, size)
    print(f'{hex(addr)} ({size:2d} bytes) {desc}: {data.hex()}')
```

**IDC method (for those without IDA Python):**

Open IDC window (File → Script file... or Shift+F2), then run:
```c
#include <idc.idc>

static main() {
    auto addr, size, i;
    auto data;
    
    // PDF path (38 bytes)
    Message("0xD580 (38 bytes) PDF path: ");
    for (i = 0; i < 38; i++) {
        Message("%02X", Byte(0xD580 + i));
    }
    Message("\n");
    
    // Environment variable (17 bytes)
    Message("0xD5B0 (17 bytes) Env var: ");
    for (i = 0; i < 17; i++) {
        Message("%02X", Byte(0xD5B0 + i));
    }
    Message("\n");
    
    // File to read (13 bytes)
    Message("0xD5C8 (13 bytes) File to read: ");
    for (i = 0; i < 13; i++) {
        Message("%02X", Byte(0xD5C8 + i));
    }
    Message("\n");
    
    // Search string 1 (5 bytes)
    Message("0xD5D5 (5 bytes) Search 1: ");
    for (i = 0; i < 5; i++) {
        Message("%02X", Byte(0xD5D5 + i));
    }
    Message("\n");
    
    // Search string 2 (10 bytes)
    Message("0xD5E0 (10 bytes) Search 2: ");
    for (i = 0; i < 10; i++) {
        Message("%02X", Byte(0xD5E0 + i));
    }
    Message("\n");
    
    // Command (31 bytes)
    Message("0xD5F0 (31 bytes) Command: ");
    for (i = 0; i < 31; i++) {
        Message("%02X", Byte(0xD5F0 + i));
    }
    Message("\n");
    
    // Command mode (1 byte)
    Message("0xD60F (1 byte) Command mode: %02X\n", Byte(0xD60F));
    
    // Command search (4 bytes)
    Message("0xD610 (4 bytes) Command search: ");
    for (i = 0; i < 4; i++) {
        Message("%02X", Byte(0xD610 + i));
    }
    Message("\n");
    
    // IP address (12 bytes)
    Message("0xD618 (12 bytes) IP addr: ");
    for (i = 0; i < 12; i++) {
        Message("%02X", Byte(0xD618 + i));
    }
    Message("\n");
    
    // HTTP request (20 bytes)
    Message("0xD630 (20 bytes) HTTP req: ");
    for (i = 0; i < 20; i++) {
        Message("%02X", Byte(0xD630 + i));
    }
    Message("\n");
    
    // Filename part 1 (5 bytes)
    Message("0xD644 (5 bytes) Filename 1: ");
    for (i = 0; i < 5; i++) {
        Message("%02X", Byte(0xD644 + i));
    }
    Message("\n");
    
    // Filename part 2 (1 byte)
    Message("0xD649 (1 byte) Filename 2: %02X\n", Byte(0xD649));
    
    // Filename part 3 (16 bytes)
    Message("0xD650 (16 bytes) Filename 3: ");
    for (i = 0; i < 16; i++) {
        Message("%02X", Byte(0xD650 + i));
    }
    Message("\n");
}
```

Check the "Output" window (View → Open subviews → Output window) to see the hex dumps.

### Phase 11: Decrypt Strings

Created Python decryption script using the RC4 implementation identified in Phase 7:

```python
#!/usr/bin/env python3
"""
RC4 Decryption Script - Reads encrypted bytes from a text file
Usage: python decrypt_from_file.py encrypted_data.txt
"""

import sys
import re

class RC4State:
    def __init__(self, key):
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def get_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]
    
    def decrypt(self, data):
        return bytes(byte ^ self.get_byte() for byte in data)


def parse_encrypted_file(filepath):
    """
    Parse a text file with lines in format:
    0xd580 (38 bytes) PDF path: c71675c60fc7143616af4c1d340141baf922b9ac42a6c7070009f759c9e12e6377f3a071db1f
    """
    entries = []
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Match pattern: 0xADDR (N bytes) Description: HEXDATA
            match = re.match(r'0x([0-9a-fA-F]+)\s*\(?\s*(\d+)\s*bytes?\)?\s*([^:]+):\s*([0-9a-fA-F]+)', line)
            if match:
                addr = int(match.group(1), 16)
                size = int(match.group(2))
                desc = match.group(3).strip()
                hex_data = match.group(4).strip()
                
                entries.append({
                    'addr': addr,
                    'size': size,
                    'desc': desc,
                    'hex': hex_data,
                    'bytes': bytes.fromhex(hex_data)
                })
    
    return entries


def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt_from_file.py <encrypted_data.txt>")
        print("\nExpected file format:")
        print("0xd580 (38 bytes) PDF path: c71675c60fc714...")
        sys.exit(1)
    
    filepath = sys.argv[1]
    entries = parse_encrypted_file(filepath)
    
    if not entries:
        print(f"No valid entries found in {filepath}")
        sys.exit(1)
    
    # Initialize RC4 with key "skibidi"
    state = RC4State(b"skibidi")
    
    print("=" * 70)
    print("RC4 DECRYPTION RESULTS")
    print("Key: 'skibidi'")
    print("=" * 70)
    
    filename_parts = []
    
    for i, entry in enumerate(entries, 1):
        decrypted = state.decrypt(entry['bytes'])
        
        # Store filename parts
        if 'filename' in entry['desc'].lower():
            filename_parts.append(decrypted)
        
        print(f"\n{i}. {entry['desc']} ({hex(entry['addr'])}, {entry['size']} bytes)")
        print(f"   Encrypted: {entry['hex']}")
        try:
            print(f"   Decrypted: {decrypted.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"   Decrypted: {decrypted}")
    
    # Combine filename parts if found
    if filename_parts:
        combined = b''.join(filename_parts)
        print("\n" + "=" * 70)
        print("COMBINED FILENAME:")
        try:
            print(f"   {combined.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"   {combined}")
        print("=" * 70)


if __name__ == "__main__":
    main()
```

Create a decrypt.txt from the IDA output

```bash
cat decrypt.txt

0xd580 (38 bytes) PDF path: c71675c60fc7143616af4c1d340141baf922b9ac42a6c7070009f759c9e12e6377f3a071db1f
0xd5b0 (17 bytes) Env var: d238bd57189ec1375ac9b7bf93dad34ba4
0xd5c8 (13 bytes) File to read: d562fb654a1a4603bcf4ae739e
0xd5d5 ( 5 bytes) Search 1: b4b2e48e6d
0xd5e0 (10 bytes) Search 2: 78c850a517827afdbb88
0xd5f0 (31 bytes) Command: f32927c9623a5945155fbdd97584797a5fac1ea330150cfa870cc63a26d98b
0xd60f ( 1 bytes) Command mode: 39
0xd610 ( 4 bytes) Command search: 4d542635
0xd618 (12 bytes) IP addr: 53d9c6d8098227cfa1de178a
0xd630 (20 bytes) HTTP req: d2208a737562cb5bb565da5f74b1b54a197d5792
0xd644 ( 5 bytes) Filename 1: 10dbf50699
0xd649 ( 1 bytes) Filename 2: c4
0xd650 (16 bytes) Filename 3: 4a046b90c6077cc31a63781e0b3ca9aa
```

Run the script

```bash
python3 decrypt.py decrypt.txt
```

**Decrypted output:**
```
======================================================================
RC4 DECRYPTION RESULTS
Key: 'skibidi'
======================================================================

1. PDF path (0xd580, 38 bytes)
   Encrypted: c71675c60fc7143616af4c1d340141baf922b9ac42a6c7070009f759c9e12e6377f3a071db1f
   Decrypted: /opt/dafin/intel/ops_brief_redteam.pdf

2. Env var (0xd5b0, 17 bytes)
   Encrypted: d238bd57189ec1375ac9b7bf93dad34ba4
   Decrypted: DAFIN_SEC_PROFILE

3. File to read (0xd5c8, 13 bytes)
   Encrypted: d562fb654a1a4603bcf4ae739e
   Decrypted: /proc/cpuinfo

4. Search 1 (0xd5d5, 5 bytes)
   Encrypted: b4b2e48e6d
   Decrypted: flags

5. Search 2 (0xd5e0, 10 bytes)
   Encrypted: 78c850a517827afdbb88
   Decrypted: hypervisor

6. Command (0xd5f0, 31 bytes)
   Encrypted: f32927c9623a5945155fbdd97584797a5fac1ea330150cfa870cc63a26d98b
   Decrypted: systemd-detect-virt 2>/dev/null

7. Command mode (0xd60f, 1 bytes)
   Encrypted: 39
   Decrypted: r

8. Command search (0xd610, 4 bytes)
   Encrypted: 4d542635
   Decrypted: none

9. IP addr (0xd618, 12 bytes)
   Encrypted: 53d9c6d8098227cfa1de178a
   Decrypted: 203.0.113.42

10. HTTP req (0xd630, 20 bytes)
   Encrypted: d2208a737562cb5bb565da5f74b1b54a197d5792
   Decrypted: GET /module HTTP/1.1

11. Filename 1 (0xd644, 5 bytes)
   Encrypted: 10dbf50699
   Decrypted: /tmp/

12. Filename 2 (0xd649, 1 bytes)
   Encrypted: c4
   Decrypted: .

13. Filename 3 (0xd650, 16 bytes)
   Encrypted: 4a046b90c6077cc31a63781e0b3ca9aa
   Decrypted: jrTXJaAFNWvOKEzs

======================================================================
COMBINED FILENAME:
   /tmp/.jrTXJaAFNWvOKEzs
======================================================================
```

---

## Solution

**File Path:** `/tmp/.jrTXJaAFNWvOKEzs`

**Additional Decrypted Strings:**
- PDF: `/opt/dafin/intel/ops_brief_redteam.pdf`
- Environment variable: `DAFIN_SEC_PROFILE`
- Command: `systemd-detect-virt 2>/dev/null`
- IP: `203.0.113.42`

---