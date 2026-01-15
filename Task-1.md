# NSA Codebreaker Challenge 2025 – Task 1: Getting Started

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Forensics  

---

## Challenge Description

You arrive on site and immediately get to work. The DAFIN-SOC team quickly briefs you on the situation. They have noticed numerous anomalous behaviors, such as tools randomly failing tests and anti-virus flagging on seemingly clean workstations. They have narrowed in on one machine they would like NSA to thoroughly evaluate.

They have provided a zipped EXT2 image from this development machine. Help DAFIN-SOC perform a forensic analysis on this - looking for any suspicious artifacts.

**Prompt:** Provide the SHA-1 hash of the suspicious artifact.

**Provided Materials:**
- `image.ext2.zip` – Zipped EXT2 filesystem image

---

## Methodology

### Phase 1: Initial Reconnaissance

Examined the filesystem image properties:

```bash
ls -lh image.ext2
file image.ext2
```

Confirmed as an ext2 filesystem. Rather than mounting (requires elevated privileges), utilized `debugfs` for non-invasive exploration.

### Phase 2: Filesystem Structure Analysis

Enumerated the root directory structure:

```bash
debugfs -R "ls -l" image.ext2
```

**Findings:** Standard Linux directory hierarchy (bin, etc, home, root, var)

### Phase 3: User Activity Investigation

Investigated root user's home directory:

```bash
debugfs -R "ls -l /root" image.ext2
```

**Key Discovery:** `.bash_history` file unusually large at 140,246 bytes—significantly larger than typical bash history files.

### Phase 4: Bash History Extraction

Extracted bash history for examination:

```bash
debugfs -R "dump /root/.bash_history bash_history_extracted" image.ext2
```

Analysis revealed suspicious operations involving file `awscevnoxu`:

```bash
cat bash_history_extracted | grep awscevnoxu

cp c /etc/runlevels/shutdown/awscevnoxu
/bin/console -s -o /etc/runlevels/shutdown/awscevnoxu
rm -f etc/runlevels/shutdown/awscevnoxu

```

**Analysis:**
- File copied to `/etc/runlevels/shutdown/awscevnoxu`
- `/bin/console` executed with this file as output
- Deletion attempted (failed due to typo: missing leading `/`)

### Phase 5: Artifact Location

Investigated shutdown runlevel directory:

```bash
debugfs -R "ls -l /etc/runlevels/shutdown" image.ext2
```

**Discovery:** File `awscevnoxu` (59 bytes) at `/etc/runlevels/shutdown/awscevnoxu`

Extracted artifact:

```bash
debugfs -R "dump /etc/runlevels/shutdown/awscevnoxu awscevnoxu" image.ext2
```

### Phase 6: Hash Calculation

Calculated SHA-1 hash:

```bash
sha1sum awscevnoxu
```

**Result:** `6d9bfd42c2c8f565f745e8faa1a4c05f026ab54a`

---

## Solution

**SHA-1 Hash:** `6d9bfd42c2c8f565f745e8faa1a4c05f026ab54a`  
**Artifact Path:** `/etc/runlevels/shutdown/awscevnoxu`

---
