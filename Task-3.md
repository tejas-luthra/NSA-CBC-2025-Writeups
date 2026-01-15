# NSA Codebreaker Challenge 2025 – Task 3: Digging Deeper

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Reverse Engineering  

---

## Challenge Description

The network administrators confirm that the IP address you provided in your description is an edge router. DAFIN-SOC is asking you to dive deeper and reverse engineer this device. Fortunately, their team managed to pull a memory dump of the device.

Scour the device's memory dump and identify anomalous or malicious activity to find out what's going on.

Your submission will be a list of IPs and domains, one per line. For example:

127.0.0.1 localhost
192.168.54.131 corp.internal
...

**Prompt:** Submit a complete list of affected IPs and FQDNs, one per line.

**Provided Materials:**
- `memory.dump.gz` – Compressed memory dump from compromised router
- `System.map.br` – Brotli-compressed kernel symbol table
- `vmlinux.xz` – XZ-compressed Linux kernel image

---

## Methodology

### Phase 1: Environment Setup

Extract provided files:
```bash
gunzip -k memory.dump.gz
brotli -d -k System.map.br
xz -dk vmlinux.xz
```

Identify kernel version:
```bash
strings vmlinux | grep -E "Linux version [0-9]" | head -1
# Linux version 5.15.134
```

Generate Volatility symbol table:
```bash
mkdir -p symdir
cp System.map vmlinux symdir/
dwarf2json linux --elf vmlinux --system-map System.map > symdir/linux-5.15.134.json
```

### Phase 2: Process Analysis

List all processes:
```bash
python3 volatility3/vol.py -s symdir -f memory.dump linux.pstree
```

**Suspicious process identified:**
```
PID    PPID   COMM
1      0      procd
├── 1168   1      dnsmasq          ← Legitimate
├── 515    1      ash              
│   └── 1552   515    4            ← SUSPICIOUS
│       └── 1854   1552   service  
│           └── 1855   1854   dnsmasq  ← Duplicate dnsmasq
```

**Red flags:**
1. Process named "4" – unusual single-digit name (PID 1552)
2. Spawned from shell (ash) – manual execution
3. Duplicate dnsmasq process
4. Child processes mimicking legitimate services

### Phase 3: Binary Extraction

Extract ELF information:
```bash
python3 volatility3/vol.py -s symdir -f memory.dump linux.elfs.Elfs --pid 1552 --dump
```

**Critical discovery:**
```
PID   Process  File Path
1552  4        /memfd:x (deleted)  ← Fileless malware technique
```

The malware used `memfd_create()` to execute entirely from memory without touching disk.

Extract complete memory segments:
```bash
python3 volatility3/vol.py -f memory.dump -s symdir -o dumps linux.proc.Maps --pid 1552 --dump
```

Reconstruct binary:
```bash
cat dumps/pid.1552.vma.0x557fab568000-0x557fab569000.dmp \
    dumps/pid.1552.vma.0x557fab569000-0x557fab56a000.dmp \
    dumps/pid.1552.vma.0x557fab56a000-0x557fab56b000.dmp \
    dumps/pid.1552.vma.0x557fab56b000-0x557fab56c000.dmp \
    dumps/pid.1552.vma.0x557fab56c000-0x557fab56d000.dmp > full_binary.bin
```

### Phase 4: Malware Analysis

Analyze strings:
```bash
strings full_binary.bin | grep -E "(Usage|hosts|dnsmasq)"
```

**Key strings found:**
```
Usage: %s <encoded file>
opening /etc/hosts
service dnsmasq restart
```

**Malware behavior:**
1. Takes encoded file as input
2. Decodes payload
3. Writes entries to `/etc/hosts`
4. Restarts dnsmasq to apply DNS changes

### Phase 5: Payload Extraction

Search for encoded payload in memory:
```bash
strings full_binary.bin | tail 


fopen /etc/hosts
%s %s
warning: weird token count (%zu); ignoring last... check this fff
Usage: %s <encoded file>
Decoded payload too short to even have the key...
service dnsmasq restart
;*3$"
?456789:;<=
 !"#$%&'()*+,-./0123
i21DxsxndoZJu7rQmvIH/DzPEhMPVo1Xs+YVeo3Ac+8eSQpcNDDPNdCg3aHCIf4jI+r6G1utINPAKTTBnQCMTgkSJULhUPLkgMWuvC38U1PzpRAinLZIDRcKxJwE+yQZLgJd7DKBys6MJyCDWeLOcU/wzhTIVlFFeLoVhChmEAI2Zex/veX7m38Q8IAmXl0gu6hkjxx+Kl6vWL9dWgtEicxVNeyJflCZ8GMa1rmw+iLaQPrRsM2zUYxU3siftisFz+RFKiIdyFLUnl1GUzGNLJs8HxpguPVmWdf3v4g+F6+KCUoWCpNY7a6atJypFMZ4tI2Gzx5n45E0WqTLZqZ8auO3wMIh6xpoBkk76Vvc0h0RHXuT8V810cB1fNAC8/2CwKlet0O7PHFqIOJ95LxcXfaQb/AGW6zhLGfXB+Ga64v0F9YMFp7IYGHRSr3vFx+l5AqYUR0bHz+CPJo7XUVmO8ATv7QHRfHFc0Tj4UIekcFUzxRsdENkn1S6t8CMAhaxdM/1THXasyRY3peZjUX5doBPZXhABLk9/PD5+zkVrp0sBEN9+NID834RVS7lRvBWT3tzu/Rs6ysUFXyX8GQRwKuppG7EVKXdp9W3T6xP1MKL3VZxo9kJfmwbxrEiKeb98bEMsA+qwdj8LtUbykZ2NAmAtQEpkrDo4D+nPX4BBSQVvyqZCDswdPYi5cZcZ8T7RXvF30MdWw+yMJ/P47CZTP5iN+Xn7KUEao/hRH7Z22+lamcOQD01wjHV/dzNi03bUle3o0Eq3lDnuktf4/Ek4BgdeAV1iWmJiBRQRw3lYoyacBP8qE3MSgARHJGMcIpnFX0bGv0ox8tgPcmbcQPjg3tusLE4sHVVS3Mbtge4pMmE7eA140VF/NhoUeHMElFGU5gy706EqYyx5xyJO3BkZ729XCfM7Ft8+cIJO6rEifV0nm6JqpSXFEnWGdeYi/YvROmcUyt3Xc4f1zCuy7HPL9Itqd3EwwZ04ZZOInID0asuQYqBjNBS/lz7mO+XEO8l0UFsJxSVvQwrx7u83l7aWxvZgrv+XLxS27bmjx3MGDykgzoCot41ZIKYlcYazmg3Ggg98gaYPvG05f9hoBw6iLsOF7Ry3cD/8syUKaYFbVF4XZ4Fnp1ZX6i/CzmJnjJjz8QU3zUzVjwSv17kRnZ3ayDte53XZ3eE32SjBQFKGpiAX6JFPE4/KJoD9apuf8+cY+oHbo7oElHMWNeSirwrwTTE0L3sgYhYlAAFoPQMZInzDHV1Ze2+JYtVfHYGWOx1hYDWhwoT0e9TasfwSmq7xRBGV2OxA51qAzUNM2f8YKjr7tUMaIqqJA1AcPnMHQmN9bbIPNx+2fn4/ih8t8IAeG4B9ZwDPOT+/P9nuWWH/5LhlnKtSMaj/ZtLMrTfNkLlmEfDSArBxOWtVP1N6ZDesT/LGRKbvvzYYFPowCk2cjLwcMeGtbuWOI4QpmQcFkSPRpqkHjuLoAbBYHXbieL8XMpjSHwXMvB4/qF1bWJ9hQ/tzmYohJY+82N0EE8p0CnHakZVaSWsJNSXaGbXhnbqXlz7oS0++STapMCzxzruTw0nL57PPe5GcMTuVkvrNKin+aAh11PzQ3AnGUv/ZanlHB/10DNBqYDA43lzpG/kh8m/MsYF/6Odh1AchBmY9RFiiuJwDdClrYsbqSuY

```

Found custom base64 encoded payload in libc memory region. Save that to ``payload.enc``

```bash
cat payload.enc       
        
i21DxsxndoZJ
UX5doBPZXhABLk9/PD5+zkVrp0sBEN9+NID834RVS7lRvBWT3tzu/Rs6ysUFXyX8GQRwKuppG7EVKXdp9W3T6xP1MKL3VZxo9kJfmwbxrEiKeb98bEMsA+qwdj8LtUbykZ2NAm
rDo4D+nPX4BBSQVvyqZCDswdPYi5cZcZ8T7RXvF30MdWw+yMJ/P47CZTP5iN+Xn7KUEao/hRH7Z22+lamcOQD01wjHV/dzNi03bUle3o0Eq3lDnuktf4/Ek4BgdeAV1iWmJiBRQRw3lYoyacBP8qE3MSgARHJGMcIpnFX0bGv0ox8tgPcmbcQPjg3tusLE4sHVVS3Mbtge4pMmE7eA140VF/NhoUeHMElFGU5gy706EqYyx5xyJO3BkZ729XCfM7Ft8+cIJO6rEifV0nm6JqpSXFEnWGdeYi/YvROmcUyt3Xc4f1zCuy7HPL9Itqd3EwwZ04ZZOInID0asuQYqBjNBS/lz7mO+XEO8l0UFsJxSVvQwrx7u83l7aWxvZgrv+XLxS27bmjx3MGDykgzoCot41ZIKYlcYazmg3Ggg98gaYPvG05f9hoBw6iLsOF7Ry3cD/8syUKaYFbVF4XZ4Fnp1ZX6i/CzmJnjJjz8QU3zUzVjwSv17kRnZ3ayDte53XZ3eE32SjBQFKGpiAX6JFPE4/KJoD9apuf8+cY+oHbo7oElHMWNeSirwrwTTE0L3sgYhYlAAFoPQMZInzDHV1Ze2+JYtVfHYGWOx1hYDWhwoT0e9TasfwSmq7xRBGV2OxA51qAzUNM2f8YKjr7tUMaIqqJA1AcPnM
QmN9bbIPNx+2fn4/ih8t8IAeG4B9ZwDPOT+/P9nuWWH/5LhlnKtSMaj/ZtLMrTfNkLlmEfDSArBxOWtVP1N6ZDesT/LGRKbvvzYYFPowCk2cjLwcMeGtbuWOI4QpmQcFkSPRpqkHjuLoAbBYHXbieL8XMpjSHwXMvB4/qF1bWJ9hQ/tzmYohJY+82N0EE8p0CnHakZVaSWsJNSXaGbXhnbqXlz7oS0++STapMCzxzruTw0nL57PPe5GcMTuVkvrNKin+aAh11PzQ3AnGUv/ZanlHB/10DNBqYDA43lzpG/kh8m/MsYF/6Odh1AchBmY9RFiiuJwDdClrYsbqSuY
```
### Phase 6: Payload Decryption

Execute malware in isolated VM:
```bash
chmod +x full_binary.bin
sudo ./full_binary.bin payload.enc
cat /etc/hosts
```

---

## Solution

Complete DNS hijacking configuration (38 entries):

```
203.0.113.224 ports.ubuntu.com
203.0.113.158 mirrors.rockylinux.org
203.0.113.158 mirrors.kernel.org
203.0.113.158 mirrors.fedoraproject.org
203.0.113.158 mirrors.rpmfusion.org
203.0.113.224 us.archive.ubuntu.com
203.0.113.224 archive.archlinux.org
203.0.113.224 deb.debian.org
203.0.113.224 security.debian.org
203.0.113.115 files.pythonhosted.org
203.0.113.115 pypi.org
203.0.113.158 geo.mirror.pkgbuild.com
203.0.113.224 repo-default.voidlinux.org
203.0.113.224 download.opensuse.org
203.0.113.115 pypi.python.org
203.0.113.158 mirror.rackspace.com
203.0.113.224 archive.ubuntu.com
203.0.113.224 ports.ubuntu.com
203.0.113.224 distfiles.gentoo.org
203.0.113.158 mirror.stream.centos.org
203.0.113.224 ftp.us.debian.org
203.0.113.224 packages.linuxmint.com
203.0.113.224 http.kali.org
203.0.113.224 security.ubuntu.org
203.0.113.224 archive.ubuntu.org
203.0.113.224 dl.rockylinux.org
203.0.113.224 dl-cdn.alpinelinux.org
203.0.113.224 security.ubuntu.com
203.0.113.224 download1.rpmfusion.org
203.0.113.158 mirrors.opensuse.org
203.0.113.158 xmirror.voidlinux.org
203.0.113.224 dl.fedoraproject.org
203.0.113.224 repos.opensuse.org
203.0.113.224 cache.nixos.org
203.0.113.115 pypi.io
203.0.113.224 repo.almalinux.org
203.0.113.158 mirrors.alpinelinux.org
```

---