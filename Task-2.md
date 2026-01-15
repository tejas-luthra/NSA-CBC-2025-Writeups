# NSA Codebreaker Challenge 2025 – Task 2: The Hunt Continues

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Network Forensics  

---

## Challenge Description

With your help, the team concludes that there was clearly a sophisticated piece of malware installed on that endpoint that was generating some network traffic. Fortunately, DAFIN-SOC also has an IDS which retained the recent network traffic in this segment.

DAFIN-SOC has provided a PCAP to analyze. Thoroughly evaluate the PCAP to identify potential malicious activity.


**Prompt:** Submit all the IP addresses that are assigned to the malicious device, one per line

**Provided Materials:**
- `traffic.pcap` – PCAP to analyze

---

## Methodology

### Phase 1: DNS Traffic Analysis with Zeek

Analyzed the PCAP using Zeek. The DNS traffic captures interest:

```bash
zeek -r traffic.pcap
cat dns.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA Z answers TTLs rejected | tail
```

**Output (last 10 entries):**
```
192.168.46.133  47958   192.168.46.2    53      udp     50959   0.018000        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdcus02.centralus.cloudapp.azure.com,135.233.45.221        5.000000,5.000000,5.000000      F
192.168.46.133  58239   192.168.46.2    53      udp     36290   0.113511        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdeus04.eastus.cloudapp.azure.com,135.234.160.245  5.000000,5.000000,5.000000      F
192.168.46.133  58239   192.168.46.2    53      udp     36290   0.222262        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdeus03.eastus.cloudapp.azure.com,135.234.160.246  5.000000,5.000000,5.000000      F
192.168.46.133  47312   192.168.46.2    53      udp     8619    0.010000        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdeus02.eastus.cloudapp.azure.com,135.234.160.244  5.000000,5.000000,5.000000      F
192.168.46.133  36317   192.168.46.2    53      udp     44673   0.168750        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdcus02.centralus.cloudapp.azure.com,135.233.45.221        5.000000,5.000000,5.000000      F
192.168.46.133  36317   192.168.46.2    53      udp     44673   0.198451        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdwus02.westus.cloudapp.azure.com,172.178.240.163  5.000000,5.000000,5.000000      F
192.168.3.188   37197   192.168.3.254   53      udp     49345   -       archive.ubuntu.com      1       C_INTERNET      1       A       -       -       F       F       T       F       0       -       -       F
192.168.3.188   57751   192.168.3.254   53      udp     30980   2.794355        archive.ubuntu.com      1       C_INTERNET      28      AAAA    0       NOERROR F       F       T       T       0       2620:2d:4000:1::102,2620:2d:4002:1::103,2620:2d:4002:1::101,2620:2d:4002:1::102,2620:2d:4000:1::101,2620:2d:4000:1::103  60.000000,60.000000,60.000000,60.000000,60.000000,60.000000     F
192.168.46.133  60012   192.168.46.2    53      udp     43112   0.092973        watson.events.data.microsoft.com        1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       blobcollectorcommon.trafficmanager.net,onedsblobvmssprdwus04.westus.cloudapp.azure.com,172.178.240.162  5.000000,5.000000,5.000000      F
192.168.3.188   37197   192.168.3.254   53      udp     49345   -       archive.ubuntu.com      -       -       -       -       0       NOERROR F       F       F       T       0       203.0.113.108   37.000000       F
```

### Phase 2: Identifying Malicious DNS Response

**Suspicious entry discovered:**
```
192.168.3.188   37197   192.168.3.254   53      udp     49345   -       archive.ubuntu.com      -       -       -       -       0       NOERROR F       F       F       T       0       203.0.113.108   37.000000       F
```

**Legitimate Response**
```
192.168.2.129   37197   192.168.2.254   53      udp     49345   -       archive.ubuntu.com      -       -       -       -       0       NOERROR F       F       F       T       0       91.189.91.83,91.189.91.81,185.125.190.83,185.125.190.82,185.125.190.81,91.189.91.82      37.000000,37.000000,37.000000,37.000000,37.000000,37.000000     F
```

**Red flags:**
- Query: `archive.ubuntu.com` (legitimate Ubuntu package repository)
- Answer: `203.0.113.108` (different from the other responses - suspicious)

**Analysis:** DNS hijacking detected. The device at `192.168.3.254` is responding with a fake IP address for Ubuntu's package repository.

### Phase 3: MAC Address Identification

Filtered Wireshark for the suspicious DNS server:
```
ip.addr == 192.168.3.254
```

Examined Linux Cooked Capture v2 (SLL2) frames to extract link-layer information:

**MAC Address:** `00:0c:29:6b:81:d4` (VMware virtual NIC)

### Phase 4: FTP Configuration Extraction

Filtered for FTP traffic from the malicious device:
```
ftp
```

Discovered FTP object list containing router configuration backups:

| Packet | Size | Filename |
|--------|------|----------|
| 38 | 9856 bytes | `ftp/RFC2549.txt` |
| 185 | 9856 bytes | `RFC2549.txt` |
| 1101 | 808 bytes | `ftp/router1_backup.config` |
| 1625 | 842 bytes | `ftp/router3_backup.config` |
| 2259 | 1339 bytes | `ftp/router2_backup.config` |

Exported FTP objects (File → Export Objects → FTP-DATA) and examined `router3_backup.config`:

```
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.8.4.3'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fdf2:87c7:eb73::/48'
	option packet_steering '1'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'eth0'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.3.254'
	option netmask '255.255.255.0'
	option ip6assign '60'

config interface 'to_openwrt2'
	option device 'eth1'
	option proto 'static'
	list ipaddr '192.168.5.1/28'

config interface 'host_nat'
	option proto 'dhcp'
	option device 'eth2'

config route
	option target '192.168.3.0/24'
	option gateway '192.168.3.254'
	option interface 'lan'

config route
	option target '0.0.0.0/0'
	option gateway '192.168.5.2'
	option interface 'to_openwrt2'
```

### Phase 5: IP Address Enumeration

**Extracted IP addresses assigned to router3 (malicious device):**

1. **Loopback interface:** `127.8.4.3/8`
2. **LAN bridge (br-lan):** `192.168.3.254/24`
3. **to_openwrt2 interface:** `192.168.5.1/28`

---

## Solution

**IP Addresses (one per line):**
```
192.168.5.1
192.168.3.254
127.8.4.3
```

---
