---

title: "ToolShell on SharePoint: CVE-2025-49704/49706 and Patch Bypasses CVE-2025-53770/53771"
slug: "sharepoint-toolshell-cves-2025"
date: "2025-09-03"
author: "Bugb Security Team"
authorTitle: "Security Researchers"
excerpt: "A clear look at the recent on-premises SharePoint attack chain dubbed ToolShell, how CVE-2025-49704 and CVE-2025-49706 were chained for RCE, and how patch-bypass CVEs CVE-2025-53770/53771 raised the stakes—plus what to patch, rotate, hunt and monitor right now."
category: "research"
---

# ToolShell on SharePoint: CVE-2025-49704/49706 and Patch Bypasses CVE-2025-53770/53771

## Summary

A wave of **active attacks** has hit **on-premises Microsoft SharePoint Server** using a chain now widely referred to as **ToolShell**. The chain combines a **spoofing** bug (**CVE-2025-49706**) with a **remote code execution** bug (**CVE-2025-49704**). Microsoft later disclosed **patch bypasses**—**CVE-2025-53770** (related to 49704) and **CVE-2025-53771** (related to 49706)—and shipped comprehensive security updates. **SharePoint Online (Microsoft 365) is not affected.** ([Microsoft][1])

Microsoft and CISA both confirm **in-the-wild exploitation**, with guidance to **apply the latest updates, enable AMSI in Full Mode, rotate ASP.NET machine keys, and restart IIS**. Multiple threat actors, including state-linked groups, have used this chain; some intrusions culminated in ransomware deployment. ([Microsoft][1], [CISA][2])

## Affected Products & Fixed Releases

| Product                                    | Status           | Where to get the July 2025 security updates   |
| ------------------------------------------ | ---------------- | --------------------------------------------- |
| **SharePoint Server Subscription Edition** | **Patched**      | KB5002768 (apply latest comprehensive update) |
| **SharePoint Server 2019**                 | **Patched**      | KB5002754 + KB5002753 (language pack)         |
| **SharePoint Server 2016**                 | **Patched**      | KB5002760 + KB5002759 (language pack)         |
| **SharePoint Online (Microsoft 365)**      | **Not affected** | N/A                                           |

> Updates are cumulative—installing the latest supersedes earlier ones. After patching, **rotate machine keys and restart IIS**. ([Microsoft Security Response Center][3], [Microsoft][1])

## What Are These CVEs?

* **CVE-2025-49704 — RCE**: Enables code execution on vulnerable on-prem SharePoint servers. Widely chained with 49706. ([CISA][2])
* **CVE-2025-49706 — Spoofing**: Network spoofing that helps pivot into the RCE path. ([CISA][2])
* **CVE-2025-53770 — Patch bypass (RCE-related)**: Newer issue related to 49704; Microsoft confirms comprehensive updates now address it. ([Microsoft][1], [NVD][4])
* **CVE-2025-53771 — Patch bypass (path traversal / security bypass)**: Related to 49706; covered by the July comprehensive updates. ([Microsoft][1])

CISA added these to KEV and published a MAR with web-shell and TTP details, underscoring real-world impact. ([CISA][2])

## How ToolShell Attacks Unfold (at a glance)

1. **Initial access** via crafted requests to SharePoint endpoints (e.g., ToolPane).
2. **Auth bypass + RCE chain** (49706 → 49704), often dropping a web shell.
3. **Post-exploitation**: Exfiltrate **ASP.NET machine keys**, disable defenses, run encoded PowerShell from **w3wp.exe**, then lateral movement.
4. **Impact**: From content theft to **Warlock** ransomware in some cases. ([Microsoft][1])

## Non-Exploit Validation Playbook (Safe for Blue Teams)

Use the steps below to **verify risk** and **hunt for compromise** **without** attempting exploitation.

### 1) Confirm Patch State

* Inventory on-prem SharePoint farms; verify **KB5002768 / KB5002754+2753 / KB5002760+2759** present.
* Ensure you applied **the latest** cumulative updates (July 2025 or later). ([Microsoft Security Response Center][3])

### 2) Enable/Verify AMSI in Full Mode

* Confirm **AMSI integration** is on and **Full Mode** enabled for SharePoint 2016/2019/Subscription Edition. If AMSI cannot be enabled, consider **temporarily removing internet exposure** until patched. ([Microsoft Security Response Center][3], [Microsoft][1])

### 3) Rotate Keys and Restart IIS

* **Rotate ASP.NET machine keys** across the farm, then **iisreset** on all SharePoint servers. Repeat after patch if AMSI wasn’t enabled earlier. ([Microsoft Security Response Center][3], [Microsoft][1])

### 4) Hunt for Known IOCs (paraphrased from Microsoft)

Look for suspicious **.aspx** web shells and PowerShell activity tied to SharePoint worker processes:

* **Files**: any variant of **spinstall0.aspx** (and similar names) under `…\Web Server Extensions\15/16\TEMPLATE\LAYOUTS\`.
* **Processes**: **w3wp.exe** spawning **cmd.exe** then **powershell.exe** with base64-encoded commands.
* **Network**: POSTs to **`/_layouts/15/ToolPane.aspx?DisplayMode=Edit`**, and any unusual referrer patterns such as `/_layouts/SignOut.aspx`.
  Use your SIEM/XDR to filter by server path, parent process, base64 indicators, and endpoint alerts flagged by your EDR. ([Microsoft][1], [CISA][2])

### 5) EDR/AV Detections

Microsoft documents several **Defender** detection names for this campaign. Map them to your toolset or create equivalent detections for suspicious sign-out request bodies, machine-key access attempts, and SharePoint worker anomalies. ([Microsoft Security Response Center][3])

## Rapid Hardening Checklist

* **Patch now**: Apply the latest **July 2025** comprehensive updates for your SharePoint version. ([Microsoft][1])
* **AMSI Full Mode**: Enable and verify—this blocks unauthenticated exploit attempts Microsoft observed. ([Microsoft][1])
* **Rotate keys**: Rotate **ASP.NET machine keys** and **restart IIS** across all SharePoint servers. ([Microsoft Security Response Center][3])
* **Purge malicious modules**: Before restarting IIS, remove any malicious module entries from `applicationHost.config`/`web.config`. ([CISA][2])
* **Hunt and clean**: Search for **spinstall*.aspx*\* variants and related encoded PowerShell activity; eradicate persistence. ([Microsoft][1])
* **Reduce exposure**: If AMSI can’t be enabled immediately, **take public-facing servers off the internet** until fully remediated. ([Microsoft Security Response Center][3])

## Why This Matters

This is a **multi-stage, repeat-exploited** attack path against collaboration infrastructure that often straddles crown-jewel data. Even after patching, **stolen machine keys** can enable ongoing impersonation if not rotated—so treat **key rotation** as non-negotiable alongside updates. ([Microsoft Security Response Center][3], [Microsoft][1])

## Role of Cert-X-Gen (How we help)

Our approach for clients running on-prem SharePoint:

* **Behavioral fingerprinting** of ToolShell-like requests and post-exploitation patterns.
* **Automated hygiene checks**: patch level, AMSI mode, and key-rotation drift.
* **IOC sweeps** for suspicious LAYOUTS-path files and **w3wp.exe → cmd → powershell** chains.
* **Ransomware path disruption**: alerting on tampering with Defender, LSASS access, and lateral-movement tooling.

This is **defensive validation**—no exploit traffic—built to confirm you’re safe without adding risk.

## Timeline

* **July 19, 2025** — MSRC publishes customer guidance; confirms **on-prem only** impact. ([Microsoft Security Response Center][3])
* **July 22–23, 2025** — Microsoft threat intel blog details ToolShell activity, actors, IOCs, and mitigations. ([Microsoft][1])
* **July 24–Aug 6, 2025** — CISA updates alert repeatedly, adds MAR and KEV entries, highlights ransomware cases, and prescribes hunting guidance. ([CISA][2])

## References

* **MSRC:** Customer guidance for SharePoint vulnerability **CVE-2025-53770/53771**. ([Microsoft Security Response Center][3])
* **Microsoft Security Blog:** Disrupting active exploitation of on-premises SharePoint vulnerabilities. ([Microsoft][1])
* **CISA Alert:** Guidance and MAR on ToolShell exploitation. ([CISA][2])
* **NVD:** **CVE-2025-53770** details (RCE; exploit exists in the wild). ([NVD][4])
* **Unit 42 Analysis:** Overview of the ToolShell chain and impact. ([Unit 42][5])

---

*Need help verifying your farm is clean and correctly hardened? Bugb can run a safe, read-only validation pass and deliver a fix list tailored to your environment.*

* [IT Pro](https://www.itpro.com/security/microsofts-new-sharepoint-vulnerability-everything-you-need-to-know?utm_source=chatgpt.com)
* [The Times of India](https://timesofindia.indiatimes.com/technology/tech-news/microsoft-sharepoint-zero-day-breach-hits-75-servers-heres-what-the-company-said/articleshow/122805393.cms?utm_source=chatgpt.com)
* [windowscentral.com](https://www.windowscentral.com/microsoft/microsofts-cybersecurity-crackdown-is-here-a-response-to-beijing-linked-breaches?utm_source=chatgpt.com)

[1]: https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/ "Disrupting active exploitation of on-premises SharePoint vulnerabilities | Microsoft Security Blog"
[2]: https://www.cisa.gov/news-events/alerts/2025/07/20/update-microsoft-releases-guidance-exploitation-sharepoint-vulnerabilities "UPDATE: Microsoft Releases Guidance on Exploitation of SharePoint Vulnerabilities | CISA"
[3]: https://nvd.nist.gov/vuln/detail/CVE-2025-53770?utm_source=chatgpt.com "CVE-2025-53770 Detail - NVD"
[4]: https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/?utm_source=chatgpt.com "Active Exploitation of Microsoft SharePoint Vulnerabilities"
