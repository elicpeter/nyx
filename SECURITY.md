# Security Policy

## Supported Versions

| Version | Supported | Notes                |
|---------|-----------|----------------------|
| 0.2.x   | ✅        | Latest stable line   |
| 0.1.x   | ✅        | Critical fixes only  |
| < 0.1   | ❌        | End-of-life          |

We follow [Semantic Versioning] as soon as we hit **1.0.0**.  
Before that, breaking changes may land in any minor release.

## Reporting a Vulnerability

* **Private disclosure first.**  
  Please **do not** open public GitHub issues for security bugs.

* **How to report**  
  1. To report a vulnerability, please use the GitHub disclosure in the security tab to alert us to a security issue.

* **What to include**  
  – A minimal PoC or reproduction steps  
  – Affected Nyx version (`nyx --version`) and OS  
  – Impact explanation (e.g. RCE, DoS, data leak)

* **Response timeline**  
  We acknowledge within **3 business days** and give a status update every **7 days** thereafter until resolution.

## Disclosure Process

1. We confirm the issue and assign a CVE (via GitHub or MITRE).  
2. A fix is developed on a private branch and back-ported if needed.  
3. Coordinated release: new version on crates.io + public advisory.  
4. Credit is given to the reporter unless they request anonymity.

## Scope & Severity

This policy covers vulnerabilities that let an **untrusted Nyx input** cause:

* Remote or local code execution in the Nyx process
* Privilege escalation, data exfiltration, or denial of service

**False positives / missed detections** in scan results are *quality issues*, not security issues—please file normal GitHub issues for those.

[Semantic Versioning]: https://semver.org
