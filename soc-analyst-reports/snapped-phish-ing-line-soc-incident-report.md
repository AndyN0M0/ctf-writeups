# SOC Incident Investigation Report

## Microsoft 365 Credential Phishing Campaign

### Incident Classification

**Incident Type:** Credential Phishing  
**Attack Category:** Phishing / Credential Harvesting / Malicious Phishing Kit  
**Impersonated Organization:** Microsoft / Microsoft 365  
**Severity:** High  
**Status:** Confirmed  
**Investigation Environment:** TryHackMe controlled laboratory environment

---

# 1. Executive Summary

An investigation was conducted into a suspected phishing campaign targeting users of SwiftSpend Finance.

The campaign used emails impersonating a financial/accounts-payable function and delivered malicious HTML or PDF attachments. The attachments redirected victims to infrastructure hosted under the domain `kennaroads[.]buzz`.

The phishing infrastructure impersonated Microsoft 365 and presented victims with a fraudulent login page designed to capture email addresses and passwords.

Analysis of the phishing kit confirmed that submitted credentials were processed by a PHP script named `submit.php`. The script collected credentials together with additional victim information including IP address, User-Agent, country and timestamp.

The captured information was configured to be sent to:

`m3npat[@]yandex[.]com`

Analysis of the exposed credential log identified:

`michael.ascot@swiftspend.finance`

as a user who submitted credentials more than once.

The investigation also identified a second phishing delivery mechanism using a PDF document containing Microsoft/OneDrive branding and a direct URI annotation pointing to the same phishing infrastructure.

Based on the available evidence, the activity is assessed with high confidence as a credential phishing campaign using a reusable phishing kit and shared backend infrastructure.

---

# 2. Incident Overview

The investigation began with several suspicious emails containing financial-themed lures.

Four messages used a "Direct Credit Advice" theme and included an HTML attachment.

A fifth message used a "Quote for Services Rendered" theme and included a PDF attachment.

Although the delivery mechanisms differed, both attachment types ultimately referenced the same phishing infrastructure.

This correlation indicates that the messages were likely components of the same broader phishing operation.

---

# 3. Initial Indicators

The following characteristics immediately increased the suspicion level:

- Financial-themed unsolicited emails
- HTML attachment presented as a financial document
- Sender/Return-Path domain inconsistency
- Missing or inconsistent email authentication
- External redirect to an unrelated domain
- Microsoft/Office 365-themed URL path
- Recipient email address embedded in the URL
- Fake Microsoft login interface
- Credential harvesting PHP backend
- Exposed credential logs

---

# 4. Email Header Investigation

The first group of messages displayed a visible sender associated with:

`groupmarketingonline[.]icu`

The Return-Path referenced:

`braemarhowells[.]com`

This discrepancy was considered suspicious but not independently conclusive.

Header authentication results showed inconsistent SPF/DKIM/DMARC information.

The investigation therefore treated the authentication results as contextual evidence rather than a standalone verdict.

The Return-Path domain resolved to:

`191.223.127.111`

The IP was associated with:

`Dingfeng Xinhui Hongkong Technology Limited`

No attribution to the organization was made based solely on the IP ownership information.

---

# 5. Malicious Attachment Analysis

## 5.1 Direct Credit Advice.html

The HTML attachment was identified as a small ASCII HTML document.

Static inspection revealed an immediate meta-refresh redirect to:

`hxxp://kennaroads[.]buzz/data/Update365/office365/`

The URL also contained the victim's email address.

This demonstrated that the attachment functioned as a phishing redirector rather than a legitimate financial document.

---

## 5.2 VirusTotal Result

The SHA-256 hash of the attachment was:

`c6ed70c3970a9ba62ef5f54be8608913a631f53e08e4914a4036299bb5d3ddb6`

VirusTotal reported:

`0 / 62`

vendor detections.

The result was not considered evidence of benign behavior because direct static analysis demonstrated malicious redirect functionality.

---

# 6. Infrastructure Investigation

The primary phishing domain identified was:

`kennaroads[.]buzz`

DNS resolution returned:

`172.67.216.206`

The IP was associated with Cloudflare infrastructure.

The investigation did not treat this IP as the origin server because Cloudflare can operate as a reverse proxy.

HTTP investigation revealed an active web server using nginx and PHP.

The infrastructure returned multiple redirects and dynamically generated paths.

This behavior was consistent with a phishing framework rather than a static informational website.

---

# 7. Phishing Page Analysis

The phishing URL ultimately redirected to a login page containing:

- Microsoft-style branding
- Microsoft/Office 365 terminology
- Email input field
- Password input field
- JavaScript validation
- Form submission to a PHP backend

The page was therefore assessed as a Microsoft 365 credential phishing page.

The attacker was impersonating:

**Microsoft**

---

# 8. Phishing Kit Analysis

The `/data/` directory exposed:

`Update365.zip`

VirusTotal identified the archive as associated with a Trojan.

The archive contained:

**49 files**

The presence of a multi-file phishing kit indicates reusable infrastructure rather than a single-purpose malicious document.

---

# 9. Credential Harvesting Analysis

The phishing kit contained:

`submit.php`

Analysis of the PHP source code demonstrated that the application processed:

- Email address
- Password
- Client IP address
- User-Agent
- Country
- Timestamp

The code constructed a message containing the submitted information.

The destination was explicitly defined in the PHP mail function:

`m3npat[@]yandex[.]com`

This represents direct evidence of the credential collection destination.

---

# 10. Credential Exposure

The phishing infrastructure exposed a log file under:

`/data/Update365/log.txt`

Review of the log identified a user who submitted credentials more than once:

`michael.ascot@swiftspend.finance`

This demonstrates that the phishing infrastructure was not merely prepared for credential collection; evidence existed showing that credentials had actually been submitted.

---

# 11. Secondary Phishing Mechanism

A separate email contained:

`Quote.pdf`

The PDF used Microsoft Office 365 and OneDrive-themed branding.

The visible lure instructed the victim to access a document.

Static PDF analysis identified an embedded URI annotation pointing to:

`hxxps://kennaroads[.]buzz/data/Update365/office365`

This established infrastructure correlation between the PDF-based lure and the HTML-based phishing campaign.

---

# 12. Campaign Correlation

The following indicators were shared across the investigated artifacts:

| Evidence | Observation |
|---|---|
| Phishing domain | `kennaroads[.]buzz` |
| Backend path | `/data/Update365/office365/` |
| Branding | Microsoft / Office 365 |
| HTML lure | Direct Credit Advice |
| PDF lure | OneDrive document |
| Phishing kit | `Update365.zip` |
| Backend | PHP |
| Credential collection | `submit.php` |
| Credential destination | `m3npat[@]yandex[.]com` |

The shared infrastructure provides strong evidence that the messages were related.

---

# 13. Attack Timeline

## Stage 1 — Initial Delivery

Victims received phishing emails masquerading as financial/accounting communications.

## Stage 2 — Attachment Execution

HTML attachments redirected victims toward the phishing infrastructure.

## Stage 3 — Infrastructure Redirection

The web server generated additional paths and redirected victims through the phishing framework.

## Stage 4 — Credential Collection

Victims were presented with a fraudulent Microsoft 365 login page.

## Stage 5 — Credential Submission

Credentials were processed by `submit.php`.

## Stage 6 — Data Collection

The phishing kit collected:

- Email
- Password
- IP
- User-Agent
- Country
- Timestamp

## Stage 7 — Exfiltration

Captured information was configured to be sent to:

`m3npat[@]yandex[.]com`

## Stage 8 — Evidence of Victim Interaction

The exposed log showed that:

`michael.ascot@swiftspend.finance`

submitted credentials more than once.

---

# 14. Indicators of Compromise

| IOC Type | Indicator | Confidence | Relevance |
|---|---|---:|---|
| Domain | `groupmarketingonline[.]icu` | High | Phishing sender |
| Domain | `braemarhowells[.]com` | Medium | Return-Path infrastructure |
| IP | `191.223.127.111` | Medium | Return-Path infrastructure |
| Domain | `kennaroads[.]buzz` | High | Phishing infrastructure |
| URL path | `/data/Update365/office365/` | High | Phishing backend |
| Email | `m3npat[@]yandex[.]com` | High | Credential collection |
| File | `Direct Credit Advice.html` | High | Redirector |
| File | `Quote.pdf` | High | Phishing lure |
| File | `Update365.zip` | High | Phishing kit |
| File | `log.txt` | High | Credential log |
| File | `submit.php` | High | Credential harvesting |

---

# 15. Assessment

## Confidence: High

The evidence strongly supports the following conclusions:

1. The emails were part of a phishing campaign.
2. The campaign impersonated Microsoft/Office 365.
3. The HTML attachment operated as a redirector.
4. The PDF contained a link to the same phishing infrastructure.
5. The infrastructure hosted a credential harvesting page.
6. The phishing kit contained a credential collection backend.
7. Captured credentials were configured to be exfiltrated to an external email address.
8. At least one victim submitted credentials multiple times.

---

# 16. Detection Opportunities

A defensive organization could potentially detect this campaign using:

### Email Security

- Detect sender/Return-Path domain inconsistencies
- Inspect HTML attachments
- Block or quarantine unsolicited HTML attachments
- Detect Microsoft-themed links pointing to unrelated domains
- Monitor suspicious `.icu` and `.buzz` domains where appropriate

### DNS

Monitor endpoints querying:

`kennaroads[.]buzz`

### Web Proxy

Detect requests containing:

`/data/Update365/office365/`

### Endpoint Detection

Alert on:

- Browser launches from email attachments
- HTML files initiating external network connections
- Suspicious Office 365 impersonation domains

### Credential Protection

- Enforce phishing-resistant MFA
- Monitor impossible or unusual login behavior
- Investigate repeated authentication attempts
- Monitor leaked credential indicators

---

# 17. Recommended Mitigations

1. Block identified malicious domains and URLs.
2. Quarantine matching phishing emails.
3. Reset credentials for confirmed victims.
4. Revoke active authentication sessions for compromised accounts.
5. Review authentication logs for affected users.
6. Enforce MFA, preferably phishing-resistant MFA.
7. Block or restrict execution of unsolicited HTML attachments.
8. Improve email authentication and DMARC enforcement.
9. Monitor for additional infrastructure using the same phishing-kit patterns.
10. Search historical email telemetry for the identified sender and domains.

---

# 18. Evidence Limitations

Several observations were deliberately not treated as definitive attribution.

### Cloudflare IP

The resolved IP address belonged to Cloudflare infrastructure.

This does not establish the physical location or ownership of the phishing server.

### PDF Metadata

The PDF listed:

`User PC`

as the author.

This does not identify the attacker because document metadata can be automatically generated or modified.

### Email Authentication

SPF/DKIM/DMARC results were interpreted together with the visible sender and Return-Path rather than being treated as independent proof of legitimacy.

---

# 19. Final Conclusion

The investigation identified a confirmed Microsoft 365 credential phishing campaign using a reusable phishing kit.

The campaign demonstrated multiple delivery mechanisms but relied on common backend infrastructure.

The strongest technical evidence consisted of:

- Malicious HTML redirector
- Microsoft 365 impersonation page
- Shared phishing infrastructure
- Embedded PDF URI pointing to the same infrastructure
- Credential harvesting PHP code
- External credential collection address
- Exposed credential logs
- Evidence of repeated credential submission

The campaign therefore represents a significant credential theft risk.

The investigation successfully reconstructed the attack path from initial email delivery through credential collection and exfiltration.

---

# Appendix A — Key Artifacts

## HTML Attachment

`Direct Credit Advice.html`

SHA-256:

`c6ed70c3970a9ba62ef5f54be8608913a631f53e08e4914a4036299bb5d3ddb6`

## Phishing Kit

`Update365.zip`

Archive contents:

`49 files`

## Credential Harvesting Script

`submit.php`

Credential collection destination:

`m3npat[@]yandex[.]com`

## Credential Log

`log.txt`

Repeated victim:

`michael.ascot@swiftspend.finance`

## Final Flag

`THM{pL4y_w1Th_tH3_URL}`
