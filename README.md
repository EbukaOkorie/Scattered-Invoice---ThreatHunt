# Incident Response Report: Log(N) Pacific — Scattered Invoice (Hunt 02)

---

**Prepared By:** Chukwuebuka Okorie, Information Security Analyst

**Organisation:** Log(N) Pacific CyberRange

**Date of Report:** April 2026

**Investigation Window:** 2026-02-25 21:00 UTC — 2026-02-25 23:00 UTC

**Platform:** Microsoft Sentinel (KQL) | Workspace: law-cyber-range | Tables: SigninLogs, EmailEvents, CloudAppEvents

**Scenario:** Business Email Compromise (BEC) — £24,500 fraudulent wire transfer

**Threat Actor Profile:** Scattered Spider TTPs

---

Disclaimer: _This report is based on a simulated breach investigation conducted on the Log(N) Pacific CyberRange. All telemetry is from a controlled intrusion simulation._

---

<img width="856" height="228" alt="image" src="https://github.com/user-attachments/assets/c2b86fb2-ebbb-4a32-8fa4-4b9b7eec591e" />


## Executive Summary

On 25 February 2026, a threat actor compromised Mark Smith's Microsoft 365 account through MFA fatigue, using credentials likely purchased from infostealer marketplaces. Within 30 minutes, the attacker read Mark's emails, created two hidden inbox rules to forward financial emails and delete security alerts, sent a fraudulent invoice email to Finance requesting a £24,500 wire transfer to updated banking details, and browsed files on OneDrive and SharePoint. The entire attack ran through a single session from a Dutch IP.

**Business Impact:** If the wire transfer was processed, direct financial loss of £24,500. Additional exposure includes potential UK GDPR notification obligations if personal data in OneDrive/SharePoint was accessed, credential reset costs across the organisation, and reputational damage. No Conditional Access policies were in place to prevent the sign-in, which is the single biggest defence gap identified.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 21:54:24 | First MFA fatigue attempt (ResultType 50074) |
| 21:54:55 | Second MFA denial (ResultType 50140) |
| 21:55:15 | Third MFA denial (ResultType 50140) |
| 21:59:52 | MFA approved, attacker signs in to One Outlook Web |
| ~22:00 | MailItemsAccessed, attacker reads Mark's emails |
| 22:02 | Forward rule (`.`) created, sends invoice emails to insights@duck.com |
| 22:03 | Delete rule (`..`) created, auto-deletes security alerts |
| ~22:09 | Attacker accesses SharePoint and OneDrive files |
| ~22:24 | BEC email sent to j.reynolds with fraudulent invoice |

---

## Indicators of Compromise

| IOC Type | Value | Context |
|---|---|---|
| IP Address | `205.147.16.190` | Attacker source IP (Netherlands) |
| Email Address | `insights@duck.com` | Inbox rule forwarding destination |
| Email Address | `jwilson.vhr@proton.me` | *(not observed in this hunt, included from threat intel on Scattered Spider)* |
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` | Attacker session GUID across all activity |
| User Agent | `Firefox 147.0 / Linux` | Attacker browser and OS |
| Email Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` | BEC email subject line |
| Inbox Rule | `.` (single dot) | Forward rule name |
| Inbox Rule | `..` (double dot) | Delete rule name |

---

## Background

This is Hunt 02, following the EmberForge Source Leak investigation. This time, the scenario is a Business Email Compromise. The IR Lead reported that an employee, Mark Smith, flagged repeated MFA push notifications he didn't initiate and inbox rules he didn't create. Finance also received an email from Mark's account with updated banking details for an invoice payment of £24,500. The IR Lead wanted me to work through the sign-in logs, email events, and cloud app activity to reconstruct what happened.

The investigation was scoped to a 2-hour window across three tables: SigninLogs, EmailEvents, and CloudAppEvents.

---

## Flag-by-Flag Walkthrough

---

### Q00 — Workspace Name
**Flag:** `law-cyber-range`

This came straight from the Sentinel UI. The workspace for all the hunt exercises on the Log(N) Pacific CyberRange.

---

### Q01 — Compromised Account
**Flag:** `m.smith@lognpacific.org`

I started by filtering SigninLogs for activity related to the reported user, Mark Smith. His UPN showed up immediately.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where UserPrincipalName has "smith"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType
```

<img width="924" height="246" alt="image" src="https://github.com/user-attachments/assets/de938a27-926e-4a45-836c-d45895164b7c" />

---

### Q02 — Attacker Source IP
**Flag:** `205.147.16.190`

Filtering Mark's sign-in activity, I spotted an unfamiliar IP appearing at 21:54 with MFA failures followed by a successful authentication. This IP did not match any of Mark's normal sign-in patterns.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, IPAddress, ResultType, Location
| sort by TimeGenerated asc
```

<img width="922" height="282" alt="image" src="https://github.com/user-attachments/assets/00b60500-74b0-47dd-a66d-f1ac61b375b3" />

---

### Q03 — Attack Origin Country
**Flag:** `NL`

The Location field on the attacker's sign-in entries showed the Netherlands. A Dutch IP authenticating to a UK organisation's mailbox during an MFA fatigue attack is a strong indicator of compromise.

---

### Q04 — MFA Denial Error Code
**Flag:** `50074`

This is the Azure AD error code for "Strong authentication required." It means the user's credentials were correct but MFA was not completed. The attacker had Mark's password but was being blocked by MFA, which is exactly what you would expect before an MFA fatigue attack.

---

### Q05 — MFA Fatigue Intensity
**Flag:** `3`

I counted 3 failed MFA attempts (ResultType 50074 and 50140) from the attacker's IP before the first successful sign-in. MFA fatigue works by spamming the user with push notifications until they get frustrated and just approve one. Three attempts is not a lot, which could mean Mark approved quickly or the attacker got lucky.

---

### Q06 — Application Accessed
**Flag:** `One Outlook Web`

The first successful authentication from the attacker's IP was to One Outlook Web. This is the AppDisplayName value from SigninLogs. The attacker went straight for the mailbox, which makes sense for a BEC attack where the goal is to intercept invoice communications.

---

### Q07 — Attacker OS
**Flag:** `Linux`

I pulled this from the DeviceDetail.operatingSystem field in SigninLogs. The attacker was using a Linux machine, which is consistent with Scattered Spider's known tooling. Most corporate users at a law firm would be on Windows or macOS, so a Linux sign-in is another red flag.

---

### Q08 — Attacker Browser
**Flag:** `Firefox 147.0`

From DeviceDetail.browser on the attacker's sessions. Combined with Linux, this paints a picture of the attacker's setup.

---

### Q09 — First Post-Auth Action
**Flag:** `MailItemsAccessed`

Moving to CloudAppEvents, I filtered for the attacker's IP after the successful sign-in and sorted by time. The first action was MailItemsAccessed, meaning the attacker immediately started reading Mark's emails. This is the reconnaissance phase of the BEC, where they look for ongoing invoice threads to hijack.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, ActionType, Application
| sort by TimeGenerated asc
```

---

### Q10 — Rule Creation Method
**Flag:** `New-InboxRule`

The attacker created inbox rules at 22:02 and 22:03. The ActionType in CloudAppEvents was New-InboxRule. Inbox rules are a favourite persistence and evasion technique for BEC attackers because they can silently redirect or delete emails without the victim noticing.

---

### Q11 — Forward Rule Name
**Flag:** `.`

The first rule was named with just a single dot. This is nearly invisible in the inbox rules list. Most people scrolling through their rules would not even notice it. Very deliberate.

---

### Q12 — Forward Destination
**Flag:** `insights@duck.com`

I found this in the ForwardTo parameter within the RawEventData JSON on the inbox rule creation event. The attacker was forwarding copies of emails to a DuckDuckGo email alias, which provides privacy and makes the recipient harder to trace.

---

### Q13 — Forward Keywords
**Flag:** `invoice, payment, wire, transfer`

The SubjectOrBodyContainsWords parameter in the rule's RawEventData showed exactly what the attacker was after. The rule only forwarded emails containing these financial keywords. This confirms the intent was invoice fraud from the start.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend RawData = parse_json(RawEventData)
| project TimeGenerated, ActionType, RawData
```

<img width="914" height="188" alt="image" src="https://github.com/user-attachments/assets/ee131f66-9a7e-42bb-b7b6-d7d590f4c4cb" />

---

### Q14 — Rule Processing Flag
**Flag:** `StopProcessingRules`

This parameter was set on the attacker's forwarding rule. What it does is tell Exchange to stop evaluating any other inbox rules after this one fires. So if the victim had their own rules that might have caught or flagged the forwarded emails, those rules would never run. Another layer of evasion.

<img width="922" height="448" alt="image" src="https://github.com/user-attachments/assets/c5a3873b-2996-4c8c-907d-d85c49c8db14" />

---

### Q15 — Delete Rule Name
**Flag:** `..`

The second rule was named with two dots. If the first rule (single dot) was hard to spot, this one is even sneakier sitting right next to it. This rule was designed to automatically delete security-related notifications.

---

### Q16 — Delete Keywords
**Flag:** `suspicious, security, phishing, unusual, compromised, verify`

These are the keywords the delete rule was targeting. Any email containing these words would be automatically deleted from Mark's inbox. The purpose is obvious: if the security team or Microsoft sends Mark a warning about suspicious activity on his account, he would never see it. The attacker was covering their tracks in real time.

---

### Q17 — BEC Target
**Flag:** `j.reynolds@lognpacific.org`

Moving to EmailEvents, I filtered for emails sent from the attacker's IP during the investigation window. The recipient was j.reynolds, who based on the scenario context works in Finance. The attacker specifically targeted someone with the authority to process wire transfers.

```kql
EmailEvents
| where SenderIPv4 == "205.147.16.190"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```

<img width="923" height="214" alt="image" src="https://github.com/user-attachments/assets/c43ea386-fe77-4b56-9e22-fc61ac4797ca" />

---

### Q18 — BEC Subject Line
**Flag:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`

The subject line starts with "RE:" which means the attacker was replying to an existing invoice thread. This is a thread hijack. By replying within a legitimate conversation, the email looks completely normal to the recipient. J. Reynolds would see what appears to be Mark following up on a real invoice, not a fraudulent message from an attacker.

---

### Q19 — Email Direction
**Flag:** `Intra-org`

This is a critical finding. The email was classified as internal (intra-org) because it was sent from Mark's compromised account to another internal user. This means any email gateway rules designed to catch external phishing or BEC would not have flagged it. The attacker was operating from inside the trust boundary.

<img width="925" height="265" alt="image" src="https://github.com/user-attachments/assets/5763a5a4-e9f7-403d-b2bc-82af193196dd" />

---

### Q20 — BEC Sender IP
**Flag:** `205.147.16.190`

The SenderIPv4 on the BEC email matched the attacker's sign-in IP exactly. This confirms the fraudulent email was sent from the same session the attacker established through MFA fatigue. One session, one attacker, full chain from initial access to the BEC.

---

### Q21 — Cloud App Accessed
**Flag:** `Microsoft OneDrive for Business`

The attacker did not stop at email. I found FileAccessed events in CloudAppEvents from the attacker's IP. The Application field showed Microsoft OneDrive for Business. The attacker was browsing Mark's files, possibly looking for more financial information, contracts, or other data they could use.

---

### Q22 — SharePoint App Accessed
**Flag:** `Microsoft SharePoint Online`

This one caught me out initially. I tried several values from SigninLogs (Office 365 SharePoint Online, SharePoint Online Web Client Extensibility, OfficeHome) and they were all wrong. The answer was in the Application field in CloudAppEvents, which logs it as "Microsoft SharePoint Online" rather than the SigninLogs AppDisplayName of "Office 365 SharePoint Online." Lesson learned: always check which table the question is pointing to, because the same service can have different display names across tables.

---

### Q23 — Session Correlation
**Flag:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

This GUID ties the entire investigation together. I found it by parsing the RawEventData on the inbox rule creation events in CloudAppEvents and extracting AppAccessContext.AADSessionId. I then confirmed it matched the SessionId on the attacker's successful sign-in in SigninLogs. One session ID linking sign-ins, inbox rule creation, email access, and file browsing.

```kql
CloudAppEvents
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend RawData = parse_json(RawEventData)
| extend AADSessionId = tostring(RawData.AppAccessContext.AADSessionId)
| project TimeGenerated, ActionType, AADSessionId
```

---

### Q24 — Conditional Access Status
**Flag:** `notApplied`

The IR Lead asked what failed in the defences. The ConditionalAccessStatus on the attacker's successful sign-in was "notApplied," meaning no Conditional Access policies evaluated or blocked the sign-in. A policy requiring managed devices or blocking risky locations (like a Dutch IP signing into a UK org) would have stopped this attack at the door. This is the single biggest defence gap in this incident.

---

### Q25 — MFA Fatigue MITRE ID
**Flag:** `T1621`

This maps to MITRE ATT&CK T1621: Multi-Factor Authentication Request Generation. The technique describes exactly what happened here: the attacker repeatedly triggered MFA push notifications to wear down the user until they approved one.

---

### Q26 — Email Rules MITRE ID
**Flag:** `T1564.008`

This maps to T1564.008: Hide Artifacts — Email Hiding Rules. The attacker created inbox rules specifically to hide evidence of the compromise by forwarding financial emails out and deleting security alerts. This falls under Defence Evasion in the ATT&CK framework.

---

### Q27 — Credential Source
**Flag:** `infostealer`

The IR Lead asked how the attacker already had Mark's password before the MFA fatigue started. Scattered Spider is well known for purchasing credentials harvested by infostealer malware. Tools like Raccoon, RedLine, and Vidar steal saved passwords, session tokens, and browser data from infected machines, and the logs are sold on dark web marketplaces. The attacker likely bought Mark's credentials from one of these sources.

---

### Q28 — Immediate Containment
**Flag:** `revoke sessions`

The IR Lead wanted to know the single most important containment action. The attacker still had a valid session and the inbox rules were still active. Revoking sessions invalidates all active tokens immediately, kicking the attacker out. A password reset alone would not kill existing session tokens, so revoking sessions had to come first.

---

### Q29 — Threat Actor Attribution
**Flag:** `Scattered Spider`

Everything in this investigation points to Scattered Spider. MFA fatigue as the initial access method, purchasing credentials from infostealer logs, inbox rule manipulation for persistence and evasion, BEC targeting finance, and the use of anonymising infrastructure. This is the same group that targeted MGM Resorts and Caesars Entertainment using very similar TTPs.

---

## MITRE ATT&CK Mapping

| Attack Phase | Technique | ID | What Happened | Detection Gap |
|---|---|---|---|---|
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | Attacker used Mark's stolen credentials to authenticate | No alerting on sign-ins from anomalous locations or devices |
| Initial Access | MFA Request Generation | T1621 | 3 MFA push spam attempts before user approved | No detection for repeated MFA denials followed by approval |
| Persistence | Email Forwarding Rule | T1114.003 | Forward rule (`.`) sending invoice-related emails to external address | No alerting on new inbox rules with external forwarding |
| Defence Evasion | Email Hiding Rules | T1564.008 | Delete rule (`..`) removing security alert emails automatically | No alerting on rules that delete emails matching security keywords |
| Collection | Email Collection: Remote Email Collection | T1114.002 | MailItemsAccessed events from attacker IP across the session | No alerting on mailbox access from new/unusual IPs |
| Lateral Movement | Internal Spearphishing | T1534 | BEC email sent internally from compromised account to Finance | Intra-org email bypassed external gateway controls entirely |
| Collection | Data from Cloud Storage | T1530 | Attacker accessed OneDrive and SharePoint files | No alerting on file access from suspicious session context |
| Resource Development | Obtain Credentials: Purchase | T1589.001 | Credentials likely purchased from infostealer marketplace | Outside org's detection scope, but password hygiene and monitoring for leaked creds could help |

---

## Incident Response Playbooks

---

### Playbook 1: MFA Fatigue / Push Spam

**Triggers:** Multiple MFA denial error codes (50074, 50140) from the same IP in quick succession, followed by a successful authentication. User reports of unexpected MFA notifications.

**Response Steps:**
- Revoke all active sessions for the affected account immediately.
- Reset the user's password and re-register MFA.
- Block the source IP at the Conditional Access level.
- Review all activity from the successful session (inbox rules, email sends, file access).
- Contact the user to confirm they did not intentionally approve the MFA prompt.
- Check if the user's credentials appear in known infostealer dumps.

---

### Playbook 2: Malicious Inbox Rule Creation

**Triggers:** New-InboxRule events with external forwarding addresses. Rules with single-character or suspicious names. Rules containing StopProcessingRules. Rules targeting security-related keywords for deletion.

**Response Steps:**
- Remove all attacker-created inbox rules immediately.
- Audit the forwarding destination and determine what emails were exfiltrated.
- Check for any emails the delete rule may have already removed (recoverable items folder).
- Review all inbox rules across the organisation for similar patterns, as the attacker may have compromised other accounts.
- Block the external forwarding domain at the mail transport level.

---

### Playbook 3: Business Email Compromise (Intra-org)

**Triggers:** Emails with financial keywords (invoice, payment, wire, transfer) sent from an account showing other compromise indicators. Emails referencing updated banking details. Internal emails sent from IPs that do not match the user's normal sign-in pattern.

**Response Steps:**
- Contact the recipient (Finance) immediately to halt any pending payments.
- Quarantine the fraudulent email.
- Notify the bank if a transfer has already been initiated, as there is sometimes a recall window.
- Preserve the email headers and metadata for legal and law enforcement purposes.
- Issue an internal advisory so Finance staff know to verify banking detail changes through a separate channel (phone call, in-person).

---

## Recommendations

**Immediate:**
- Revoke all sessions for m.smith@lognpacific.org.
- Reset Mark Smith's password and re-register MFA (preferably number matching or FIDO2 instead of push notifications).
- Remove both inbox rules (`.` and `..`).
- Block the forwarding destination (insights@duck.com) at the transport rule level.
- Contact j.reynolds and Finance to confirm no payment was processed for the fraudulent invoice.
- Block IP 205.147.16.190.

**Short-Term:**
- Implement Conditional Access policies requiring managed/compliant devices and blocking sign-ins from high-risk locations.
- Enable number matching for MFA to eliminate push fatigue as an attack vector entirely.
- Create Sentinel analytics rules for: repeated MFA failures followed by success, inbox rule creation with external forwarding, inbox rules with StopProcessingRules or security keyword deletion.
- Audit all mailboxes for similar inbox rule patterns.
- Check Mark's credentials against known breach databases and infostealer logs.

**Long-Term:**
- Move to phishing-resistant MFA (FIDO2 security keys or Windows Hello for Business) across the organisation.
- Implement mail flow rules that flag or block auto-forwarding to external domains.
- Deploy Microsoft Defender for Office 365 with BEC detection capabilities.
- Establish a verification procedure for any banking detail changes on invoices (out-of-band confirmation via phone).
- Run regular tabletop exercises simulating BEC scenarios with Finance staff.
- Subscribe to threat intelligence feeds that monitor for employee credentials appearing in infostealer marketplaces.

---

## Detection Rules

These are Sentinel scheduled query rules I would deploy based on what I found in this investigation.

**MFA Fatigue Detection:**
```kql
SigninLogs
| where TimeGenerated > ago(15m)
| where ResultType in ("50074", "50140")
| summarize FailCount = count(), FailTimes = make_list(TimeGenerated) by UserPrincipalName, IPAddress
| where FailCount >= 3
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | where TimeGenerated > ago(15m)
) on UserPrincipalName, IPAddress
| project UserPrincipalName, IPAddress, FailCount, SuccessTime = TimeGenerated1
```

**Suspicious Inbox Rule Creation:**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| extend RawData = parse_json(RawEventData)
| extend RuleName = tostring(RawData.Parameters[0].Value)
| extend ForwardTo = tostring(RawData.Parameters[3].Value)
| where ForwardTo != "" or RuleName matches regex @"^\.{1,3}$"
| project TimeGenerated, AccountDisplayName, RuleName, ForwardTo, IPAddress
```

**Intra-org BEC Pattern:**
```kql
EmailEvents
| where EmailDirection == "Intra-org"
| where Subject has_any ("invoice", "wire", "payment", "banking details")
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | where Location != "GB"
) on $left.SenderIPv4 == $right.IPAddress
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, SenderIPv4, Location
```

---

## Lessons Learned

**What worked:** Sysmon-equivalent telemetry forwarded to Sentinel gave us full visibility after the fact. The three-table structure (SigninLogs, EmailEvents, CloudAppEvents) allowed complete attack chain reconstruction. Session correlation via AADSessionId proved the entire attack was one continuous session.

**What I would do differently:** In a real scenario, I would have checked for Conditional Access policy gaps before the incident, not after. The "notApplied" status on Q24 should never happen for a production environment. I also learned the hard way on Q22 that "application name as logged" can differ between tables for the same service. In future hunts, I will always check which table a question is pointing to before submitting.

**What the organisation should do differently:** The absence of Conditional Access policies and the reliance on basic MFA push notifications were the two enablers of this entire attack. Number matching or FIDO2 would have neutralised the MFA fatigue. A Conditional Access policy blocking unmanaged devices or foreign IPs would have stopped the sign-in entirely. Neither of these requires significant budget, just configuration.

---

## Summary

This was a clean, focused BEC attack. The attacker had Mark Smith's credentials (likely from an infostealer), spammed him with MFA push notifications until he approved, then moved quickly through the mailbox. Within about 30 minutes they had set up forwarding rules, deleted security alerts, sent a fraudulent invoice email to Finance, and browsed files on OneDrive and SharePoint. The entire attack ran through a single session from a Dutch IP on a Linux machine with Firefox.

The biggest defence failures were the lack of Conditional Access policies (which would have blocked the sign-in entirely) and the absence of real-time alerting on inbox rule creation or MFA fatigue patterns. The first containment priority was revoking sessions to kill the attacker's access immediately.

---

## Flag Summary

| # | Question | Flag |
|---|----------|------|
| Q00 | Workspace name | `law-cyber-range` |
| Q01 | Compromised account | `m.smith@lognpacific.org` |
| Q02 | Attacker source IP | `205.147.16.190` |
| Q03 | Attack origin country | `NL` |
| Q04 | MFA denial error code | `50074` |
| Q05 | MFA fatigue intensity | `3` |
| Q06 | Application accessed | `One Outlook Web` |
| Q07 | Attacker OS | `Linux` |
| Q08 | Attacker browser | `Firefox 147.0` |
| Q09 | First post-auth action | `MailItemsAccessed` |
| Q10 | Rule creation method | `New-InboxRule` |
| Q11 | Forward rule name | `.` |
| Q12 | Forward destination | `insights@duck.com` |
| Q13 | Forward keywords | `invoice, payment, wire, transfer` |
| Q14 | Rule processing flag | `StopProcessingRules` |
| Q15 | Delete rule name | `..` |
| Q16 | Delete keywords | `suspicious, security, phishing, unusual, compromised, verify` |
| Q17 | BEC target | `j.reynolds@lognpacific.org` |
| Q18 | BEC subject line | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Q19 | Email direction | `Intra-org` |
| Q20 | BEC sender IP | `205.147.16.190` |
| Q21 | Cloud app accessed | `Microsoft OneDrive for Business` |
| Q22 | SharePoint app accessed | `Microsoft SharePoint Online` |
| Q23 | Session correlation | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| Q24 | Conditional Access status | `notApplied` |
| Q25 | MFA fatigue MITRE ID | `T1621` |
| Q26 | Email rules MITRE ID | `T1564.008` |
| Q27 | Credential source | `infostealer` |
| Q28 | Immediate containment | `revoke sessions` |
| Q29 | Threat actor attribution | `Scattered Spider` |

---

*End of Report — Prepared by Chukwuebuka Okorie, Log(N) Pacific CyberRange*
