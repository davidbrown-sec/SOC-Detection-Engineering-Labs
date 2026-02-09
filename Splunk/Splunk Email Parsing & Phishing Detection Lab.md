# 📧 Splunk Email Parsing & Phishing Detection Lab

> **Objective:** Build a SOC-style email ingestion, normalization, and phishing detection pipeline in Splunk by correctly ingesting full `.eml` files (headers + HTML body) as single events, extracting key fields, and creating detection-ready searches, alerts, and dashboards.

---

## 🧠 Why This Lab Matters
Email telemetry is one of the most critical data sources in a SOC, yet it is often **poorly parsed** or **fragmented**. In this lab, I deliberately addressed a common real-world problem — **Splunk splitting email headers and HTML bodies into separate events** — and engineered a clean, detection-ready solution.

This project demonstrates:
- Deep understanding of **Splunk event breaking & parsing**
- Practical SOC troubleshooting and validation workflows
- Email security fundamentals (phishing, campaign analysis)
- Production-minded ingestion design (no duplicate data, clean re-ingest)

---

## 🏗️ Architecture Overview

**Data Flow:**
```
.eml files → Splunk Monitor Input → props.conf Parsing → Field Extraction → Detection Searches → Alerts / Dashboards
```

📸 **Screenshot Placeholder – Architecture Diagram**
> _Insert diagram showing `.eml` files flowing into Splunk and being parsed into searchable events._

---

## 📥 Data Ingestion

- Source: Raw `.eml` email files
- Ingestion Method: `Files & Directories` monitor input
- Sourcetype: `email:eml`
- Index: `mail_v2`

Each email is ingested as **one complete event**, including:
- Full RFC 5322 headers
- MIME boundaries
- HTML body content

📸 **Screenshot Placeholder – Splunk Data Input Configuration**
> _Show the Files & Directories input pointing to the email folder._

---

## 🔧 Parsing & Event Normalization

### Problem Encountered
Initially, Splunk was:
- Splitting headers and HTML bodies into separate events
- Breaking events on blank lines and MIME boundaries

This made detection logic unreliable and SOC analysis difficult.

### Solution Implemented
A custom `props.conf` configuration was created to:
- Treat each `.eml` file as **one event**
- Prevent truncation of large HTML bodies
- Enable reliable header field extraction

📄 **Key Parsing Configuration (props.conf)**
```conf
[email:eml]
SHOULD_LINEMERGE = true
LINE_BREAKER = ([\r\n]+)\Z
TRUNCATE = 0
MAX_EVENTS = 1

EXTRACT-email_subject = (?i)(?:\r?\n|^)Subject:\s*(?<subject>[^\r\n]+)
EXTRACT-email_from = (?i)(?:\r?\n|^)From:\s*(?<email_from>[^\r\n]+)
EXTRACT-email_to = (?i)(?:\r?\n|^)To:\s*(?<email_to>[^\r\n]+)
EXTRACT-message_id = (?i)(?:\r?\n|^)Message-ID:\s*(?<message_id>[^\r\n]+)
EXTRACT-email_date = (?i)(?:\r?\n|^)Date:\s*(?<email_date>[^\r\n]+)
```

📸 **Screenshot Placeholder – props.conf Configuration**
> _Show the props.conf file highlighting LINE_BREAKER and field extractions._

---

## 🔁 Clean Re-Ingestion Strategy (No Duplicates)

To apply the new parsing logic **without duplicating data**:

- Original emails were preserved in the original index
- A new index (`mail_v2`) was created
- Emails were re-ingested from a renamed folder

This approach mirrors **production-safe reprocessing workflows** used in SOC environments.

📸 **Screenshot Placeholder – Index Configuration**
> _Show the creation of the new index in Splunk._

---

## 🔍 Validation & Quality Checks

### Confirm One Event per Email
```spl
index=mail_v2 sourcetype=email:eml
| stats min(len(_raw)) max(len(_raw)) avg(len(_raw))
```

### Confirm Field Extraction
```spl
index=mail_v2 sourcetype=email:eml
| table subject email_from email_to message_id email_date
```

📸 **Screenshot Placeholder – Single Event with Full Headers + HTML**
> _Show one event containing headers and HTML body together._

📸 **Screenshot Placeholder – Extracted Email Fields**
> _Show the table view with populated subject/from/to fields._

---

## 🚨 Detection Use Cases

### 1️⃣ Repeated Subject Phishing Campaign Detection
```spl
index=mail_v2 sourcetype=email:eml
| stats count by subject
| where count > 3
```

📸 **Screenshot Placeholder – Repeated Subject Detection Results**

---

### 2️⃣ URL Extraction from HTML Body
```spl
index=mail_v2 sourcetype=email:eml
| rex field=_raw "(?i)href=\"(?<url>https?://[^\"]+)\""
```

📸 **Screenshot Placeholder – Extracted URLs from Email Body**

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|------------|---------------|-------------|
| T1566.001 | Spearphishing Attachment | Malicious email attachments |
| T1566.002 | Spearphishing Link | Malicious links embedded in emails |

---

## 📊 Dashboards & Alerting (Planned)

- 📊 Phishing Campaign Volume Over Time
- 📊 Top Sender Domains
- 📊 Repeated Subject Heatmap
- 🚨 Scheduled alerts for campaign thresholds

📸 **Screenshot Placeholder – Phishing Dashboard Overview**

---

## 🧠 SOC Skills Demonstrated

- Splunk ingestion & parsing troubleshooting
- Email protocol & MIME structure understanding
- Field extraction with regex
- Detection engineering fundamentals
- Clean lab documentation and validation

---

## 🚀 Future Enhancements

- DMARC / SPF / DKIM parsing
- IOC enrichment (VirusTotal, Talos)
- Jira Service Management alert integration
- Risk-based alerting
- Case management workflow simulation

---

## 📌 Final Notes
This lab intentionally focuses on **getting the data right first** — a foundational SOC skill. Reliable detections, alerts, and investigations only work when ingestion and parsing are engineered correctly.

---

📬 *Built as part of a hands-on SOC and blue-team learning path using Splunk.*

