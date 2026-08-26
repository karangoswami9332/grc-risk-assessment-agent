# Internal GRC Control Catalog

This document is the **Internal GRC Control Catalog** for the GRC Risk Agent project.
These entries are curated project controls for RAG-grounded mapping. They are **not**
official ISO, NIST, CIS, or other framework control numbers.

Each control has a stable Control ID. Prefer retrieving one control section at a time.

---

## CTRL-AC-001 — Enforce Least Privilege Access

**Control ID:** CTRL-AC-001

**Name:** Enforce Least Privilege Access

**Objective:** Limit user and service permissions to the minimum required for the role.

**Control Type:** Preventive

**Domain:** Access Control

**Description:** Access to systems and data should follow least privilege. Unique identities receive only the rights needed for assigned duties. Standing or shared privileged rights increase unauthorized access risk.

**Example Implementation:** Role-based access control (RBAC), just-in-time elevation for admin tasks, and removal of unused entitlements during joiner/mover/leaver processes.

---

## CTRL-AC-002 — Require Multi-Factor Authentication

**Control ID:** CTRL-AC-002

**Name:** Require Multi-Factor Authentication

**Objective:** Reduce account takeover by requiring strong authentication beyond a password.

**Control Type:** Preventive

**Domain:** Access Control

**Description:** Privileged, remote, and internet-facing access to sensitive systems should require multi-factor authentication (MFA) or equivalent strong authentication.

**Example Implementation:** Enforce MFA for administrators, VPN/remote access, and cloud consoles; prefer phishing-resistant factors where available.

---

## CTRL-AC-003 — Periodic Access Review and Recertification

**Control ID:** CTRL-AC-003

**Name:** Periodic Access Review and Recertification

**Objective:** Detect and remove excessive or outdated access rights over time.

**Control Type:** Detective

**Domain:** Access Control

**Description:** Access entitlements should be reviewed on a defined schedule. Owners confirm that remaining access is still required; unused or inappropriate rights are revoked.

**Example Implementation:** Quarterly access recertification campaigns for privileged and data-sensitive roles, with tracked exceptions and remediation deadlines.

---

## CTRL-CLD-001 — Block Public Access to Cloud Storage

**Control ID:** CTRL-CLD-001

**Name:** Block Public Access to Cloud Storage

**Objective:** Prevent unauthorized public access to cloud-hosted sensitive information.

**Control Type:** Preventive

**Domain:** Cloud Security

**Description:** Cloud storage containing sensitive or confidential information should be private by default and configured to prevent anonymous or unintended public access.

**Example Implementation:** Enable provider block-public-access settings and restrict bucket/object policies to approved identities only.

---

## CTRL-CLD-002 — Review Cloud IAM Configurations

**Control ID:** CTRL-CLD-002

**Name:** Review Cloud IAM Configurations

**Objective:** Prevent overly broad cloud identity policies that enable unauthorized access.

**Control Type:** Preventive

**Domain:** Cloud Security

**Description:** Cloud IAM roles and policies should avoid wildcards and excessive privileges. Policies that grant public or organization-wide read/write to sensitive resources should be corrected promptly.

**Example Implementation:** Least-privilege IAM policies, deny-public guards, and peer review of policy changes before production apply.

---

## CTRL-CLD-003 — Scan Cloud Configurations for Misconfiguration

**Control ID:** CTRL-CLD-003

**Name:** Scan Cloud Configurations for Misconfiguration

**Objective:** Detect insecure cloud settings such as public storage or weak IAM before exploitation.

**Control Type:** Detective

**Domain:** Cloud Security

**Description:** Automated configuration scanning should identify deviations from secure baselines, including public buckets, open security groups, and risky identity bindings.

**Example Implementation:** Continuous cloud security posture management (CSPM) or provider config rules with alerts and ticketed remediation.

---

## CTRL-DAT-001 — Encrypt Sensitive Data

**Control ID:** CTRL-DAT-001

**Name:** Encrypt Sensitive Data

**Objective:** Protect confidentiality of sensitive information at rest and in transit.

**Control Type:** Preventive

**Domain:** Data Protection

**Description:** Personal, credential, regulated, and business-confidential data should be encrypted in storage and during network transmission using approved algorithms and key management.

**Example Implementation:** Provider-managed or customer-managed encryption keys for object storage and databases; TLS for data in transit.

---

## CTRL-DAT-002 — Classify and Protect Sensitive Information

**Control ID:** CTRL-DAT-002

**Name:** Classify and Protect Sensitive Information

**Objective:** Ensure sensitive data is identified and handled according to its classification.

**Control Type:** Preventive

**Domain:** Data Protection

**Description:** Information should be classified (for example public, internal, confidential, restricted) and protected with access, storage, and sharing rules matching that classification.

**Example Implementation:** Data classification labels, handling standards, and placement rules that forbid restricted data in publicly reachable locations.

---

## CTRL-DAT-003 — Control Data Export and Loss Prevention

**Control ID:** CTRL-DAT-003

**Name:** Control Data Export and Loss Prevention

**Objective:** Reduce unauthorized disclosure through uncontrolled export or transfer of sensitive data.

**Control Type:** Preventive

**Domain:** Data Protection

**Description:** Export, download, and sharing of sensitive data should be restricted to authorized channels. Data-loss prevention controls help block or flag risky transfers.

**Example Implementation:** DLP policies on email and cloud sync, restricted export roles, and approval workflows for bulk data extracts.

---

## CTRL-MON-001 — Security Logging and Monitoring

**Control ID:** CTRL-MON-001

**Name:** Security Logging and Monitoring

**Objective:** Detect unauthorized access, abuse, and suspicious activity through retained logs and monitoring.

**Control Type:** Detective

**Domain:** Security Monitoring

**Description:** Security-relevant events (authentication, privilege use, data access, and configuration changes) should be logged, retained, and reviewed or alerted on in near real time where risk warrants.

**Example Implementation:** Centralized logging for identity and cloud storage access, alerts on anonymous reads or failed privileged logins, and defined response playbooks.
