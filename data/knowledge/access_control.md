# Access control and information protection

## Least privilege and unauthorized access
Access to systems and data should follow least privilege: users and services receive only the rights needed for their role. Unique identities, strong authentication, and timely access reviews reduce unauthorized access. Privileged accounts require extra protection, including multi-factor authentication (MFA) and session monitoring. Shared or standing admin credentials increase the likelihood of account takeover and data exposure.

## Public cloud storage and misconfiguration
Misconfigured public cloud storage (for example an object bucket with public-read or overly broad identity policies) can expose sensitive files to the internet without an exploit. Preventive controls include private buckets by default, block-public-access settings, encryption, and least-privilege IAM. Detective controls include configuration scanning, access logs, and alerts on anonymous or unexpected reads.

## Confidentiality of sensitive information
Personal data, credentials, and business-confidential records require confidentiality controls across storage, transit, and processing. Classify data, restrict who can export it, and avoid placing production data in publicly reachable locations. A confidentiality failure (unauthorized disclosure) is typically high impact when the information is personal, regulated, or commercially sensitive.

## Preventive and detective controls
Preventive controls stop or reduce unauthorized access before it succeeds: MFA, network restrictions, hardened configurations, and data-loss prevention on exports. Detective controls identify abuse or misconfiguration after or during the event: audit logs, cloud security posture management, anomaly detection, and periodic access recertification. Both types should be used together; detection without prevention leaves a wide window of exposure.

## Risk treatment
When unauthorized access or cloud exposure is identified, treatment should match the risk: mitigate (close the misconfiguration, enforce MFA, tighten IAM), avoid (do not store sensitive data in that service), transfer (contractual or insurance arrangements where appropriate), or accept only with documented residual risk and owner approval. Do not leave a known public exposure untreated.
