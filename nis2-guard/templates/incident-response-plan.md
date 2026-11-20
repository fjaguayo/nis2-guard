# Incident response plan (template)

Fill in the bracketed fields and review the document at least once a year. The deadlines
follow Article 23 of NIS2, GDPR Article 33 and DORA Article 19, but your national law,
technical standards and competent authority may refine them. Confirm with your advisor.

## 1. Responsible people

- Incident lead: [name, phone, deputy]
- Management contact: [name, phone]
- Legal and data protection contact: [name]
- Authority or CSIRT to notify: [name and contact channel]

## 2. Detection

Alert sources: [authentication logs, antivirus/EDR, supplier notices, external reports].
Who reviews alerts and how often: [define].

## 3. Classification

An incident is significant if it causes or can cause severe operational disruption or
financial loss, or if it affects other people by causing considerable material or
non-material damage. Internal criteria to decide this: [define thresholds].

## 4. Notification deadlines

| When | What | To whom |
|------|------|---------|
| Within 24 h of becoming aware | Early warning: whether unlawful action is suspected and whether there is cross-border impact | [authority / CSIRT] |
| Within 72 h | Notification with initial assessment, severity, impact and indicators of compromise | [authority / CSIRT] |
| Within 1 month of the notification | Final report: root cause, measures applied and cross-border impact | [authority / CSIRT] |

Other frameworks that may apply to the same incident (delete what does not apply):

| Framework | When | What | To whom |
|-----------|------|------|---------|
| GDPR Art. 33, 34 | Within 72 h of becoming aware of a personal data breach | Nature of the breach, categories and approximate number of people and records, likely consequences, measures taken | Supervisory authority [AEPD in Spain]; affected people without undue delay if the risk is high |
| DORA Art. 19 | Initial: within 4 h of classifying it as major and no later than 24 h after becoming aware. Intermediate: within 72 h of the initial notification. Final: within 1 month of the latest intermediate report | Classification, impact on services and clients, root cause, recovery | Financial competent authority [Banco de España / CNMV / DGSFP] |

A single incident can trigger several reports with different clocks. Name one person who
decides which ones apply: [name].

## 5. Containment and recovery

Steps to isolate systems, revoke credentials, restore from backups and validate recovery: [define].

## 6. After the incident

Lessons-learned meeting within 15 days. Agreed changes and an owner for each: [record].
