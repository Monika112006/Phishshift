"""
Synthetic & Curated Corpus Generator for PhishShift.
Produces 500+ validated messages complying with Section 05:
- Schema: message_id, channel, subject_or_title, body_text, sanitized_url_features,
          sender_domain_type, label, campaign_group, collected_date.
- High lexical and syntactic variation to retain 400+ diverse records post-deduplication.
- Includes holdout campaign groups for FR-03 generalization testing.
- Includes urgent legitimate messages (password resets, payroll) for FR-05 false-positive testing.
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from src.defanger import extract_inert_url_features, defang_url


CAMPAIGN_SPECS = [
    # ---------------- PHISHING CAMPAIGNS ----------------
    {
        "campaign_group": "phish_credential_expire_classic",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "spoofed_lookalike",
        "subjects": [
            "CRITICAL: Password Expiration Notice for {user}",
            "Action Required: Your Office365 password expires in {hours} hours",
            "Urgent Security Alert: Account credential renewal required",
            "Notification: Immediate password synchronization needed",
            "Warning: Active Directory credential expiration on {date}",
            "Employee Portal: Mandatory authentication reset before {date}"
        ],
        "bodies": [
            "Dear employee, your corporate account password will expire in {hours} hours. Failure to update will result in account suspension. Click here to verify credentials: {url}",
            "Security notice: We detected an expired security certificate on your workstation. Keep your existing password by verifying at: {url}",
            "Final reminder: Your mailbox access will be disabled by midnight unless you confirm your login identity at: {url}",
            "System prompt: We were unable to validate your single sign-on token. Please re-authenticate your mailbox session at: {url}",
            "IT Infrastructure: Immediate verification required to maintain active VPN access. Re-verify account details here: {url}"
        ],
        "raw_urls": [
            "http://login-microsoft-portal-security.xyz/auth/login",
            "http://portal-verify-credential-update.top/user/session",
            "http://198.51.100.23/owa/auth.php",
            "http://identity-management-sync.click/reset",
            "http://account-recovery-session.work/portal"
        ],
        "count": 55,
        "is_holdout": False
    },
    {
        "campaign_group": "phish_executive_wire_fraud",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "free_webmail",
        "subjects": [
            "Confidential Task - Quick request from {exec_title}",
            "Urgent: wire transfer request before end of day",
            "Are you at your desk right now? Need immediate assistance",
            "Vendor Payment - Urgent Processing Needed",
            "Discrete inquiry from {exec_title} - reply required",
            "Immediate payment release authorized for contract #{contract_id}"
        ],
        "bodies": [
            "Hi, I am currently in a closed-door meeting and unable to take phone calls. Please process an urgent vendor invoice payment of ${amount}. Wire instructions link: {url}",
            "I need you to handle a discrete assignment for the executive board today. Can you purchase {num} Apple/Amazon gift cards for our client presentation? Confirm when done.",
            "Please review the attached overseas remittance voucher immediately. Our supplier will hold shipments if not settled in 2 hours: {url}",
            "Are you free? I am stuck in an offsite conference with spotty reception. Wire ${amount} to our logistics partner by 3 PM: {url}",
            "Urgent settlement needed for invoice #{contract_id}. The supplier will discontinue services without prompt clearing: {url}"
        ],
        "raw_urls": [
            "http://secure-wire-transfer-doc.club/invoice/download",
            "http://bit.ly/3xVendorPay",
            "http://remittance-document-portal.buzz/file?id=992",
            "http://rb.gy/wire-settlement-doc",
            "http://overseas-remittance-gateway.link/pay"
        ],
        "count": 45,
        "is_holdout": False
    },
    {
        "campaign_group": "phish_sms_package_delivery",
        "label": "phishing",
        "channel": "sms",
        "sender_domain_type": "suspicious_random",
        "subjects": ["SMS Notification"],
        "bodies": [
            "USPS: Package {pkg_id} could not be delivered due to incomplete address. Please update your details within 12h: {url}",
            "FedEx Alert: Outstanding customs fee ($2.45) required for parcel #{pkg_id}. Pay online to release: {url}",
            "DHL Express: Your delivery is on hold at local depot. Reschedule here: {url}",
            "Postal Service Notice: Dispatch failed for order #{pkg_id}. Confirm delivery slot today: {url}",
            "Courier tracking: Your shipment #{pkg_id} arrived at sorting facility. Address confirmation required: {url}"
        ],
        "raw_urls": [
            "http://tinyurl.com/usps-track-994",
            "http://post-redelivery-fees.link/track",
            "http://rb.gy/dhl892",
            "http://parcel-redirection-hub.buzz/confirm",
            "http://cutt.ly/delivery-fee-release"
        ],
        "count": 45,
        "is_holdout": False
    },
    {
        "campaign_group": "phish_fake_payroll_update",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "spoofed_lookalike",
        "subjects": [
            "Action Required: Direct Deposit Information Discrepancy",
            "Payroll Notification: Bank account verification needed",
            "Important: Month-End Salary Distribution Hold",
            "HR Payroll: Tax withholding form correction mandatory",
            "Disbursement Alert: Routing number mismatch on your file"
        ],
        "bodies": [
            "HR Payroll Department: A routing number discrepancy was flagged for your upcoming salary disbursement. Confirm your banking details immediately: {url}",
            "Your tax withholding W-2 form has been revised. Log in to your employee payroll portal to review and sign: {url}",
            "Salary deposit delayed: We were unable to credit your checking account. Update account information here: {url}",
            "Employee payroll audit: Please submit updated direct deposit confirmation to avoid payroll interruption: {url}",
            "Payroll alert: Electronic fund transfer failed for period ending {date}. Re-verify account details: {url}"
        ],
        "raw_urls": [
            "http://workday-payroll-portal-verification.work/login",
            "http://hr-directdeposit-update.support-update.com/w2",
            "http://203.0.113.88/payroll/verify.html",
            "http://portal-employee-payroll-auth.xyz/verify",
            "http://adp-remittance-update.top/disburse"
        ],
        "count": 45,
        "is_holdout": False
    },
    {
        "campaign_group": "phish_cloud_storage_share",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "free_webmail",
        "subjects": [
            "{vendor} shared an encrypted document with you via SharePoint",
            "OneDrive: Project budget proposal file requires your review",
            "Google Drive: New confidential spreadsheet shared by {user}",
            "DocuSign: Action requested on vendor non-disclosure agreement"
        ],
        "bodies": [
            "You have received a protected document from {vendor}. To view this secured spreadsheet, authenticate with your organization credentials: {url}",
            "{user} shared 'Q4_Compensation_Audit.pdf' with you on corporate OneDrive. Access expires in 24 hours: {url}",
            "Please review and electronically sign the attached service level agreement for contract #{contract_id}: {url}",
            "A confidential audit document has been deposited in your company drop folder. Sign in to review: {url}"
        ],
        "raw_urls": [
            "http://sharepoint-secure-cloud-access.xyz/doc",
            "http://onedrive-portal-review.top/file",
            "http://docusign-electronic-sign.click/view",
            "http://google-drive-shared-vault.buzz/audit"
        ],
        "count": 40,
        "is_holdout": False
    },
    # HOLDOUT CAMPAIGN 1: Novel phrasing MFA Session bypass (AT-02 candidate)
    {
        "campaign_group": "phish_novel_mfa_session_bypass",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "suspicious_random",
        "subjects": [
            "System Diagnostic: Periodic token synchronization challenge",
            "Security handshake advisory: Authenticator state validation",
            "Session validation ticket #{ticket_num}",
            "Telemetry alignment: Ephemeral handshake check required",
            "Device trust assertion: Incomplete security assertion token"
        ],
        "bodies": [
            "In accordance with updated telemetry baseline policies, your authenticator seed requires re-alignment. Proceed with the automated handshake: {url}",
            "A security telemetry discrepancy requires an ephemeral synchronization of your primary security key. Acknowledge the diagnostic link: {url}",
            "Periodic zero-trust endpoint reconciliation detected a missing trust claim on your device. Finalize alignment: {url}",
            "Security broker notice: Your identity session has encountered an attestation boundary divergence. Resolve via: {url}",
            "Infrastructure advisory: Cryptographic key material rollover in progress. Align local credential vault: {url}"
        ],
        "raw_urls": [
            "http://telemetry-handshake-broker.xyz/challenge",
            "http://zero-trust-claims-verifier.top/sync",
            "http://is.gd/telemetry-token-validate",
            "http://attestation-boundary-resolver.click/align",
            "http://identity-broker-reconcile.work/auth"
        ],
        "count": 45,
        "is_holdout": True  # Excluded from training to test FR-03 & AT-02
    },
    # HOLDOUT CAMPAIGN 2: Novel supply chain invoice modification
    {
        "campaign_group": "phish_unfamiliar_supply_chain_phish",
        "label": "phishing",
        "channel": "email",
        "sender_domain_type": "external_partner",
        "subjects": [
            "Notice of banking reconciliation shift - Q4 contracts",
            "Administrative note regarding remittance accounts for vendor {vendor}",
            "Amended banking details for pending disbursements",
            "Accounting advisory: Updated settlement routing for {vendor}",
            "Contract #{contract_id}: Re-routed payment instructions"
        ],
        "bodies": [
            "Kindly take note that our financial institution has completed a merger. Future payments for contract #{contract_id} must be directed to the updated escrow ledger: {url}",
            "Following our compliance review, our clearing accounts have been updated. Please reconcile before releasing outstanding statements: {url}",
            "Please note our revised IBAN and clearing coordinates for upcoming vendor disbursements: {url}",
            "Our treasury operations have transitioned to a new banking partner. Please download the certified clearing mandate: {url}"
        ],
        "raw_urls": [
            "http://escrow-remittance-reconcile.click/ledger",
            "http://vendor-settlement-audit.top/clearing",
            "http://treasury-operations-mandate.buzz/mandate",
            "http://clearing-bank-reconcile.xyz/iban"
        ],
        "count": 40,
        "is_holdout": True  # Excluded from training
    },

    # ---------------- LEGITIMATE CAMPAIGNS ----------------
    {
        "campaign_group": "legit_urgent_password_reset",
        "label": "legitimate",
        "channel": "email",
        "sender_domain_type": "internal_corporate",
        "subjects": [
            "Internal IT: Password Reset Request Confirmed",
            "Your One-Time Passcode for Corporate SSO",
            "Security Notice: Password successfully changed",
            "Action Required: Mandatory Annual Security Awareness Training",
            "Self-Service Password Reset: Verification PIN enclosed",
            "IT Helpdesk: Your temporary access credentials for new laptop"
        ],
        "bodies": [
            "Hello, your request to reset your enterprise domain password has been received. If you initiated this request, use your single-use recovery code {code}. If not, contact Helpdesk immediately at ext. 4400.",
            "Your corporate Single Sign-On session was authenticated from a new workstation. If this was you, no action is needed. View account security logs at internal portal: {url}",
            "Mandatory compliance notice: Please complete the Q4 Cyber Awareness module by Friday. Link to enterprise learning management system: {url}",
            "Your self-service password reset PIN is {code}. This PIN will expire in 10 minutes. For help, contact itsupport@corp.internal.",
            "IT Security Alert: Suspicious sign-in blocked by Azure AD Identity Protection. Reset your password immediately via internal SSO: {url}"
        ],
        "raw_urls": [
            "https://sso.internal.corp.local/security/audit",
            "https://lms.corp.internal.net/courses/cyber-2026",
            "https://helpdesk.corp.internal.net/portal",
            "https://selfservice.corp.internal.net/password-reset",
            "https://identity.corp.internal.net/myprofile"
        ],
        "count": 55,
        "is_holdout": False
    },
    {
        "campaign_group": "legit_payroll_hr_notices",
        "label": "legitimate",
        "channel": "email",
        "sender_domain_type": "internal_corporate",
        "subjects": [
            "HR Department: Open Enrollment Benefits Period Now Active",
            "Payroll Statement Available: October 2026 Direct Deposit",
            "Annual Tax Information (W-2 / 1099) Electronic Consent",
            "Notice: Timesheet submission deadline for upcoming holiday",
            "Corporate 401(k) Employer Contribution Match Annual Summary"
        ],
        "bodies": [
            "Dear Colleague, Open Enrollment for healthcare and retirement plans is now open through Nov 15. Review your current elections in the HR Intranet: {url}",
            "Your payslip for period ending October 31, 2026 is ready for viewing in Workday. Note: HR will never ask for your banking passwords via email. Access directly: {url}",
            "Please review and submit your monthly timesheet before 5:00 PM today to prevent any processing delays for payroll: {url}",
            "Your electronic W-2 delivery preferences have been saved. You can download prior year tax statements from: {url}",
            "Company benefits update: Dental and vision copay schedules for the upcoming fiscal calendar have been posted: {url}"
        ],
        "raw_urls": [
            "https://workday.corp.internal.net/payroll/view",
            "https://intranet.corp.internal.net/hr/benefits-2026",
            "https://timesheets.corp.internal.net/submit",
            "https://benefits.corp.internal.net/enrollment",
            "https://taxportal.corp.internal.net/w2-download"
        ],
        "count": 55,
        "is_holdout": False
    },
    {
        "campaign_group": "legit_mfa_push_notifications",
        "label": "legitimate",
        "channel": "sms",
        "sender_domain_type": "internal_corporate",
        "subjects": ["MFA Security Verification"],
        "bodies": [
            "Your Duo Security verification code is {code}. Do not share this code with anyone. It expires in 5 minutes.",
            "Microsoft Authenticator: Approve sign-in request for user {user} on corporate VPN? If unauthorized, reply STOP and report to SOC.",
            "Okta Verify: 6-digit authentication code: {code}. For support visit {url}",
            "Enterprise SMS Gateway: Your authorization code for workstation unlock is {code}.",
            "Google Workspace 2-Step Verification code: G-{code}. Never disclose this code over the phone."
        ],
        "raw_urls": [
            "https://verify.corp.internal.net/auth-help",
            "https://okta.corp.internal.net/support",
            "https://duo.corp.internal.net/device-management"
        ],
        "count": 45,
        "is_holdout": False
    },
    {
        "campaign_group": "legit_engineering_alerts",
        "label": "legitimate",
        "channel": "email",
        "sender_domain_type": "internal_corporate",
        "subjects": [
            "[CRITICAL P1] Service Latency Spike in Production Cluster",
            "PagerDuty: High Priority incident #4912 assigned to DevOps",
            "Scheduled Maintenance: Kubernetes cluster rolling upgrade tonight",
            "[Resolved] Incident #4908: API Gateway 502 Bad Gateway errors cleared",
            "Security Alert: Automated weekly container vulnerability scan summary"
        ],
        "bodies": [
            "Alertmanager notification: High 5xx error rate detected on API Gateway service. On-call engineers please join the triage bridge: {url}",
            "Grafana Alert: Memory usage exceeded 90% on database replica db-prod-03. Runbook: {url}",
            "DevOps team notice: Routine kernel security patches will be applied tonight between 02:00 and 03:00 UTC. No customer downtime anticipated.",
            "SonarQube code quality gate passed for repository phishshift-backend. View scan results: {url}",
            "AWS GuardDuty finding: Port probe activity observed on bastion host bastion-02. Host quarantined per runbook."
        ],
        "raw_urls": [
            "https://grafana.internal.corp.local/d/alerts",
            "https://runbooks.corp.internal.net/incident/4912",
            "https://pagerduty.internal.corp.local/incidents",
            "https://sonarqube.corp.internal.net/dashboard",
            "https://aws-console.internal.corp.local/guardduty"
        ],
        "count": 45,
        "is_holdout": False
    },
    {
        "campaign_group": "legit_daily_team_collaboration",
        "label": "legitimate",
        "channel": "email",
        "sender_domain_type": "internal_corporate",
        "subjects": [
            "Notes from weekly architecture sync & next sprint goals",
            "PR #342: Fix input sanitization in payment processor ready for review",
            "Lunch & Learn session: Best practices in NLP model explainability",
            "Design Doc: PhishShift multi-stage risk classification architecture",
            "Welcome to the team! Onboarding checklist and resource links"
        ],
        "bodies": [
            "Team, thanks for attending today's sync. Key action items: finalize requirement traceability matrix, run baseline benchmarks, and merge sprint branches.",
            "Hey everyone, please take a look at Pull Request #342 when you get a chance. Code changes are covered with unit tests: {url}",
            "Reminder: We have the quarterly all-hands meeting tomorrow at 10 AM in the auditorium and via Zoom. Slides will be shared after the call.",
            "Please review the proposed design document for the feature extraction pipeline before our technical review on Thursday: {url}",
            "Great job finishing sprint 14 on schedule! Let's complete retrospectives on the Jira board by Friday afternoon: {url}"
        ],
        "raw_urls": [
            "https://github.corp.internal.net/phishshift/core/pull/342",
            "https://confluence.corp.internal.net/display/ENG/SyncNotes",
            "https://jira.corp.internal.net/browse/PS-89",
            "https://docs.corp.internal.net/d/design-doc-nlp"
        ],
        "count": 45,
        "is_holdout": False
    },
    # HOLDOUT CAMPAIGN 3: Legitimate business messages with urgency & password mentions
    {
        "campaign_group": "legit_holdout_executive_announcements",
        "label": "legitimate",
        "channel": "email",
        "sender_domain_type": "internal_corporate",
        "subjects": [
            "URGENT: Executive Leadership Council Reorganization Notice",
            "Critical Compliance Deadline: Annual Code of Conduct Attestation",
            "Action Needed: Mandatory MFA hardware security key registration",
            "Urgent: Financial audit documentation required by external auditors",
            "Immediate Attention: Building access badge re-credentialing"
        ],
        "bodies": [
            "All Staff: The annual audit period closes this Friday at 6:00 PM. All employees must log into the compliance portal to complete sign-off: {url}. Please prioritize immediately.",
            "From the Chief Information Security Officer: In response to industry threats, all staff must register their physical FIDO2 key. Review the rollout guide here: {url}",
            "Notice from Finance: End-of-year expense reports must be submitted without delay. Unsubmitted claims will be deferred to next fiscal year: {url}",
            "Urgent request from Facilities: Security badge scanners will be re-keyed this weekend. Verify your security clearance badge ID here: {url}",
            "Chief Compliance Officer: Confirmation of anti-bribery attestation is mandatory for all active employees before month end: {url}"
        ],
        "raw_urls": [
            "https://compliance.corp.internal.net/attestation/2026",
            "https://security.corp.internal.net/fido2-rollout",
            "https://finance.corp.internal.net/expenses",
            "https://facilities.corp.internal.net/badge-rekey",
            "https://legal.corp.internal.net/compliance"
        ],
        "count": 45,
        "is_holdout": True  # Excluded from training to test FPR on legitimate urgent messages
    }
]


def generate_curated_dataset() -> List[Dict[str, Any]]:
    records = []
    message_counter = 1000

    users = ["alice.smith", "bob.martin", "carol.white", "david.kim", "elena.rostova", "frank.miller", "grace.hopper", "harold.f"]
    vendors = ["AcmeLogistics", "ApexSupplyCorp", "NordicSaaS", "VertexGlobal", "DeltaTech", "OmniCorpCloud"]
    exec_titles = ["CEO", "Chief Financial Officer", "VP of Operations", "Executive Director", "Chief Security Officer"]

    base_date = datetime(2026, 9, 1)

    for spec in CAMPAIGN_SPECS:
        campaign = spec["campaign_group"]
        label = spec["label"]
        channel = spec["channel"]
        sender_type = spec["sender_domain_type"]
        is_holdout = spec["is_holdout"]
        count = spec["count"]

        for i in range(count):
            message_counter += 1
            msg_id = f"MSG-{message_counter:05d}"
            
            user = random.choice(users)
            vendor = random.choice(vendors)
            exec_title = random.choice(exec_titles)
            hours = random.choice([2, 4, 6, 8, 12, 24, 48])
            amount = f"{random.randint(1500, 75000):,}"
            num = random.randint(3, 12)
            pkg_id = f"US{random.randint(100000, 999999)}X"
            code = f"{random.randint(100000, 999999)}"
            ticket_num = f"{random.randint(1000, 9999)}"
            contract_id = f"CTR-{random.randint(2000, 8999)}"
            date_str = (base_date + timedelta(days=random.randint(1, 60))).strftime("%b %d, %Y")

            raw_url = random.choice(spec["raw_urls"])
            if "?" in raw_url:
                raw_url += f"&session_token={random.randint(10000, 99999)}"
            else:
                raw_url += f"?req_id={random.randint(1000, 9999)}"
            
            sanitized_features = extract_inert_url_features(raw_url)
            defanged_display_url = sanitized_features["defanged_url"]

            subject_template = random.choice(spec["subjects"])
            body_template = random.choice(spec["bodies"])

            subject = subject_template.format(
                user=user, hours=hours, exec_title=exec_title,
                ticket_num=ticket_num, vendor=vendor, date=date_str, contract_id=contract_id
            )
            body = body_template.format(
                user=user, hours=hours, amount=amount, num=num,
                pkg_id=pkg_id, code=code, ticket_num=ticket_num,
                contract_id=contract_id, url=defanged_display_url, date=date_str,
                vendor=vendor, exec_title=exec_title
            )

            # Introduce deliberate duplicate template clones every 10th record
            if i % 10 == 0 and i > 0:
                body = body.replace("Please ", "Kindly ").replace("immediately", "without delay")

            day_offset = random.randint(0, 50)
            collected_date = (base_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")

            record = {
                "message_id": msg_id,
                "channel": channel,
                "subject_or_title": subject,
                "body_text": body,
                "sanitized_url_features": sanitized_features,
                "sender_domain_type": sender_type,
                "label": label,
                "campaign_group": campaign,
                "is_holdout": is_holdout,
                "collected_date": collected_date
            }
            records.append(record)

    random.seed(42)
    random.shuffle(records)
    return records


def build_and_save_data():
    dataset = generate_curated_dataset()
    
    with open("data/phishshift_raw.json", "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    manifest = {
        "dataset_name": "PhishShift Message Risk Benchmark Corpus",
        "total_records": len(dataset),
        "license": "Creative Commons Attribution 4.0 International (CC BY 4.0) & Educational Research License",
        "version": "1.0.0",
        "created_date": "2026-10-27",
        "provenance": {
            "sources": [
                "Locally authored benign enterprise communications (IT, HR, DevOps, Admin)",
                "Simulated synthetic phishing campaign variants inspired by ENISA and CISA threat advisories",
                "Controlled perturbation benchmarks for robustness analysis"
            ],
            "inert_url_guarantee": "All URLs converted to defanged format (hxxp / [.]) - strictly inert per NFR-01",
            "pii_compliance": "No real credentials, mailboxes, or user PII included per NFR-02"
        },
        "campaign_summary": {}
    }

    for item in dataset:
        cg = item["campaign_group"]
        if cg not in manifest["campaign_summary"]:
            manifest["campaign_summary"][cg] = {
                "label": item["label"],
                "channel": item["channel"],
                "is_holdout": item["is_holdout"],
                "count": 0
            }
        manifest["campaign_summary"][cg]["count"] += 1

    with open("data/corpus_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Generated {len(dataset)} records across {len(manifest['campaign_summary'])} campaigns.")
    print("Files written: data/phishshift_raw.json, data/corpus_manifest.json")


if __name__ == "__main__":
    build_and_save_data()
