"""
Independent Evaluation of PhishGuard AI on Out-of-Distribution & Unseen Scenarios.
This script evaluates the trained PhishGuard AI model on a freshly curated,
completely independent test set of 50 realistic phishing, social engineering,
and legitimate communications without modifying the model, rules, dataset, or UI.
"""

import os
import sys
import json
import re
from typing import Dict, List, Any, Tuple

# Ensure root workspace is in sys.path
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_DIR)

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
    classification_report,
)

from src.model import PhishGuardClassifier, DEFAULT_MODEL_PATH
from src.tactics import analyze_tactics
from src.preprocessing import clean_text

DATA_PATH = os.path.join(WORKSPACE_DIR, "data", "dataset.csv")

# 50 Independent, Curated Test Cases
INDEPENDENT_TEST_SET: List[Dict[str, Any]] = [
    # =========================================================================
    # PHISHING & SOCIAL ENGINEERING (Label = 1, 25 Cases)
    # =========================================================================
    # 1. Subtle BEC & Executive Impersonation
    {
        "id": "bec_falcon_escrow",
        "category": "Subtle BEC",
        "label": 1,
        "text": (
            "Subject: Extremely Urgent - Project Falcon Escrow Wire\n\n"
            "Hi David, I am in meetings with counsel all morning and can't jump on a call. "
            "We just received approval from the board to finalize the initial escrow deposit "
            "for the Project Falcon acquisition. Wire $78,500 immediately to the attorney's trust "
            "account detailed in the attached instructions. Speed is critical to avoid missing the closing deadline today."
        ),
    },
    {
        "id": "bec_legal_retainer",
        "category": "Subtle BEC",
        "label": 1,
        "text": (
            "Subject: Confidential: Engagement with Outside Legal Counsel\n\n"
            "Hi Marcus, Please keep this strictly between us for now due to regulatory sensitivities. "
            "We are engaging Sullivan & partners for advisory on a confidential merger. They need a retainer "
            "fee of $42,000 processed before 3:00 PM today. Let me know when you can initiate the domestic "
            "wire and I will send the bank coordinates."
        ),
    },
    {
        "id": "bec_summit_giftcards",
        "category": "Subtle BEC",
        "label": 1,
        "text": (
            "Subject: Quick favor for the regional sales summit\n\n"
            "Good morning, I am currently facilitating our off-site leadership workshop and cannot step out. "
            "We need to present 8 Target digital gift cards worth $150 each to our guest speakers this afternoon. "
            "Could you purchase these right away and reply with the gift card numbers and redemption PINs? "
            "I will approve the expense reimbursement tonight."
        ),
    },
    {
        "id": "bec_heathrow_stipend",
        "category": "Subtle BEC",
        "label": 1,
        "text": (
            "Subject: Emergency stipend request - travel issue\n\n"
            "Hi HR / Accounting team, I am stranded at London Heathrow due to flight cancellations and my "
            "corporate card is being declined. Could you please wire an emergency travel stipend of $3,500 "
            "to my European Revolut account immediately so I can rebook lodging and travel? Routing details attached."
        ),
    },
    {
        "id": "bec_kpmg_audit_validation",
        "category": "Subtle BEC",
        "label": 1,
        "text": (
            "Subject: External Audit Confirmation - Sensitive Bank Validation\n\n"
            "Dear Treasury Team, As part of our annual KPMG compliance audit, our external auditors need an "
            "immediate re-confirmation of our operating liquidity. Please reply urgently with our current account "
            "balance and latest wire routing numbers to authorize the auditor validation portal."
        ),
    },

    # 2. MFA Fatigue, Push Bombing & Session Hijacking
    {
        "id": "mfa_okta_verify_checkpoint",
        "category": "MFA Fatigue",
        "label": 1,
        "text": (
            "Okta Security Notice: Multiple unrecognized push authentication prompts were detected on your "
            "registered Okta Verify device. To stop these repeated notification prompts and re-secure your "
            "session token, please tap the link below and authenticate immediately: https://okta-session-verify-checkpoint.com/auth"
        ),
    },
    {
        "id": "mfa_duo_phone_bypass",
        "category": "MFA Fatigue",
        "label": 1,
        "text": (
            "Duo Two-Factor Verification: A login attempt was detected from a new location (Kyiv, UA). "
            "If this wasn't you, press 1 on the incoming phone prompt or authenticate at "
            "https://duo-security-protect-gate.net/token to lock your credentials and reset your security keys."
        ),
    },
    {
        "id": "mfa_msft_code_match",
        "category": "MFA Fatigue",
        "label": 1,
        "text": (
            "Microsoft 365 Alert: Your Microsoft Authenticator app session has encountered a continuous sync failure. "
            "You will receive 3 push verification requests on your mobile phone; you must approve the number matching "
            "code displayed here: 84 to restore uninterrupted email access."
        ),
    },
    {
        "id": "mfa_ping_federate_timeout",
        "category": "MFA Fatigue",
        "label": 1,
        "text": (
            "PingFederate Single Sign-On: Your active workstation session has expired due to policy timeout. "
            "An automated MFA push was dispatched to your mobile device. Click here to confirm identity and "
            "maintain your active VPN session: http://sso-pingidentity-corp-renew.com"
        ),
    },
    {
        "id": "mfa_fido_key_attestation",
        "category": "MFA Fatigue",
        "label": 1,
        "text": (
            "Google Workspace Admin: Your physical FIDO security key failed cryptographic attestation. "
            "An emergency one-time verification passcode has been SMS-delivered. Enter the passcode at "
            "https://workspace-accounts-recovery-auth.com to prevent immediate account lockdown."
        ),
    },

    # 3. Payment Diversion & Supplier Account Modification
    {
        "id": "payment_acme_remittance_swap",
        "category": "Payment Diversion",
        "label": 1,
        "text": (
            "Subject: Updated Remittance Instructions for Invoice INV-88192\n\n"
            "Dear Accounts Payable, Please note that due to our recent corporate banking consolidation, "
            "all future payments to Acme Industrial Logistics must be remitted to our new Chase Treasury account. "
            "Attached is our updated W-9 form and ACH banking details. Please update your ERP system prior "
            "to releasing this week's disbursements."
        ),
    },
    {
        "id": "payment_payroll_direct_deposit",
        "category": "Payment Diversion",
        "label": 1,
        "text": (
            "Subject: Request to change direct deposit account\n\n"
            "Hello Payroll Department, I recently opened a new high-yield savings account and would like to "
            "update my direct deposit allocation before the upcoming semi-monthly payroll. Can you please deposit "
            "100% of my net wages into the attached account ending in 4921 starting this cycle? Let me know if you need any other documents."
        ),
    },
    {
        "id": "payment_machinery_swift_iban",
        "category": "Payment Diversion",
        "label": 1,
        "text": (
            "Subject: RE: Outstanding Machinery Payment - New SWIFT Details\n\n"
            "Hello Finance, Regarding PO #91029 for the conveyor systems: Our European subsidiary's previous "
            "Deutsche Bank account is currently undergoing an audit. Please remit the remaining €64,000 balance "
            "using the following IBAN: ES9121000418450200051332. Kindly send the wire transfer receipt once completed."
        ),
    },
    {
        "id": "payment_overpayment_wire_refund",
        "category": "Payment Diversion",
        "label": 1,
        "text": (
            "Subject: Overpayment Notice & Wire Refund Demand\n\n"
            "Dear Billing Team, Our accounting records indicate that our company overpaid invoice #3910 by $14,250.00. "
            "Our CFO has requested an immediate electronic wire refund to our operating account instead of issuing "
            "account credit. Please find our bank details attached and process the refund within 48 hours."
        ),
    },
    {
        "id": "payment_escrow_title_change",
        "category": "Payment Diversion",
        "label": 1,
        "text": (
            "Subject: Revised Wire Instructions for Property Closing Escrow\n\n"
            "Dear Buyer, Please be advised that the previously provided wire instructions for escrow deposit have "
            "been updated due to an internal banking switch at First Horizon Title. Do not send funds to the previous account. "
            "Please wire the final closing balance of $31,400.00 to the updated routing and account numbers attached."
        ),
    },

    # 4. Paraphrased & Pretexting Phishing
    {
        "id": "paraphrased_miro_whiteboard",
        "category": "Paraphrased Phishing",
        "label": 1,
        "text": (
            "Hey! I drafted our preliminary Q1 strategic roadmap and customer journey maps on the collaborative whiteboard. "
            "Take a look when you have a free moment and drop any comments before our alignment session: "
            "http://miro-collab-spaces-board.io/shared/plan"
        ),
    },
    {
        "id": "paraphrased_greenhouse_job",
        "category": "Paraphrased Phishing",
        "label": 1,
        "text": (
            "Hello! I came across your impressive LinkedIn profile and believe your background is a great match for "
            "our remote Senior Systems Architect opening ($185k - $210k). If interested in discussing further, please "
            "review the complete job specification and upload your updated resume here: https://greenhouse-talent-recruitment.cc/job/8812"
        ),
    },
    {
        "id": "paraphrased_podcast_interview",
        "category": "Paraphrased Phishing",
        "label": 1,
        "text": (
            "Hi team, Our editorial crew would love to feature your engineering organization on our weekly Enterprise "
            "Tech Spotlight podcast. We have put together the preliminary discussion topics and interview questions in "
            "this shared document: https://notion-guest-briefing-docs.com/read?id=39104"
        ),
    },
    {
        "id": "paraphrased_adobe_contract",
        "category": "Paraphrased Phishing",
        "label": 1,
        "text": (
            "Hi Robert, Following our phone discussion this morning, here is the revised master service agreement "
            "with our updated indemnity clause. Please look over section 4 and complete your digital initials here: "
            "http://adobesign-document-review-portal.net/doc/29184"
        ),
    },
    {
        "id": "paraphrased_recognition_perks",
        "category": "Paraphrased Phishing",
        "label": 1,
        "text": (
            "Congratulations! You were nominated by a teammate for our quarterly employee excellence reward. "
            "To select your prepaid Mastercard or merchandise gift card, please log into the employee recognition "
            "catalog: http://company-perks-rewards-claim.org/redeem"
        ),
    },

    # 5. Realistic Lures & Contemporary Smishing
    {
        "id": "smishing_usps_redelivery",
        "category": "Contemporary Smishing/Lures",
        "label": 1,
        "text": (
            "USPS Alert: Package tracking #94001118992238472910 could not be delivered due to an incorrect house number. "
            "A $1.85 redelivery fee is required. Update your address and confirm delivery here: "
            "https://usps-post-redelivery-tracking.com"
        ),
    },
    {
        "id": "smishing_ezpass_toll",
        "category": "Contemporary Smishing/Lures",
        "label": 1,
        "text": (
            "E-ZPass Toll Violation: We have recorded unpaid toll fees of $12.50 associated with your license plate. "
            "Avoid late penalties and vehicle registration suspension by settling balance now: "
            "https://toll-service-violation-pay.info"
        ),
    },
    {
        "id": "smishing_voicemail_audio",
        "category": "Contemporary Smishing/Lures",
        "label": 1,
        "text": (
            "New Voicemail received from (415) 891-0231 (duration 0:48). To listen to this audio message online, "
            "click here: https://mobile-voicemail-playback-service.com/listen?id=6109"
        ),
    },
    {
        "id": "lure_qr_code_migration",
        "category": "Contemporary Smishing/Lures",
        "label": 1,
        "text": (
            "IT Support Notification: Our company is migrating to enhanced enterprise single-sign on. "
            "Please scan the attached QR code with your mobile camera to register your corporate authenticator "
            "token before your legacy login expires on Friday."
        ),
    },
    {
        "id": "lure_quarantined_files",
        "category": "Contemporary Smishing/Lures",
        "label": 1,
        "text": (
            "Microsoft Defender Alert: 4 inbound files addressed to you were quarantined due to anomalous encryption headers. "
            "Click here to preview the quarantined messages and request sandbox release: "
            "https://security-quarantine-portal-admin.com/release"
        ),
    },

    # =========================================================================
    # LEGITIMATE COMMUNICATIONS (Label = 0, 25 Cases)
    # =========================================================================
    # 1. Legitimate Security Alerts & Notifications
    {
        "id": "legit_github_pat_created",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "GitHub Security Notification: A new personal access token (classic) with 'repo, workflow' scopes was "
            "generated on your account from IP address 198.51.100.24. If you created this token, no action is needed. "
            "If you did not generate this token, please visit your account settings at github.com to revoke it immediately."
        ),
    },
    {
        "id": "legit_aws_root_console",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "AWS CloudTrail Notification: Root user console login was observed in AWS account 482910481920 in "
            "us-east-1 on 2026-10-15 09:14 UTC. Event ID: d84e2091-c812. This notification is sent per your "
            "CloudWatch alarm configuration for root account activity."
        ),
    },
    {
        "id": "legit_slack_session_notice",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "Slack Security Notice: We noticed a new sign-in to your Slack workspace 'Engineering Hub' from Chrome "
            "on macOS in Austin, TX, United States. IP: 66.249.79.10. If this was you, you can safely ignore this email. "
            "You can view all active sessions anytime in your account preferences."
        ),
    },
    {
        "id": "legit_google_2step_status",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "Google Account Alert: 2-Step Verification was recently turned on for your account user@company.com on "
            "October 14, 2026. From now on, when you sign in on an unrecognized device, you will be prompted for your "
            "second factor. You can manage your security keys and backup codes in your Google Account settings."
        ),
    },
    {
        "id": "legit_vpn_tunnel_active",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "Corporate GlobalProtect VPN: Your remote workstation successfully established an encrypted SSL-VPN tunnel "
            "to Gateway us-west-gateway.corp.net. Assigned Virtual IP: 10.240.18.94. Session timeout is configured for 12 hours."
        ),
    },
    {
        "id": "legit_bank_fraud_text_reply",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "Wells Fargo Fraud Alert: Did you attempt a $64.18 transaction at Home Depot ending in 8109? "
            "Reply 1 if authorized, or reply 2 if fraudulent. We will never ask you for your PIN, passwords, "
            "or full card number via text."
        ),
    },
    {
        "id": "legit_it_patch_cycle",
        "category": "Legitimate Security Alert",
        "label": 0,
        "text": (
            "IT Systems Advisory: The monthly security patch cycle for corporate Windows and macOS laptops will begin "
            "this Thursday at 8:00 PM. Systems will require a reboot within 72 hours. Please save your open work before leaving for the day."
        ),
    },

    # 2. Legitimate Financial & Billing Notices
    {
        "id": "legit_stripe_jira_receipt",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "Receipt from Atlassian via Stripe: Payment of $480.00 for 40 Jira Software Cloud Standard user licenses "
            "was successfully processed on Oct 12, 2026. Payment method: Visa ending in 3192. View and download your "
            "PDF invoice directly in your Atlassian billing administration console."
        ),
    },
    {
        "id": "legit_pge_autopay_final",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "Pacific Gas and Electric: Your monthly energy statement for service period Sep 10 - Oct 09 is now finalized. "
            "Total amount due: $118.42, due on November 03, 2026. Auto-pay is active and scheduled. You can log into "
            "pge.com to review hourly breakdown and rate plan details."
        ),
    },
    {
        "id": "legit_concur_expense_approved",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "SAP Concur Notification: Expense report 'Q3 Regional Client Visits' submitted by Alex Chen in the amount "
            "of $1,248.60 has been approved by your department manager and forwarded to Accounts Payable for scheduled disbursement."
        ),
    },
    {
        "id": "legit_colocation_standard_inv",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "Dear Finance Team, Attached is our standard quarterly invoice #INV-7731 for server colocation services "
            "covering Q4 2026. Payment terms are net 45 per our master service agreement. Remittance details remain "
            "identical to previous quarters. Thank you for your continued business."
        ),
    },
    {
        "id": "legit_capitalone_savings_interest",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "Capital One Statement Notice: Your monthly high-yield savings interest of $34.12 was credited to account "
            "ending in 9021 on September 30, 2026. Current annual percentage yield: 4.25%. Sign in to the official "
            "Capital One mobile app to review your balance."
        ),
    },
    {
        "id": "legit_workday_biweekly_payslip",
        "category": "Legitimate Billing",
        "label": 0,
        "text": (
            "Workday Notification: Your bi-weekly payslip for the pay period ending October 15, 2026 is now available. "
            "To view gross pay, tax deductions, and benefits contributions, log into the Workday employee self-service "
            "portal from the company intranet."
        ),
    },

    # 3. Legitimate Operational & IT Notices
    {
        "id": "legit_postgres_maintenance",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "Engineering Announcement: Scheduled database index optimization on our production PostgreSQL replicas "
            "will take place on Sunday, Oct 18 between 02:00 and 04:00 UTC. Brief read latency spikes of 50-100ms may occur. "
            "Primary writer databases remain unaffected."
        ),
    },
    {
        "id": "legit_jira_ticket_monitor_closed",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "Jira Service Management: Issue IT-4921 ('Request for second external monitor and USB-C dock') has been marked "
            "as RESOLVED by Support Tech James Wilson. If your hardware is functioning as expected, no further action is necessary."
        ),
    },
    {
        "id": "legit_wifi_wpa3_cert_notice",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "Corporate Network Notice: The root CA certificate for the 'CorpSecure-WPA3' wireless network will be renewed on "
            "November 1. Managed company laptops will receive the updated profile automatically via MDM. Personal guest "
            "devices should continue using 'Corp-Guest'."
        ),
    },
    {
        "id": "legit_jetbrains_license_renewed",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "JetBrains License Server: The annual commercial subscription for All Products Pack has been renewed for the "
            "organization through October 2027. Developers can refresh their floating license tickets automatically within their IDE."
        ),
    },
    {
        "id": "legit_flu_vaccine_wellness",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "Employee Wellness Committee: The annual on-site seasonal flu vaccination clinic will be held in Conference Room B "
            "next Tuesday from 9:00 AM to 3:00 PM. Participation is voluntary and covered at no cost under our group health plans."
        ),
    },
    {
        "id": "legit_thanksgiving_holiday_memo",
        "category": "Legitimate Operations",
        "label": 0,
        "text": (
            "Human Resources Bulletin: In observance of Thanksgiving, company offices will be closed on Thursday, November 26 "
            "and Friday, November 27. On-call engineering support will follow the standard emergency rotation schedule."
        ),
    },

    # 4. Legitimate Business & Workplace Collaboration
    {
        "id": "legit_qbr_slides_review",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Hi team, I uploaded the draft presentation slides for next week's Q4 Business Review with executive leadership "
            "to our team's Google Drive folder. Please leave comments or suggested revisions on slides 8 through 14 before "
            "our dry run on Wednesday afternoon."
        ),
    },
    {
        "id": "legit_sprint_retro_action_items",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Hey everyone, thanks for the constructive discussion during yesterday's Sprint 14 retrospective. I have "
            "summarized the top action items on our Confluence wiki: focusing on unit test coverage for the payment "
            "gateway and improving our CI build times. See you all at standup."
        ),
    },
    {
        "id": "legit_team_lunch_poll_rsvp",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Hey folks! To celebrate wrapping up our major release milestone this month, we're planning a team lunch next "
            "Friday at noon. Please reply to this thread with any dietary preferences or cuisine suggestions by tomorrow "
            "so we can make the reservation."
        ),
    },
    {
        "id": "legit_github_pr_telemetry",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Pull Request #342: 'Implement exponential backoff retry for downstream telemetry collector' is ready for review. "
            "Unit tests and lint checks have passed in GitHub Actions. Requesting review from @backend-core-team when you get a chance."
        ),
    },
    {
        "id": "legit_nda_legal_redlines",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Hi Rebecca, Attached is our legal department's redlined version of the mutual non-disclosure agreement for the "
            "potential joint development initiative. Our legal counsel has adjusted the confidentiality period to three "
            "years in section 6. Let us know if these terms work for your team."
        ),
    },
    {
        "id": "legit_cloud_migration_proposal_sync",
        "category": "Legitimate Collaboration",
        "label": 0,
        "text": (
            "Good afternoon Mark, Thanks for the detailed proposal regarding cloud migration consulting. Our architectural "
            "review committee met this morning to evaluate the timeline. We would like to schedule a 30-minute sync this "
            "Thursday at 2 PM to clarify milestone deliverables for phase two."
        ),
    },
]


def verify_no_overlap() -> Tuple[bool, List[str]]:
    """
    Verifies that NONE of the independent test samples overlap with:
    1. data/dataset.csv
    2. scripts/augment_dataset.py
    3. src/samples.py
    4. tests/test_regressions.py
    5. tests/test_model.py
    6. tests/test_tactics.py
    7. tests/test_e2e_verification.py
    8. scripts/diagnose.py
    """
    issues = []

    # 1. Load dataset.csv
    df = pd.read_csv(DATA_PATH)
    training_texts = df["text"].dropna().astype(str).tolist()
    training_clean = set(clean_text(t) for t in training_texts)
    training_raw = set(t.strip().lower() for t in training_texts)

    # 2. Collect existing test/script files
    files_to_check = [
        os.path.join(WORKSPACE_DIR, "scripts", "augment_dataset.py"),
        os.path.join(WORKSPACE_DIR, "src", "samples.py"),
        os.path.join(WORKSPACE_DIR, "tests", "test_regressions.py"),
        os.path.join(WORKSPACE_DIR, "tests", "test_model.py"),
        os.path.join(WORKSPACE_DIR, "tests", "test_tactics.py"),
        os.path.join(WORKSPACE_DIR, "tests", "test_e2e_verification.py"),
        os.path.join(WORKSPACE_DIR, "scripts", "diagnose.py"),
    ]

    other_texts = []
    for fpath in files_to_check:
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                # Find all quoted string literals with >= 30 chars
                quotes = re.findall(r'["\']([^"\']{30,})["\']', content)
                other_texts.extend(quotes)

    other_clean = set(clean_text(t) for t in other_texts)
    other_raw = set(t.strip().lower() for t in other_texts)

    # Check each sample
    training_token_sets = [set(re.findall(r"\w+", t)) for t in training_raw if len(t) > 30]

    for s in INDEPENDENT_TEST_SET:
        sample_id = s["id"]
        raw = s["text"].strip().lower()
        cleaned = clean_text(s["text"])

        # Check raw exact match
        if raw in training_raw:
            issues.append(f"Sample '{sample_id}' exact raw match in training dataset.csv!")
        if raw in other_raw:
            issues.append(f"Sample '{sample_id}' exact raw match in existing scripts/tests!")

        # Check cleaned match
        if cleaned in training_clean:
            issues.append(f"Sample '{sample_id}' cleaned match in training dataset.csv!")
        if cleaned in other_clean:
            issues.append(f"Sample '{sample_id}' cleaned match in existing scripts/tests!")

        # Token set Jaccard similarity > 0.70 check
        sample_tokens = set(re.findall(r"\w+", raw))
        if len(sample_tokens) > 5:
            for t_tokens in training_token_sets:
                if len(t_tokens) > 5:
                    intersection = len(sample_tokens & t_tokens)
                    if intersection / len(sample_tokens) > 0.80 and intersection / len(t_tokens) > 0.80:
                        jaccard = intersection / len(sample_tokens | t_tokens)
                        if jaccard > 0.75:
                            issues.append(
                                f"Sample '{sample_id}' has high Jaccard similarity ({jaccard:.2f}) with a training sample"
                            )
                            break

    return len(issues) == 0, issues


def run_evaluation() -> Dict[str, Any]:
    """Runs independent inference and calculates all standard metrics."""
    clf = PhishGuardClassifier(DEFAULT_MODEL_PATH)
    clf.load()

    y_true = []
    y_pred = []
    y_prob = []
    sample_results = []

    for s in INDEPENDENT_TEST_SET:
        pred_res = clf.predict(s["text"])
        tactics_res = analyze_tactics(s["text"])

        phish_prob = pred_res["calibrated_phish_probability"]
        pred_label = pred_res["prediction"]
        risk_level = pred_res["risk_level"]
        risk_score = pred_res["risk_score_index"]
        tactics_list = list(tactics_res.keys())

        y_true.append(s["label"])
        y_pred.append(pred_label)
        y_prob.append(phish_prob)

        sample_results.append({
            "id": s["id"],
            "category": s["category"],
            "true_label": s["label"],
            "predicted_label": pred_label,
            "calibrated_prob": round(phish_prob, 4),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "tactics": tactics_list,
            "is_correct": bool(s["label"] == pred_label),
        })

    # Metrics
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.0

    # Risk Tier Breakdown
    phish_samples = [r for r in sample_results if r["true_label"] == 1]
    legit_samples = [r for r in sample_results if r["true_label"] == 0]

    risk_tiers = {
        "phishing_high": sum(1 for r in phish_samples if r["risk_level"] == "High"),
        "phishing_medium": sum(1 for r in phish_samples if r["risk_level"] == "Medium"),
        "phishing_low": sum(1 for r in phish_samples if r["risk_level"] == "Low"),
        "legit_high": sum(1 for r in legit_samples if r["risk_level"] == "High"),
        "legit_medium": sum(1 for r in legit_samples if r["risk_level"] == "Medium"),
        "legit_low": sum(1 for r in legit_samples if r["risk_level"] == "Low"),
    }

    # Category Breakdown
    categories = sorted(list(set(s["category"] for s in INDEPENDENT_TEST_SET)))
    cat_summary = {}
    for cat in categories:
        cat_items = [r for r in sample_results if r["category"] == cat]
        total = len(cat_items)
        correct = sum(1 for r in cat_items if r["is_correct"])
        avg_prob = np.mean([r["calibrated_prob"] for r in cat_items])
        cat_summary[cat] = {
            "total": total,
            "correct": correct,
            "accuracy": round(correct / total, 4) if total > 0 else 0.0,
            "avg_probability": round(float(avg_prob), 4),
        }

    return {
        "sample_count": len(INDEPENDENT_TEST_SET),
        "phishing_count": len(phish_samples),
        "legit_count": len(legit_samples),
        "confusion_matrix": {
            "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "specificity": round(float(spec), 4),
            "roc_auc": round(float(auc), 4),
        },
        "risk_tiers": risk_tiers,
        "category_summary": cat_summary,
        "detailed_results": sample_results,
    }


if __name__ == "__main__":
    print("=====================================================================")
    print("   PhishGuard AI - Final Independent Evaluation Pipeline")
    print("=====================================================================")

    print("\n[Step 1] Verifying no data overlap with training set or existing regression tests...")
    no_overlap, issues = verify_no_overlap()
    if not no_overlap:
        print("[FAIL] OVERLAP DETECTED:")
        for iss in issues:
            print(f"  - {iss}")
        sys.exit(1)
    else:
        print("[OK] SUCCESS: 0 overlaps found across training dataset and test suites.")

    print("\n[Step 2] Executing independent inference across 50 out-of-distribution test cases...")
    eval_res = run_evaluation()

    m = eval_res["metrics"]
    cm = eval_res["confusion_matrix"]
    print("\n------------------------- EVALUATION METRICS -------------------------")
    print(f"Total Test Cases   : {eval_res['sample_count']} (Phish: {eval_res['phishing_count']}, Legit: {eval_res['legit_count']})")
    print(f"Accuracy           : {m['accuracy'] * 100:.2f}%")
    print(f"Precision          : {m['precision'] * 100:.2f}%")
    print(f"Recall             : {m['recall'] * 100:.2f}%")
    print(f"F1-Score           : {m['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate: {m['false_positive_rate'] * 100:.2f}% (FPR = FP / (FP + TN))")
    print(f"Specificity        : {m['specificity'] * 100:.2f}%")
    print(f"ROC-AUC            : {m['roc_auc']:.4f}")

    print("\n-------------------------- CONFUSION MATRIX --------------------------")
    print(f"                  Predicted Legit    Predicted Phish")
    print(f"  Actual Legit    TN = {cm['tn']:<14} FP = {cm['fp']:<14}")
    print(f"  Actual Phish    FN = {cm['fn']:<14} TP = {cm['tp']:<14}")

    print("\n------------------------ RISK TIER BREAKDOWN -------------------------")
    rt = eval_res["risk_tiers"]
    print(f"Phishing Samples (n={eval_res['phishing_count']}): High: {rt['phishing_high']}, Medium: {rt['phishing_medium']}, Low: {rt['phishing_low']}")
    print(f"Legitimate Samples (n={eval_res['legit_count']}): High: {rt['legit_high']}, Medium: {rt['legit_medium']}, Low: {rt['legit_low']}")

    print("\n----------------------- CATEGORY PERFORMANCE -------------------------")
    for cat, stats in eval_res["category_summary"].items():
        print(f"  {cat:<28} : {stats['correct']}/{stats['total']} ({stats['accuracy']*100:.1f}%) | Avg Prob: {stats['avg_probability']:.4f}")

    # Check for any misclassifications or borderline cases
    misclassifications = [r for r in eval_res["detailed_results"] if not r["is_correct"]]
    print(f"\nTotal Binary Misclassifications: {len(misclassifications)}")
    for item in misclassifications:
        print(f"  [MISCLASS] ID: {item['id']} [{item['category']}] | True: {item['true_label']} | Pred: {item['predicted_label']} | Prob: {item['calibrated_prob']} | Risk: {item['risk_level']} | Tactics: {item['tactics']}")

    # Save test set and results to JSON
    data_dir = os.path.join(WORKSPACE_DIR, "data")
    test_set_path = os.path.join(data_dir, "independent_test_set.json")
    results_path = os.path.join(data_dir, "independent_evaluation_results.json")

    with open(test_set_path, "w", encoding="utf-8") as f:
        json.dump(INDEPENDENT_TEST_SET, f, indent=2)
    print(f"\nSaved independent test set to: {test_set_path}")

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(eval_res, f, indent=2)
    print(f"Saved independent evaluation metrics to: {results_path}")
