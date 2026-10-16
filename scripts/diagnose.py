"""
Diagnostic script to test model predictions and identify weaknesses.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.model import PhishGuardClassifier, DEFAULT_MODEL_PATH
from src.tactics import analyze_tactics


def run_diagnostics():
    clf = PhishGuardClassifier(DEFAULT_MODEL_PATH)
    clf.load()

    test_cases = [
        # Legitimate emails
        ("legit_shipping", "Your Amazon order #112-9842145 has shipped via UPS. Expected delivery is Friday. Track package at official carrier site. Thank you for your purchase.", "legit"),
        ("legit_newsletter", "Weekly Engineering Digest: In this issue, we cover Python 3.13 performance improvements, new open source tools, and upcoming tech conferences. Read the articles on our tech blog.", "legit"),
        ("legit_calendar", "Invitation: Product Roadmap Sync @ Thu Oct 16, 2026 2pm - 3pm (sarah@company.com). Please find the video call link in the calendar invite.", "legit"),
        ("legit_pwd_reset", "You requested a password reset for your account. If you made this request, please follow the link below to set a new password. If you did not request this, you can safely ignore this email.", "legit"),
        ("legit_invoice", "Attached is invoice #4921 for professional consulting services rendered in September 2026. Payment terms are net 30. Thank you for your continued partnership.", "legit"),
        ("legit_bank_statement", "Your monthly account statement for checking account ending in 4102 is now ready to view in our online banking portal. Log in to your account at our official website.", "legit"),

        # Obvious phishing
        ("obvious_phish_1", "URGENT: Your account has been suspended! Click here immediately to verify your password and avoid permanent closure: http://fake-login-bank.com", "phish"),
        ("obvious_phish_2", "IRS Warning: You owe back taxes of $4,500. Legal action and arrest will occur within 24 hours if payment is not made via wire transfer or gift cards.", "phish"),
        ("obvious_phish_3", "CRITICAL ALERT: Your PayPal account has unauthorized transactions. Verify your identity now or account will be permanently blocked: http://paypaI-security.com", "phish"),

        # Subtle / Sophisticated phishing (often missed by basic n-gram bag-of-words models)
        ("subtle_payroll", "Hi HR, I need to update my direct deposit bank routing information before this Friday payroll cutoff. I attached the new voided check details.", "phish"),
        ("subtle_giftcard", "Are you at your desk right now? I need you to purchase 5 Apple gift cards of $100 each for a client gift presentation right away. Do not call me as I am in a board meeting.", "phish"),
        ("subtle_onedrive", "Sarah has shared a confidential document 'Q4_Executive_Compensation_Plan.pdf' with you on OneDrive. Click here to view document: http://onedrive-share-doc.ru/view", "phish"),
        ("subtle_docusign", "Please review and electronically sign 'Employment Contract Amendment 2026' sent via DocuSign. Completion required by end of business today: http://docusign-envelope-review.com", "phish"),
        ("subtle_quarantine", "You have 3 incoming emails held in quarantine server due to SPF mismatch. Release messages to your inbox: https://mail-quarantine-portal.net/release", "phish"),
        ("subtle_wire_transfer", "Please initiate an urgent wire transfer of $48,200 to the vendor account in the attached invoice before 4 PM today for the acquisition.", "phish"),

        # Out-of-Sample / Unseen Subtle Phishing & Legitimate Cases
        ("unseen_account_termination", "Your streaming subscription has expired. Click http://service-billing-portal.com to renew payment details immediately or account will be terminated.", "phish"),
        ("unseen_bank_2fa_harvest", "Security Alert: An unrecognized device signed in to your account. Enter your password and 2FA passcode at http://bank-device-verify.net to prevent permanent deactivation.", "phish"),
        ("unseen_bec_vendor_banking", "Hi Accounts Payable, Please be advised that our banking coordinates have changed due to our annual financial audit. Please route the upcoming invoice #84102 payment to our new account ending in 8831 instead of the old account.", "phish"),
        ("unseen_ceo_urgent_wire", "Hi, I am boarding a flight right now and cannot take calls. I need you to urgently wire $32,500 for the acquisition deposit to the escrow attorney details in the attached note before close of business.", "phish"),
        ("unseen_cloud_share_box", "Robert shared 'Q4_Compensation_and_Bonus_Review.xlsx' with you via Box Secure Storage. Tap here to review document and authenticate with your corporate SSO: http://box-corporate-preview.info/auth", "phish"),
        ("unseen_mfa_fatigue", "Duo Security: 12 failed authentication attempts detected from IP 84.15.22.1. Your corporate device token has expired. Verify your identity now: http://duo-verify-auth.org/login", "phish"),
        ("unseen_legit_maint", "Platform Maintenance Notice: Our cloud services will undergo scheduled infrastructure upgrades on Saturday between 01:00 and 03:00 UTC. No disruption to data access is anticipated. Thank you for your patience.", "legit"),
        ("unseen_legit_hr", "HR Team: Annual benefits open enrollment for health and dental plans starts next Monday. Informational webinar sessions are scheduled for Wednesday at 10 AM. Participation is completely optional.", "legit"),
    ]

    print(f"{'Case Name':<28} | {'Expected':<7} | {'Risk Level':<10} | {'Probability':<12} | {'Tactics Detected'}")
    print("-" * 95)

    fp_count = 0
    fn_count = 0

    for name, text, expected in test_cases:
        pred = clf.predict(text)
        tactics = list(analyze_tactics(text).keys())
        prob = pred["calibrated_phish_probability"]
        risk = pred["risk_level"]

        is_error = False
        if expected == "legit" and risk == "High":
            fp_count += 1
            is_error = True
        elif expected == "phish" and risk == "Low":
            fn_count += 1
            is_error = True

        flag = " [ERROR!]" if is_error else ""
        print(f"{name:<28} | {expected:<7} | {risk:<10} | {prob:<12.4f} | {', '.join(tactics) or 'None'}{flag}")

    print("-" * 95)
    print(f"Summary: {fp_count} False Positives (High Risk on Legit), {fn_count} False Negatives (Low Risk on Phish)")


if __name__ == "__main__":
    run_diagnostics()
