"""
Curated sample messages for PhishGuard AI demonstration and testing.
Provides diverse legitimate, subtle spear-phishing, cloud lure, security-sensitive, and obvious phishing email and SMS samples.
"""

from typing import Dict, List

SAMPLE_MESSAGES: List[Dict[str, str]] = [
    # 1. OBVIOUS PHISHING
    {
        "id": "phish_it_support",
        "category": "Obvious Phishing",
        "type": "Email",
        "title": "🚨 Impersonated IT Support (Account Suspension Threat)",
        "content": (
            "Subject: CRITICAL: Immediate Action Required - IT Helpdesk Security Notice\n\n"
            "Dear Employee,\n\n"
            "Our IT Department detected multiple unauthorized access attempts on your corporate workstation. "
            "As a result, your account will be suspended within 24 hours unless you verify your identity.\n\n"
            "You must act now to avoid permanent loss of access. Please click the link below to verify your "
            "password and confirm your login credentials immediately:\n\n"
            "https://it-support-portal-secure-verify.com/login?id=88319\n\n"
            "Failure to comply before 5:00 PM today will result in immediate termination of your email access "
            "and escalation to human resources.\n\n"
            "Sincerely,\n"
            "Global IT Security Team & System Administrator"
        ),
    },
    {
        "id": "phish_tax_threat",
        "category": "Obvious Phishing",
        "type": "Email",
        "title": "⚖️ IRS Law Enforcement Threat (Legal Action & Arrest)",
        "content": (
            "Subject: FINAL NOTICE: Legal Proceedings & Warrant Issued\n\n"
            "INTERNAL REVENUE SERVICE AUDIT DIVISION\n\n"
            "This is our final reminder regarding unresolved federal tax liability. A formal law enforcement notice "
            "and arrest warrant has been prepared under your Social Security Number.\n\n"
            "To prevent local police report filing and severe penalties, you must provide your bank account details "
            "and submit verification within 2 hours. Click below to pay the settlement fee immediately:\n\n"
            "http://irs-official-resolution-case.info/dispute"
        ),
    },
    {
        "id": "phish_bank_sms",
        "category": "Obvious Phishing",
        "type": "SMS",
        "title": "📱 Urgent Banking Smishing (Fraud Alert + 2FA Harvesting)",
        "content": (
            "URGENT ALERT from Chase Security: An unauthorized charge of $1,842.50 was flagged on your debit card. "
            "If you did not authorize this transaction, respond immediately or your account will be locked. "
            "Click here to verify your identity and enter your one-time passcode: https://chase-security-verify-alerts.com/auth"
        ),
    },

    # 2. SUBTLE SPEAR-PHISHING / BEC
    {
        "id": "subtle_bec_payroll",
        "category": "Subtle Phishing",
        "type": "Email",
        "title": "🕵️ BEC Payroll Diversion (Subtle Spear-Phishing)",
        "content": (
            "Subject: Direct Deposit Account Update - Routing Change\n\n"
            "Hi HR,\n\n"
            "I need to update my direct deposit bank routing information before this Friday payroll cutoff. "
            "My previous checking account was compromised and closed. I attached the new voided check details for account setup.\n\n"
            "Please confirm once updated so my upcoming paycheck transitions smoothly.\n\n"
            "Thanks,\n"
            "David Miller\n"
            "Senior Director of Engineering"
        ),
    },
    {
        "id": "subtle_ceo_giftcard",
        "category": "Subtle Phishing",
        "type": "Email",
        "title": "🎁 Executive Impersonation (CEO Urgent Gift Card Request)",
        "content": (
            "Subject: Quick task - are you at your desk?\n\n"
            "Are you at your desk right now? I need you to purchase 5 Apple gift cards of $100 each for a client gift presentation right away. "
            "Do not call me as I am in a board meeting. Once purchased, scratch the back and email the card codes here.\n\n"
            "I will submit the expense reimbursement directly to accounting this afternoon.\n\n"
            "Best,\n"
            "Mark\n"
            "Chief Executive Officer"
        ),
    },
    {
        "id": "subtle_cloud_doc",
        "category": "Subtle Phishing",
        "type": "Email",
        "title": "📑 Deceptive Cloud Document Lure (OneDrive / SharePoint)",
        "content": (
            "Subject: Sarah has shared a confidential document with you on OneDrive\n\n"
            "Sarah Jenkins (sjenkins@partner-consulting.org) has shared a confidential document 'Q4_Executive_Compensation_Plan.pdf' with you on OneDrive.\n\n"
            "Click here to view document: http://onedrive-share-doc.ru/view?token=99281\n\n"
            "This link will expire in 48 hours. Please do not forward this link to unauthorized personnel."
        ),
    },
    {
        "id": "subtle_docusign_lure",
        "category": "Subtle Phishing",
        "type": "Email",
        "title": "🖋️ E-Signature Deception (DocuSign Envelope Review)",
        "content": (
            "Subject: Please DocuSign: Employment Contract Amendment 2026\n\n"
            "DocuSign Security Service\n\n"
            "All parties have completed initial drafting. Please review and electronically sign 'Employment Contract Amendment 2026' sent via DocuSign. "
            "Completion required by end of business today: http://docusign-envelope-review.com\n\n"
            "Do not share this email. Access code is embedded in the link."
        ),
    },

    # 3. SECURITY-SENSITIVE / AMBIGUOUS NOTIFICATIONS
    {
        "id": "ambiguous_bank_statement",
        "category": "Security-Sensitive / Borderline",
        "type": "Email",
        "title": "🏦 Monthly Bank Statement Notification (Requires Out-of-Band Verification)",
        "content": (
            "Subject: Your monthly account statement is now ready\n\n"
            "Dear Customer,\n\n"
            "Your monthly statement for checking account ending in 4102 is now ready to view. "
            "To access your statement, sign in to your account at our official website or open our mobile banking app.\n\n"
            "Security Reminder: We will never ask you to send your password, PIN, or full account details via email.\n\n"
            "Thank you for choosing Chase Banking Services."
        ),
    },
    {
        "id": "ambiguous_pwd_reset",
        "category": "Security-Sensitive / Borderline",
        "type": "Email",
        "title": "🔒 Password Reset Notice (Common Dual-Use Lure)",
        "content": (
            "Subject: Password Reset Request for your Account\n\n"
            "Hello,\n\n"
            "We received a request to reset the password associated with this email address. "
            "If you made this request, please follow the link below to set a new password:\n\n"
            "https://auth.company-domain.com/account/reset?token=abc88921\n\n"
            "If you did not make this request, you can safely ignore this email. Your password will remain unchanged."
        ),
    },

    # 4. LEGITIMATE COMMUNICATIONS
    {
        "id": "legit_shipping_delivery",
        "category": "Legitimate Communication",
        "type": "Email",
        "title": "📦 Legitimate Shipment Tracking Update",
        "content": (
            "Subject: Your Amazon order #112-9842145 has shipped via UPS\n\n"
            "Hello Alex,\n\n"
            "Your recent order has shipped via UPS standard ground transit. The estimated delivery date is Friday, Oct 17. "
            "You can track the parcel progress directly through your official carrier tracking portal.\n\n"
            "Thank you for your purchase!"
        ),
    },
    {
        "id": "legit_meeting_sync",
        "category": "Legitimate Communication",
        "type": "Email",
        "title": "📅 Legitimate Corporate Meeting Summary & Roadmap",
        "content": (
            "Subject: Q3 Planning & Sprint Retrospective Notes\n\n"
            "Hi Team,\n\n"
            "Thank you everyone for attending this morning's sprint planning session. Attached are the meeting minutes and roadmap for Q3.\n\n"
            "Key takeaways:\n"
            "- Core feature deployment is targeted for next month.\n"
            "- Code review guidelines have been updated in the internal wiki.\n"
            "- Next weekly sync will be on Thursday at 10:00 AM in Conference Room B.\n\n"
            "Best regards,\n"
            "Sarah Jenkins\n"
            "Product Operations Manager"
        ),
    },
    {
        "id": "legit_casual_sms",
        "category": "Legitimate Communication",
        "type": "SMS",
        "title": "💬 Legitimate Personal SMS",
        "content": (
            "Hey Dave, are we still meeting at the coffee shop downtown around 3pm today? Let me know if that time works for you or if you'd rather reschedule for tomorrow."
        ),
    },
]
