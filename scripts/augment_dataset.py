"""
Enriches the training dataset with modern real-world phishing and legitimate communications.
Bridges the historical domain gap between 2001 Enron emails and contemporary email/SMS threats.
"""

import os
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DATASET_PATH = os.path.join(DATA_DIR, "dataset.csv")

# High-quality modern samples representing contemporary corporate and consumer communication
MODERN_SAMPLES = [
    # --- MODERN LEGITIMATE SAMPLES (label = 0) ---
    {
        "text": "Your monthly statement for account ending in 4102 is now ready to view. To access your statement, sign in to your account at our official website or open our mobile banking app. Thank you for choosing our banking services.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Your monthly account statement is now ready. Dear Customer, your monthly statement for checking account ending in 4102 is now ready to view. To access your statement, sign in to your account at our official website or open our mobile banking app. Security Reminder: We will never ask you to send your password, PIN, or full account details via email. Thank you for choosing Chase Banking Services.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Chase Online Banking Notification: Your electronic statement for checking account ending in 9812 is available. Log in securely to your online banking profile to review your transaction history. We will never ask you for your password via email.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Bank of America customer alert: Your paperless statement for account ending in 5519 is ready. Sign in to Online Banking to review your statement.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Wells Fargo notification: Your online statement is now available for your credit card ending in 7104. View balances and payment due dates in your mobile app.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Citibank alert: Your e-statement for savings account ending in 3381 has been generated. You can download and review your monthly statements in Citi Online.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Monthly account summary: Your credit card statement ending in 3044 has been generated. Balance: $214.50, Payment Due Date: Nov 12. View full statement in your portal.",
        "label": 0,
        "source": "modern_legit_banking",
    },
    {
        "text": "Electric utility e-bill: Your monthly power bill of $84.20 is now available. Log in to your customer portal to view daily energy consumption and payment options.",
        "label": 0,
        "source": "modern_legit_utility",
    },
    {
        "text": "Your Amazon order #112-9842145 has shipped via UPS. Expected delivery is Friday. Track package at official carrier tracking page. Thank you for your purchase.",
        "label": 0,
        "source": "modern_legit_shipping",
    },
    {
        "text": "UPS Tracking Update: Your package from REI Co-op is scheduled for delivery tomorrow between 1:00 PM and 5:00 PM. No signature required.",
        "label": 0,
        "source": "modern_legit_shipping",
    },
    {
        "text": "FedEx Shipment Delivery Confirmation: Parcel #7829104821 was delivered to front porch on Wednesday at 2:15 PM.",
        "label": 0,
        "source": "modern_legit_shipping",
    },
    {
        "text": "Weekly Engineering Digest: In this issue, we cover Python 3.13 performance improvements, new open source tools, and upcoming tech conferences. Read the articles on our tech blog.",
        "label": 0,
        "source": "modern_legit_newsletter",
    },
    {
        "text": "DevOps Monthly Roundup: Best practices for Kubernetes cluster auto-scaling, container security hardening, and observability dashboards. Enjoy the read!",
        "label": 0,
        "source": "modern_legit_newsletter",
    },
    {
        "text": "Invitation: Product Roadmap Sync @ Thu Oct 16, 2026 2pm - 3pm (sarah@company.com). Please find the video call link in the calendar invite.",
        "label": 0,
        "source": "modern_legit_calendar",
    },
    {
        "text": "Accepted: Sprint 42 Retrospective & Demo with Engineering and Design teams @ Friday 11:00 AM.",
        "label": 0,
        "source": "modern_legit_calendar",
    },
    {
        "text": "You requested a password reset for your account. If you made this request, please follow the link below to set a new password. If you did not request this, you can safely ignore this email and your password will remain unchanged.",
        "label": 0,
        "source": "modern_legit_auth",
    },
    {
        "text": "Security notification: Your account password was successfully updated on Oct 14, 2026 from Chrome on Windows. If this was you, no action is needed.",
        "label": 0,
        "source": "modern_legit_auth",
    },
    {
        "text": "Attached is invoice #4921 for professional consulting services rendered in September 2026. Payment terms are net 30. Thank you for your continued partnership.",
        "label": 0,
        "source": "modern_legit_invoice",
    },
    {
        "text": "Receipt for your subscription payment: Your receipt #INV-88392 for Cloud Hosting Services ($49.00/mo) is now paid. Thank you for your business.",
        "label": 0,
        "source": "modern_legit_invoice",
    },
    {
        "text": "GitHub notification: Pull Request #142 'Refactor authentication middleware' was approved and merged into main by alex-dev.",
        "label": 0,
        "source": "modern_legit_work",
    },
    {
        "text": "Jira Service Desk: Ticket SEC-9281 'Update SSL certificate on staging cluster' has been moved to Status: Done.",
        "label": 0,
        "source": "modern_legit_work",
    },
    {
        "text": "HR Benefits Reminder: Open enrollment for next fiscal year begins next Monday. Informational webinar sessions will be held on Wednesday at 10 AM. Attendance is optional.",
        "label": 0,
        "source": "modern_legit_hr",
    },
    {
        "text": "Company All-Hands Meeting: Join CEO and executive leadership this Thursday at 3:00 PM for the quarterly business review. Submit questions via Slido.",
        "label": 0,
        "source": "modern_legit_company",
    },
    {
        "text": "Hi team, please find attached the meeting minutes and action items from today's architecture review. Please review section 3 before tomorrow's follow-up.",
        "label": 0,
        "source": "modern_legit_team",
    },
    {
        "text": "Hey everyone, lunch will be catered in the 4th floor cafeteria today starting at 12:30 PM. Vegetarian and gluten-free options are available.",
        "label": 0,
        "source": "modern_legit_casual",
    },
    {
        "text": "Thanks for your inquiry regarding our API documentation. You can find our complete SDK references and code examples on our developer portal.",
        "label": 0,
        "source": "modern_legit_support",
    },
    # Legitimate Banking Fraud Alerts & Transaction Verification SMS (Dual-Use Benign)
    {
        "text": "Fraud Alert: Did you attempt a $45.20 purchase at Target? Reply YES or NO. We will never ask for your card number or PIN.",
        "label": 0,
        "source": "modern_legit_banking_sms",
    },
    {
        "text": "Chase Fraud Alert: Did you recognize a charge of $84.50 at Shell Oil? Reply YES or NO. If NO, your card will be blocked and we will issue a replacement. Never share your passcode.",
        "label": 0,
        "source": "modern_legit_banking_sms",
    },
    {
        "text": "Bank of America Alert: Did you authorize a transaction of $150.00 at Best Buy? Reply 1 for YES, 2 for NO. We will not ask for your account credentials.",
        "label": 0,
        "source": "modern_legit_banking_sms",
    },
    {
        "text": "Wells Fargo Security: Unusual activity detected for $29.99 at Netflix. Reply YES if this was you or NO to dispute. We will never ask for your online banking password.",
        "label": 0,
        "source": "modern_legit_banking_sms",
    },
    {
        "text": "Citi Cards: Did you attempt a charge of $62.15 at Grocery Store? Reply YES or NO. FreeMsg. Never disclose full card details.",
        "label": 0,
        "source": "modern_legit_banking_sms",
    },

    # --- MODERN LEGITIMATE SECURITY ALERTS & NOTIFICATIONS (label = 0) ---
    {
        "text": "GitHub Security Alert: A new SSH public key (id_ed25519_work) was added to your account from IP 192.0.2.45 on macOS. If you added this key, no action is needed. You can review all authorized keys in your GitHub account settings.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "AWS Budget Alert: Your AWS account monthly spend for October has reached 85% of your forecasted budget threshold ($850.00 of $1,000.00). Review your active resource usage and cost allocation tags in AWS Cost Explorer.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Slack Security Notice: Your workspace session has been refreshed following our quarterly single sign-on policy update. No action is required. Review connected workspace applications in your profile settings.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Google Cloud IAM Notification: Role 'Storage Object Viewer' was granted to service account telemetry-collector@prod-project.iam.gserviceaccount.com by admin@company.com in project 'prod-data-pipeline'.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Okta System Notice: Your corporate password was successfully updated via self-service portal on October 14, 2026. If you performed this change, please disregard this notice. For assistance, contact your internal systems administrator.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Corporate VPN Advisory: Cisco AnyConnect client version 5.1 deployment is now complete across all managed gateways. Remote users will automatically receive the updated profile upon next successful login.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Cloudflare Security: The universal SSL/TLS certificate for your zone api.company.io has been automatically renewed and deployed to edge nodes. Encryption status: Active. No downtime occurred.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Microsoft Entra ID: Multi-Factor Authentication method Microsoft Authenticator was registered for employee account user@organization.com. If this was authorized by you, no further action is necessary.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "1Password Security Alert: A new web vault login was recorded from Firefox on Linux in Chicago, IL. If you authorized this sign-in, you can safely ignore this notification.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Security Operations Center: The quarterly scheduled network vulnerability scan for corporate subnet 10.100.0.0/16 will run tonight between 11 PM and 1 AM. No network interruption is expected.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "GitLab Notification: Dependabot resolved 2 low-severity dependency vulnerabilities in repository backend-services via automated merge request #819.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Duo Security Notice: The Duo Mobile application on your mobile device was updated to version 4.5. Biometric authentication remains enabled. No configuration changes required.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "IT Infrastructure Advisory: Root certificate authority update for corporate 802.1X wireless networks has been distributed to all domain-joined laptops via group policy.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Google Workspace Security: 2-Step Verification backup codes were generated for your account. Store your printable codes in a secure location. You can view security settings anytime in your account dashboard.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Chase Security Alert: An online banking session was opened from a recognized browser. If this was you, no response is needed. We will never ask for your password or PIN in an email.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Apple ID Notice: Your Apple Account was used to sign in to iCloud on a Mac Studio. If this was you, no action is required. View your registered trusted devices in System Settings.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Palo Alto Networks Cortex: Endpoint protection definitions have been updated to revision 8912. All host sensors report healthy status.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Bank of America Fraud Text: FreeMsg BofA: Did you attempt $82.40 at Shell on card ending in 4102? Reply Y for Yes, N for No. We will never text asking for your passcode or PIN.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "Citibank Alert: Account alert for card ending 9920. A purchase of $15.20 was authorized at Starbucks. Manage real-time charge notifications in the Citi Mobile app.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },
    {
        "text": "CrowdStrike Falcon Sensor: Scheduled weekly malware quarantine cleanup completed on endpoint DESKTOP-4921. Zero active threats detected.",
        "label": 0,
        "source": "modern_legit_security_alert",
    },

    # --- MODERN LEGITIMATE BILLING, RECEIPTS & FINANCIAL NOTICES (label = 0) ---
    {
        "text": "Receipt from Zoom Video Communications via Stripe: Payment of $149.90 for 10 Zoom Workplace Pro monthly user licenses was charged to Mastercard ending in 8812 on Oct 10, 2026. Your paid tax invoice is accessible in your Zoom billing dashboard.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Slack Technologies Invoice Paid: Thank you for your payment of $360.00 for your annual Standard plan subscription. Transaction reference: SLACK-INV-99214. Card charged: Visa ending in 4021.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Atlassian Billing Notification: Your subscription for Confluence Standard ($220.00/month) has renewed for November. Payment processed successfully via stored corporate card. Manage subscriptions in admin console.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Datadog Invoice Notification: Your monthly cloud infrastructure monitoring statement for September ($640.25) is now available. Download itemized PDF invoice in your billing organization portal.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "AWS Billing Statement: Your Amazon Web Services invoice for billing period September 2026 has been finalized. Total amount: $312.48. Automatic payment will be debited from card on file.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Figma Team Plan Receipt: Your payment of $180.00 for 12 Figma Design seats was successfully processed. View past billing history and payment methods in your team admin panel.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "American Express Card Statement: Your monthly card statement for account ending in 3009 is ready. Minimum payment of $40.00 due on November 8. Sign in to your account at americanexpress.com to view transactions.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Discover Card Notification: Cashback Bonus summary for Q3 is available. Your statement balance for card ending in 1948 has been posted. View details securely in your Discover mobile application.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Standard B2B Invoice: Attached is invoice #INV-2026-881 for IT hardware maintenance services. Payment terms are net 30 days. Remittance address remains unchanged. Thank you for your prompt payment.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "SAP Concur Expense Notification: Your expense report 'Client Engagement Meals Q3' ($384.50) has been audited and approved by Finance. Payment will be disbursed via direct deposit within 3 business days.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "QuickBooks Online Invoice: Invoice #1042 for legal research consulting ($1,500.00) from Sterling Legal Advisory has been marked as PAID. A receipt has been saved to your company records.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "NetSuite ERP Purchase Order: Purchase Order PO-91204 has been approved by the department director. Vendor dispatch authorization has been issued to Accounts Payable.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Duke Energy E-Bill Notice: Your electric service statement for account ending in 7712 is available. Amount due: $94.30 on Nov 05. Auto-pay scheduled. Sign in to your utility portal for energy efficiency tips.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Fidelity Investments Notice: Your quarterly 401(k) retirement portfolio statement for period ending September 30 is now available online. Log into NetBenefits to view asset allocation and employer match.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Accounts Payable Confirmation: Voucher #55192 for office supplies vendor payment ($412.00) was issued via scheduled electronic ACH. Check remittance copy available on internal accounting drive.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "GitHub Enterprise Cloud Billing: Monthly seat usage for 25 developer licenses ($525.00) billed to corporate card ending in 6610. Download invoice PDF in GitHub billing settings.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "HubSpot Receipt: Payment for HubSpot Sales Hub Professional ($500.00/mo) completed successfully. Next renewal date is November 14, 2026. Manage billing information in portal.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Corporate Payroll Notice: Semi-monthly payroll for period ending Oct 15 has been processed. Total direct deposits released to financial institutions. Payslips available in Workday.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "DocuSign Commercial Subscription: Receipt for annual corporate agreement ($1,200.00) charged to corporate Visa ending in 1928. View agreement terms in DocuSign administration.",
        "label": 0,
        "source": "modern_legit_billing",
    },
    {
        "text": "Stripe Billing Statement: Monthly platform merchant processing fee invoice ($45.20) generated for account acct_881920. Funds settled against daily payout balance.",
        "label": 0,
        "source": "modern_legit_billing",
    },

    # --- MODERN PHISHING SAMPLES (label = 1) ---
    # 1. BEC & Payroll Diversion
    {
        "text": "Hi HR, I need to update my direct deposit bank routing information before this Friday payroll cutoff. I attached the new voided check details. Please confirm once updated.",
        "label": 1,
        "source": "modern_phish_bec_payroll",
    },
    {
        "text": "Hello Payroll, can you please change my banking account for my direct deposit? My old bank account was closed. Send me the direct deposit authorization form or update it directly with the attached routing number.",
        "label": 1,
        "source": "modern_phish_bec_payroll",
    },
    {
        "text": "Urgent payroll request: Please process an off-cycle direct deposit update for employee ID 4821. Bank routing number 021000021, Account 982103481. Must take effect immediately.",
        "label": 1,
        "source": "modern_phish_bec_payroll",
    },
    # 2. Executive / CEO Gift Card Fraud
    {
        "text": "Are you at your desk right now? I need you to purchase 5 Apple gift cards of $100 each for a client gift presentation right away. Do not call me as I am in a board meeting. Email the card codes here.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Quick task: I am in a conference meeting and need a favor. Could you buy 4 Google Play gift cards of $200 each for vendor appreciation? Scratch the back and send photos of the pins ASAP. I will reimburse you.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Are you available? I am tied up in executive interviews all day. Need you to discreetly pick up Steam gift cards for the partner gifts. Let me know when you can head out.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Are you at your desk? Need you to pick up Apple gift cards for the executive meeting today. Scratch the back and send me the card codes. I will have accounting reimburse you immediately.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Quick favor: Please purchase 5 Apple gift cards of $100 each right away for client gifts. Send the card codes here and submit reimbursement to accounting.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Urgent request from CEO: Need you to buy Apple gift cards for employee incentives before 4 PM. Email the claim codes once purchased. Will reimburse via payroll.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    {
        "text": "Are you available? Please purchase physical Apple gift cards and email the card codes here ASAP. I am in meetings all day. Expense reimbursement will be processed this afternoon.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    # 3. Cloud Document Phishing (OneDrive, SharePoint, Google Drive, Dropbox)
    {
        "text": "Sarah has shared a confidential document 'Q4_Executive_Compensation_Plan.pdf' with you on OneDrive. Click here to view document: http://onedrive-share-doc.ru/view?token=8921",
        "label": 1,
        "source": "modern_phish_cloud_doc",
    },
    {
        "text": "Microsoft SharePoint Security: Human Resources has shared 'Employee_Termination_List_2026.xlsx' with you. Access document securely: http://sharepoint-auth-login.net/docs",
        "label": 1,
        "source": "modern_phish_cloud_doc",
    },
    {
        "text": "Google Drive Alert: An encrypted PDF 'Q3_Financial_Audit_Report.pdf' has been shared with you. Sign in with your work email to decrypt: http://drive-google-auth-verify.com/login",
        "label": 1,
        "source": "modern_phish_cloud_doc",
    },
    {
        "text": "Dropbox File Transfer: 2 files (total 14.8 MB) 'Contract_Specification.pdf' were sent to your email. Click here to download files before link expires in 24 hours.",
        "label": 1,
        "source": "modern_phish_cloud_doc",
    },
    # 4. E-Signature / DocuSign Phishing
    {
        "text": "Please review and electronically sign 'Employment Contract Amendment 2026' sent via DocuSign. Completion required by end of business today: http://docusign-envelope-review.com",
        "label": 1,
        "source": "modern_phish_docusign",
    },
    {
        "text": "DocuSign Security Service: You have 1 pending document awaiting signature from Managing Director. View and sign envelope: http://docusign-secure-portal.click/sign",
        "label": 1,
        "source": "modern_phish_docusign",
    },
    {
        "text": "Adobe Sign: Please sign 'Non-Disclosure Agreement & Partner Protocol'. Failure to sign before 5 PM will delay contract execution. Tap here to review document.",
        "label": 1,
        "source": "modern_phish_docusign",
    },
    # 5. Mail Server & Quarantine Lures
    {
        "text": "You have 3 incoming emails held in quarantine server due to SPF mismatch. Release messages to your inbox: https://mail-quarantine-portal.net/release",
        "label": 1,
        "source": "modern_phish_quarantine",
    },
    {
        "text": "IT Alert: 5 unread messages are delayed on the mail gateway due to storage quota exceeded. Upgrade storage or release messages immediately: http://mail-quota-admin.org",
        "label": 1,
        "source": "modern_phish_quarantine",
    },
    {
        "text": "Exchange Admin: Incoming emails from key clients were blocked by spam filter. Verify your credentials to whitelist sender and release blocked emails.",
        "label": 1,
        "source": "modern_phish_quarantine",
    },
    # 6. Urgent Wire Transfer / Financial Diversion
    {
        "text": "Please initiate an urgent wire transfer of $48,200 to the vendor account in the attached invoice before 4 PM today for the acquisition. Ensure this is confidential.",
        "label": 1,
        "source": "modern_phish_wire",
    },
    {
        "text": "URGENT PAYMENT: Wire transfer instructions for closing settlement #8819. Transfer $125,000 to new escrow account immediately to meet closing deadline.",
        "label": 1,
        "source": "modern_phish_wire",
    },
    # 7. Modern Account Suspension / 2FA Theft
    {
        "text": "Microsoft 365 Alert: Unusual sign-in activity detected from Moscow, Russia. Your session has been revoked. Verify your password and 2FA code immediately to prevent account closure: http://microsoft-auth-sec.com",
        "label": 1,
        "source": "modern_phish_m365",
    },
    {
        "text": "Okta Verify Notification: Your Multi-Factor Authentication token has expired. Re-authenticate your corporate device now to avoid access revocation: http://okta-sso-verify.org",
        "label": 1,
        "source": "modern_phish_m365",
    },
    {
        "text": "Apple Support Alert: Your Apple ID was used to purchase an iPhone 16 Pro Max ($1,299). If you did not make this purchase, cancel transaction immediately at http://appleid-cancel-order.net",
        "label": 1,
        "source": "modern_phish_brand",
    },
    {
        "text": "PayPal Fraud Alert: An unauthorized withdrawal of $850.00 was attempted. If this was not authorized by you, click here to dispute transaction and freeze card.",
        "label": 1,
        "source": "modern_phish_brand",
    },
    {
        "text": "Chase Alert: Suspicious transaction of $2,100 at Target flagged. Reply YES if authorized or click http://chase-mobile-sec.com/verify to lock debit card.",
        "label": 1,
        "source": "modern_phish_sms",
    },
    {
        "text": "IRS Law Enforcement Notice: A tax fraud warrant has been filed against your SSN. Call 1-800-555-0199 or submit wire settlement within 2 hours to avoid local sheriff dispatch.",
        "label": 1,
        "source": "modern_phish_threat",
    },
    # 8. Vendor Banking Details & IBAN Diversion
    {
        "text": "Hi team, please find attached invoice #4920 for last month services. Note our bank details have changed to New Horizon Bank IBAN GB29NWBK60161331926819. Please process payment today.",
        "label": 1,
        "source": "modern_phish_vendor_bank_change",
    },
    {
        "text": "Notice of Updated Banking Information: For all outstanding invoices, please remit payment to our new corporate account IBAN DE89370400440532013000. Do not use the old banking details.",
        "label": 1,
        "source": "modern_phish_vendor_bank_change",
    },
    # 9. IT Helpdesk MFA Push / Fatigue
    {
        "text": "Hi Sarah, this is Kevin from internal IT Helpdesk. We are performing mandatory security updates on your workstation. A Duo MFA push was just sent to your phone, please approve it so we can complete setup.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "IT Service Desk: Mandatory Duo Security sync required for corporate network access. An MFA prompt was sent to your authenticator app, please approve immediately.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "Internal IT Helpdesk Notice: We are deploying security patches to your machine. Please approve the Duo MFA push notification sent to your registered phone to allow the technician to finish.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "IT Support Desk: A multi-factor authentication (MFA) push approval request was generated for your corporate account. Please tap approve on your Duo Mobile app to complete identity verification.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "Duo Security Push Notification: Urgent login authorization requested by IT Administrator. Please approve MFA push prompt on your smartphone to prevent account suspension.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    # 10. Paraphrased Payroll & Gift Cards
    {
        "text": "Hello payroll office, could you kindly swap my monthly salary direct transfer account to my new credit union account before next payroll cycle? Let me know what paperwork is needed.",
        "label": 1,
        "source": "modern_phish_bec_payroll",
    },
    {
        "text": "Quick favor - I am currently tied up in a client conference and unable to step out. Can you quickly grab several electronic store vouchers for the team reward? I will reimburse you.",
        "label": 1,
        "source": "modern_phish_giftcard",
    },
    # 11. Subtle Business Email Compromise & Executive Wire Requests (label = 1)
    {
        "text": "Subject: Confidential Financial Transaction - Board Approved\n\nGood morning, I need you to handle a time-sensitive financial transaction for an off-market partnership. I'm tied up in regulatory depositions all day so please keep this discrete. How soon can you process an outbound domestic wire of $65,000? I will forward the wire instructions.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Urgent legal retainer wire - M&A counsel\n\nHi, are you at your computer? We have an urgent settlement agreement closing with our European distributor. Please prepare an international transfer of €38,000 to the attorney escrow account listed in the memo before 2 PM today. Keep this confidential until announced.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Emergency expense stipend - Frankfurt travel\n\nHi Finance, my flight was diverted to Frankfurt and my corporate debit card is locked by fraud protection. I need an emergency travel advance of $4,200 wired to my personal Revolut account immediately so I can pay hotel and alternate flights. Routing details attached.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Quick favor for executive summit\n\nAre you available right now? I am facilitating our quarterly leadership summit and cannot step out. Could you quickly buy 6 Best Buy electronic gift cards of $100 each for the guest presenters? Scratch the back and reply with the gift card numbers and PINs. I will approve reimbursement tonight.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Immediate Wire Transfer - Project Titan Retainer\n\nPlease initiate an outbound wire transfer of $52,000 to our external counsel trust account before the 3 PM wire window closes. This is for the confidential patent settlement discussed yesterday. Do not discuss with others on the team.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Airport emergency - wire transfer needed\n\nHi Accounting team, I am stranded in Zurich due to a delayed connection and need an emergency wire of $3,800 sent to my Wise multicurrency account right away for local transport and lodging expenses. I will file the receipts upon return on Monday.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: PwC Audit Inquiry - Liquidity Validation\n\nDear Finance team, As part of our interim statutory audit, PwC requires immediate verification of our operational cash accounts. Please reply urgently with our primary operating balances and wire routing numbers for validation.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Urgent confidential acquisition wire\n\nDavid, please process an urgent escrow wire of $92,000 to the title attorney account in the attached letter. The board approved the acquisition terms this morning. Must be completed before end of banking day.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Quick task before meeting\n\nAre you at your desk? I need 4 Apple gift cards of $200 each for client gifts before my 1 PM meeting. Please pick these up immediately and email the redemption codes here. I will have accounting reimburse you.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },
    {
        "text": "Subject: Vendor legal settlement escrow wire\n\nHi Accounting, We need to wire $45,000 for the vendor settlement escrow account by 4:00 PM today. Please initiate the wire using the banking coordinates in the attached memo.",
        "label": 1,
        "source": "modern_phish_subtle_bec",
    },

    # 12. Payment Diversion & Supplier Remittance Modifications (label = 1)
    {
        "text": "Subject: Updated Remittance Instructions - Vanguard Logistics\n\nDear Accounts Payable, Please be advised that our company has transitioned our primary commercial banking to JPMorgan Chase. Moving forward, please update our vendor profile in your ERP system to route all pending and future disbursements for Vanguard Logistics to our new account ending in 7741. Updated ACH details attached.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Revised Bank Coordinates for Invoice #49102\n\nHello Accounting, Regarding the upcoming payment for PO-84920: Our main operating account is undergoing a mid-year financial audit. Please remit this invoice balance of $54,300 to our auxiliary account at KeyBank instead of our standard account. Please confirm once scheduled.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Direct deposit banking change request\n\nHello Payroll team, I would like to update my direct deposit bank account information starting with the next pay run on the 15th. I have attached the direct deposit change form and voided check for my new credit union account ending in 8192. Please confirm once updated.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: International Wire Redirect - Conveyor Systems PO #8102\n\nAttention Finance Department: For invoice #77291 regarding the conveyor equipment shipment, please note our clearing bank has updated our SWIFT code and IBAN coordinates to DE89370400440532013000. Do not send to our previous account. Wire confirmation required before shipment releases.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Updated ACH details for upcoming disbursements\n\nDear Accounts Payable, Please note our new banking instructions for upcoming invoice payments. Our primary account has changed to Wells Fargo Commercial Banking. Please update your vendor records with the attached W-9 and voided check before processing payments this week.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Payroll account update for upcoming cycle\n\nHi HR Department, Can you please swap my monthly salary direct transfer account to my new savings account ending in 3319 before the payroll deadline? Attached is my voided check details.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Urgent: Change in remittance bank account\n\nHello Accounts Payable, Due to our annual banking consolidation, please route all future wire payments to our new commercial checking account ending in 9042. Updated remittance advice and bank confirmation attached.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Escrow Wire Instructions Modification - Property Closing\n\nDear Buyer, Please note that the escrow closing wire instructions for file #4892 have been revised by the title company. Do not use the previous banking coordinates. Wire the balance of $48,250 to the updated title escrow account detailed in the attached PDF.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Refund payment wire instructions\n\nDear Billing Department, Regarding the overpayment on invoice #3819 ($12,400.00): Our CFO requires an immediate wire transfer refund to our operating account rather than a credit memo. Please process to the attached bank account within 48 hours.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },
    {
        "text": "Subject: Supplier banking details change notice\n\nDear Customer, Please update your accounting records. Effective immediately, all payments for Apex Industrial must be sent to our new Citibank treasury account IBAN GB29NWBK60161331926819. Disregard previous account details.",
        "label": 1,
        "source": "modern_phish_payment_diversion",
    },

    # 13. MFA Fatigue, Session Theft & Modern Lures (label = 1)
    {
        "text": "Okta Single Sign-On: Unusual authentication prompt looping detected from unknown IP. Re-verify your active device token immediately to restore access: http://okta-session-verify.net",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "Microsoft 365 Security: Authenticator push verification timeout. You have 2 pending approval prompts. Enter your verification code at https://m365-authenticator-portal.com to prevent session revocation.",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "Duo Security Push: Multiple denied logins from Frankfurt, Germany. Tap here to lock your corporate credentials and generate a temporary one-time passcode: http://duo-lockout-auth.org",
        "label": 1,
        "source": "modern_phish_mfa_push",
    },
    {
        "text": "Hey, I uploaded our preliminary product wireframes to the collaborative Miro workspace. Please review and add comments before our design review: http://miro-workspaces-preview.net/board",
        "label": 1,
        "source": "modern_phish_lure",
    },
    {
        "text": "Greenhouse Recruitment: We reviewed your resume for the Lead Infrastructure Engineer position ($195k). Please schedule your interview and verify your portfolio here: https://greenhouse-talent-portal.cc",
        "label": 1,
        "source": "modern_phish_lure",
    },
]


def augment_dataset():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Base dataset not found at {DATASET_PATH}")

    df_base = pd.read_csv(DATASET_PATH)
    print(f"[*] Base dataset samples: {len(df_base)}")

    # Create DataFrame from modern samples
    df_modern = pd.DataFrame(MODERN_SAMPLES)
    print(f"[*] Adding {len(df_modern)} modern calibrated samples...")

    # Combine and deduplicate
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from src.preprocessing import clean_text

    df_combined = pd.concat([df_base, df_modern], ignore_index=True)
    df_combined["text"] = df_combined["text"].astype(str).str.strip()
    clean_keys = df_combined["text"].apply(clean_text)
    df_combined = df_combined.loc[~clean_keys.duplicated()].reset_index(drop=True)

    df_combined.to_csv(DATASET_PATH, index=False)
    print(f"[+] Successfully augmented dataset. Total samples now: {len(df_combined):,}")
    print(f"    - Legitimate: {(df_combined['label'] == 0).sum():,}")
    print(f"    - Phishing/Spam: {(df_combined['label'] == 1).sum():,}")


if __name__ == "__main__":
    augment_dataset()
