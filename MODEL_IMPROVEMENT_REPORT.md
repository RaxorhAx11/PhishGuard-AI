# PhishGuard AI - Model Improvement & Retraining Report

**Date:** October 15, 2026  
**Focus:** Targeted reduction of False Positives on Legitimate Security & Billing notices, and False Negatives on Subtle BEC & Payment Diversion attacks.

---

## 1. Executive Summary

Following the diagnostic findings in [`INDEPENDENT_EVALUATION_REPORT.md`](file:///d:/PhishGuard%20AI/INDEPENDENT_EVALUATION_REPORT.md), an end-to-end model improvement cycle was executed on PhishGuard AI. 

### Key Improvements Achieved:
1. **Recall on Independent Attacks:** Increased from **88.00% to 100.00%** (0 false negatives on the 25 independent attacks).
2. **False Positive Rate:** Slashed from **28.00% down to 8.00%** on the independent benchmark.
3. **Subtle BEC Accuracy:** Increased from **60.0% to 100.0%**.
4. **Payment Diversion Accuracy:** Increased from **80.0% to 100.0%**.
5. **Legitimate Billing Accuracy:** Increased from **50.0% to 100.0%**.
6. **Legitimate Security Alerts Accuracy:** Increased from **42.9% to 71.4%**.
7. **Fresh Out-of-Distribution Validation:** Verified on a brand-new, unseen 30-sample benchmark, achieving **90.00% Accuracy, 100.00% Recall, and 1.0000 ROC-AUC**.

---

## 2. Dataset Gap Analysis & Augmentation Strategy

### What was missing in the baseline dataset?
- **Domain Gap in Legitimate Data:** The original training corpus consisted almost entirely of legacy Enron emails (2001) and SMS spam (2012). Legitimate automated cloud notifications (Slack session notices, GitHub personal access tokens, AWS CloudTrail alerts, 2-Step Verification confirmations, Stripe SaaS receipts, Workday payslips) did not exist in those collections. Consequently, terms like `token`, `IP`, `sign-in`, `2-Step`, `receipt`, `Stripe`, and `invoice` had an overwhelming statistical correlation with malicious spam.
- **Missing Modern Conversational BEC & Payment Diversion:** Attackers conducting CEO impersonation, legal retainer requests, and supplier ACH changes write in formal, professional B2B English without malware links or overt threats. The baseline model lacked balanced training pairs representing these conversational financial attacks.
- **Feature Scaling Issue in `ThreatFeatureExtractor`:** Unscaled `log1p(text_len)` feature had a large coefficient (~+1.0) because in the legacy dataset, emails were longer than SMS. This added up to +5.7 to the logit, pushing any email longer than 200 characters towards phishing. Normalizing this feature to $[0, 1]$ removed this artificial length penalty.

### Balanced Augmentation Added to `scripts/augment_dataset.py`:
- **40 Modern Legitimate Messages (Label = 0):**
  - Modern Cloud & Developer Security Alerts: GitHub SSH keys/PATs, AWS Cost Explorer/CloudTrail, Slack session updates, Okta password confirmations, Google Cloud IAM notifications, Cisco VPN deployment notices, 1Password logins, Dependabot PRs, Cloudflare SSL renewals.
  - Modern SaaS Billing & Receipts: Zoom via Stripe receipts, Slack annual subscription invoices, Atlassian Confluence renewals, Datadog infrastructure statements, AWS finalized billing, SAP Concur expense approvals, QuickBooks paid invoices, Duke Energy e-bills, Fidelity 401(k) statements.
- **35 Modern Phishing Messages (Label = 1):**
  - Subtle BEC: Board-approved acquisition escrow wires, confidential M&A outside counsel retainers, airport emergency travel stipends (Revolut/Wise), offsite summit gift cards, PwC/EY liquidity audit inquiries.
  - Payment Diversion: Supplier ERP vendor banking updates, payroll direct deposit routing changes to credit unions, international machinery SWIFT/IBAN redirects, title company property closing escrow wire updates, overpayment wire refund demands.
  - Modern Lures & MFA Fatigue: JumpCloud directory push loops, Microsoft Entra number-matching prompts, collaborative Figma workspace phishing lures, Greenhouse recruitment interview phishing.

All new samples are 100% distinct from both the independent test set and the fresh validation set (verified by automated zero-leakage checks).

---

## 3. Before vs. After Comparison on the Independent Test Set (N = 50)

Both evaluations were executed against the exact same 50 unseen samples in [`data/independent_test_set.json`](file:///d:/PhishGuard%20AI/data/independent_test_set.json).

### Core Metrics Comparison

| Metric | Before Retraining | After Retraining | Absolute Change |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 80.00% (40/50) | **96.00% (48/50)** | **+16.00%** |
| **Precision** | 75.86% (22/29) | **92.59% (25/27)** | **+16.73%** |
| **Recall (Detection Rate)** | 88.00% (22/25) | **100.00% (25/25)** | **+12.00%** |
| **F1-Score** | 81.48% | **96.15%** | **+14.67%** |
| **False Positive Rate (FPR)** | 28.00% (7/25) | **8.00% (2/25)** | **-20.00% (71% drop)** |
| **False Negative Rate (FNR)** | 12.00% (3/25) | **0.00% (0/25)** | **-12.00% (Zero missed)** |
| **Specificity** | 72.00% (18/25) | **92.00% (23/25)** | **+20.00%** |
| **ROC-AUC** | 0.9296 | **1.0000** | **+0.0704** |

### Confusion Matrix Evolution

```
BEFORE RETRAINING:
                  Predicted Legit    Predicted Phish
  Actual Legit    TN = 18             FP = 7
  Actual Phish    FN = 3              TP = 22

AFTER RETRAINING:
                  Predicted Legit    Predicted Phish
  Actual Legit    TN = 23 (+5)        FP = 2 (-5)
  Actual Phish    FN = 0  (-3)        TP = 25 (+3)
```

### Category-Level Accuracy Comparison

| Category | Type | Count | Before Accuracy | After Accuracy | Impact |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Subtle BEC** | Phish | 5 | 60.0% (3/5) | **100.0% (5/5)** | **+40.0%** (FN: 2 $\to$ 0) |
| **Payment Diversion** | Phish | 5 | 80.0% (4/5) | **100.0% (5/5)** | **+20.0%** (FN: 1 $\to$ 0) |
| **Legitimate Billing & Finance** | Legit | 6 | 50.0% (3/6) | **100.0% (6/6)** | **+50.0%** (FP: 3 $\to$ 0) |
| **Legitimate Security Alerts** | Legit | 7 | 42.9% (3/7) | **71.4% (5/7)** | **+28.5%** (FP: 4 $\to$ 2) |
| **MFA Fatigue & Push Bombing** | Phish | 5 | 100.0% (5/5) | **100.0% (5/5)** | Maintained 100% |
| **Contemporary Smishing & Lures** | Phish | 5 | 100.0% (5/5) | **100.0% (5/5)** | Maintained 100% |
| **Paraphrased Phishing** | Phish | 5 | 100.0% (5/5) | **100.0% (5/5)** | Maintained 100% |
| **Legitimate Operations & IT** | Legit | 6 | 100.0% (6/6) | **100.0% (6/6)** | Maintained 100% |
| **Legitimate Collaboration** | Legit | 6 | 100.0% (6/6) | **100.0% (6/6)** | Maintained 100% |

---

## 4. Fresh Out-of-Distribution Validation Set (N = 30)

To guard against test set overfitting, a completely separate validation test set of **30 brand-new samples** (15 Phishing, 15 Legitimate) was constructed in [`data/fresh_validation_test_set.json`](file:///d:/PhishGuard%20AI/data/fresh_validation_test_set.json) and evaluated via [`scripts/evaluate_fresh_validation.py`](file:///d:/PhishGuard%20AI/scripts/evaluate_fresh_validation.py).

### Results on Fresh Validation Set:
- **Accuracy:** **90.00%** (27 / 30)
- **Precision:** **83.33%** (15 / 18)
- **Recall (Detection Rate):** **100.00%** (15 / 15 Attacks Caught, 0 False Negatives)
- **F1-Score:** **90.91%**
- **False Positive Rate:** **20.00%** (3 / 15)
- **Specificity:** **80.00%** (12 / 15)
- **ROC-AUC:** **1.0000**

### Category Performance on Fresh Set:
- **Subtle BEC:** 100.0% (4/4) — $P_{\text{avg}} = 0.9441$
- **Payment Diversion:** 100.0% (4/4) — $P_{\text{avg}} = 0.9918$
- **MFA Fatigue:** 100.0% (3/3) — $P_{\text{avg}} = 0.9290$
- **Paraphrased Phishing:** 100.0% (2/2) — $P_{\text{avg}} = 0.9922$
- **Contemporary Smishing:** 100.0% (2/2) — $P_{\text{avg}} = 0.9975$
- **Legitimate Operations:** 100.0% (2/2) — $P_{\text{avg}} = 0.0244$
- **Legitimate Collaboration:** 100.0% (3/3) — $P_{\text{avg}} = 0.0808$
- **Legitimate Billing:** 80.0% (4/5) — $P_{\text{avg}} = 0.1590$
- **Legitimate Security Alerts:** 60.0% (3/5) — $P_{\text{avg}} = 0.4298$

---

## 5. System Integrity & Functional Verification

1. **Existing Pytest Suite:** All 43 unit and regression tests pass without errors (`pytest -q` $\to$ `43 passed in 3.40s`).
2. **Web Application:** Streamlit application booted cleanly in headless test mode on port 8598. UI, tactic badges, HTML phrase highlighting, and risk score presentation remain fully functional.
3. **Model Artifact:** The updated model pipeline was saved to [`models/phishguard_model.joblib`](file:///d:/PhishGuard%20AI/models/phishguard_model.joblib).
