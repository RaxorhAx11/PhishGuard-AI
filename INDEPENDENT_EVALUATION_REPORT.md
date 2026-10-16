# PhishGuard AI - Final Independent Evaluation Report
**Date:** October 15, 2026  
**Evaluation Scope:** Out-of-Distribution Independent Benchmark (Unseen Scenarios)  
**Evaluator:** Independent Audit Pipeline  
**Model & Rules State:** Untouched (`models/phishguard_model.joblib`, `src/tactics.py`, `src/preprocessing.py`, `app.py`, and `data/dataset.csv` unmodified)

---

## 1. Executive Summary

An independent, rigorous out-of-distribution evaluation was executed against the trained PhishGuard AI model. A dedicated benchmark comprising **50 realistic modern email and SMS communications** (25 phishing/social engineering attacks and 25 authentic corporate/consumer legitimate messages) was developed.

None of the evaluation messages were utilized during training, synthetic augmentation, or rule development. The model, decision boundaries, heuristic rules, and web UI were kept strictly unmodified to ensure an unvarnished assessment of real-world generalization performance.

### Key Headline Results:
- **Accuracy:** 80.00% (40 / 50 correctly classified at binary threshold 0.50)
- **Precision:** 75.86% (22 True Positives / 29 Predicted Phishing)
- **Recall (Detection Rate):** 88.00% (22 / 25 Attacks Detected)
- **F1-Score:** 81.48%
- **False Positive Rate (FPR):** 28.00% (7 / 25 Legitimate flagged as Phishing)
- **Specificity:** 72.00% (18 / 25 Legitimate correctly cleared)
- **ROC-AUC Score:** 0.9296
- **Existing Regression Test Suite:** 43 of 43 passed (100%)
- **App Launch Verification:** Streamlit web application compiles and boots successfully.

---

## 2. Independent Test Set Design & Category Distribution

The evaluation benchmark was constructed across 9 distinct threat and communication categories:

| Category | Class | Count | Description |
| :--- | :---: | :---: | :--- |
| **Subtle BEC** | Phish | 5 | CEO/executive wire requests, confidential M&A escrow, emergency stipends, and audit confirmations lacking explicit links. |
| **MFA Fatigue & Push Bombing** | Phish | 5 | Okta, Duo, Microsoft Authenticator push loops, session timeout notifications, and FIDO attestation reset lures. |
| **Payment Diversion** | Phish | 5 | Supplier remittance rerouting, direct deposit alteration, machinery PO SWIFT changes, and closing escrow updates. |
| **Paraphrased Phishing** | Phish | 5 | Conversational lures avoiding generic urgency keywords (collaborative whiteboards, LinkedIn recruitment, Adobe Sign MSAs). |
| **Contemporary Smishing & Lures** | Phish | 5 | Delivery redelivery fees, toll road violations, voicemail playback lures, QR code migration, and quarantined attachment releases. |
| **Legitimate Security Alerts** | Legit | 7 | Automated notifications from GitHub (new PAT), AWS CloudTrail (root login), Slack (new login), Google 2SV, corporate VPN tunnels, and 2-way bank fraud texts. |
| **Legitimate Billing & Finance** | Legit | 6 | Stripe SaaS receipts, utility bill auto-pay notices, Concur expense approvals, recurring colocation invoices, and high-yield savings interest credits. |
| **Legitimate Operations & IT** | Legit | 6 | Scheduled PostgreSQL maintenance, resolved Jira tickets, Wi-Fi CA certificate renewals, IDE license renewals, and flu clinic announcements. |
| **Legitimate Collaboration** | Legit | 6 | Slide deck reviews in Google Drive, Sprint retrospectives, team lunch RSVP, GitHub PR reviews, NDA redlines, and client consulting syncs. |
| **Total** | — | **50** | **Balanced: 25 Phishing (50%) / 25 Legitimate (50%)** |

All raw test samples and evaluation metadata are stored in [`data/independent_test_set.json`](file:///d:/PhishGuard%20AI/data/independent_test_set.json) and [`data/independent_evaluation_results.json`](file:///d:/PhishGuard%20AI/data/independent_evaluation_results.json).

---

## 3. Data Leakage & Overlap Verification

To verify that the evaluation was strictly independent, an automated verification procedure ([`scripts/evaluate_independent.py`](file:///d:/PhishGuard%20AI/scripts/evaluate_independent.py)) checked each test sample against:
1. The 10,084 records in [`data/dataset.csv`](file:///d:/PhishGuard%20AI/data/dataset.csv)
2. Synthetic examples in [`scripts/augment_dataset.py`](file:///d:/PhishGuard%20AI/scripts/augment_dataset.py)
3. Demo samples in [`src/samples.py`](file:///d:/PhishGuard%20AI/src/samples.py)
4. Regression test fixtures in [`tests/test_regressions.py`](file:///d:/PhishGuard%20AI/tests/test_regressions.py)
5. Model test fixtures in [`tests/test_model.py`](file:///d:/PhishGuard%20AI/tests/test_model.py)
6. Diagnostic cases in [`scripts/diagnose.py`](file:///d:/PhishGuard%20AI/scripts/diagnose.py)

**Verification Results:**
- Exact Raw String Matches: **0**
- Cleaned/Normalized Token Matches: **0**
- High Token Jaccard Similarity (> 0.75): **0**
- Overlap Verification Status: **PASSED (100% Out-of-Distribution)**

---

## 4. Confusion Matrix & Empirical Metrics

### 2x2 Confusion Matrix

$$\begin{array}{c|cc}
& \text{Predicted Legit (0)} & \text{Predicted Phish (1)} \\
\hline
\text{Actual Legit (0)} & \mathbf{TN = 18} & \mathbf{FP = 7} \\
\text{Actual Phish (1)} & \mathbf{FN = 3} & \mathbf{TP = 22} \\
\end{array}$$

### Performance Metrics Table

| Metric | Formula / Meaning | Score |
| :--- | :--- | :---: |
| **Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN} = \frac{40}{50}$ | **80.00%** |
| **Precision** | $\frac{TP}{TP + FP} = \frac{22}{29}$ | **75.86%** |
| **Recall (Sensitivity)** | $\frac{TP}{TP + FN} = \frac{22}{25}$ | **88.00%** |
| **F1-Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | **81.48%** |
| **False Positive Rate (FPR)** | $\frac{FP}{FP + TN} = \frac{7}{25}$ | **28.00%** |
| **False Negative Rate (FNR)** | $\frac{FN}{FN + TP} = \frac{3}{25}$ | **12.00%** |
| **Specificity** | $\frac{TN}{TN + FP} = \frac{18}{25}$ | **72.00%** |
| **ROC-AUC** | Area under ROC Curve | **0.9296** |

### Three-Tier Risk Distribution

| True Label | Low Risk ($< 0.35$) | Medium Risk ($0.35 - 0.69$) | High Risk ($\ge 0.70$) |
| :--- | :---: | :---: | :---: |
| **Actual Phishing ($n=25$)** | 3 (12.0%) | 3 (12.0%) | **19 (76.0%)** |
| **Actual Legitimate ($n=25$)** | **16 (64.0%)** | 4 (16.0%) | 5 (20.0%) |

---

## 5. Granular Category Performance Breakdown

| Threat / Message Category | Total | Correct | Accuracy | Mean Phish Probability |
| :--- | :---: | :---: | :---: | :---: |
| **MFA Fatigue & Push Bombing** | 5 | 5 | **100.0%** | 0.9871 |
| **Contemporary Smishing & Lures** | 5 | 5 | **100.0%** | 0.9770 |
| **Paraphrased Phishing** | 5 | 5 | **100.0%** | 0.9781 |
| **Payment Diversion** | 5 | 4 | **80.0%** | 0.6489 |
| **Subtle BEC** | 5 | 3 | **60.0%** | 0.6079 |
| **Legitimate Operations & IT** | 6 | 6 | **100.0%** | 0.0811 |
| **Legitimate Workplace Collaboration** | 6 | 6 | **100.0%** | 0.0783 |
| **Legitimate Billing & Finance** | 6 | 3 | **50.0%** | 0.4223 |
| **Legitimate Security Alerts** | 7 | 3 | **42.9%** | 0.4833 |

---

## 6. Detailed Failure Mode Analysis

The model produced **10 binary misclassifications** (3 False Negatives, 7 False Positives) out of 50 samples. Analyzing these failures highlights the structural boundaries of text-only NLP classifiers.

### A. False Negatives ($FN = 3$) — Missed Phishing

1. **`bec_legal_retainer` (Subtle BEC)**
   - *Text Excerpt:* *"Subject: Confidential: Engagement with Outside Legal Counsel ... We are engaging Sullivan & partners for advisory on a confidential merger. They need a retainer fee of $42,000 processed before 3:00 PM today. Let me know when you can initiate the domestic wire..."*
   - *Calibrated Probability:* `0.2475` (Classified: Legit / Low Risk)
   - *Root Cause:* The lure relies on conversational pretexting using corporate transactional terms (*merger*, *counsel*, *advisory*, *retainer*). In the absence of an external hyperlink or domain mismatch header, the bag-of-words representation views these terms as corporate business dialogue (strongly correlated with legitimate Enron emails).

2. **`bec_heathrow_stipend` (Subtle BEC)**
   - *Text Excerpt:* *"Hi HR / Accounting team, I am stranded at London Heathrow due to flight cancellations and my corporate card is being declined. Could you please wire an emergency travel stipend of $3,500 to my European Revolut account immediately..."*
   - *Calibrated Probability:* `0.1757` (Classified: Legit / Low Risk)
   - *Root Cause:* Although the heuristic module flagged an `urgency` tactic (*immediately*), the text consists largely of travel narrative vocabulary (*flight cancellations*, *rebook lodging*, *travel issue*). Without an explicit credential collection URL, the statistical model scores the message as low risk.

3. **`payment_acme_remittance_swap` (Payment Diversion)**
   - *Text Excerpt:* *"Dear Accounts Payable, Please note that due to our recent corporate banking consolidation, all future payments to Acme Industrial Logistics must be remitted to our new Chase Treasury account. Attached is our updated W-9 form and ACH banking details..."*
   - *Calibrated Probability:* `0.2422` (Classified: Legit / Low Risk)
   - *Root Cause:* The phrasing adopts formal B2B invoice administration terminology (*banking consolidation*, *ERP system*, *ACH banking details*, *disbursements*). Without coercive threats or phishing URLs, pure lexical models struggle to differentiate an unauthorized vendor bank update from a routine corporate accounting change.

### B. False Positives ($FP = 7$) — Benign Flagged as Phishing

1. **`legit_github_pat_created` (Legit Security Alert)**
   - *Text Excerpt:* *"GitHub Security Notification: A new personal access token (classic) with 'repo, workflow' scopes was generated on your account from IP address 198.51.100.24... revoke it immediately."*
   - *Calibrated Probability:* `0.7592` (Classified: Phishing / High Risk)
   - *Root Cause:* Legitimate security incident alerts inherently reuse the exact same vocabulary as security-impersonation phishing (*security notification*, *token*, *IP address*, *revoke immediately*).

2. **`legit_slack_session_notice` (Legit Security Alert)**
   - *Text Excerpt:* *"Slack Security Notice: We noticed a new sign-in to your Slack workspace 'Engineering Hub' from Chrome on macOS... IP: 66.249.79.10..."*
   - *Calibrated Probability:* `0.7142` (Classified: Phishing / High Risk)
   - *Root Cause:* Co-occurrence of *new sign-in*, *IP address*, and *active sessions* in short notification texts maps directly onto credential harvesting warning templates.

3. **`legit_google_2step_status` (Legit Security Alert)**
   - *Text Excerpt:* *"Google Account Alert: 2-Step Verification was recently turned on... unrecognized device, you will be prompted for your second factor..."*
   - *Calibrated Probability:* `0.7371` (Classified: Phishing / High Risk)
   - *Root Cause:* Phrases like *unrecognized device*, *2-Step Verification*, and *backup codes* mimic 2FA credential-theft alerts.

4. **`legit_vpn_tunnel_active` (Legit Security Alert)**
   - *Text Excerpt:* *"Corporate GlobalProtect VPN: Your remote workstation successfully established an encrypted SSL-VPN tunnel to Gateway us-west-gateway.corp.net. Assigned Virtual IP: 10.240.18.94..."*
   - *Calibrated Probability:* `0.5127` (Classified: Phishing / Medium Risk)
   - *Root Cause:* High density of technical networking and security infrastructure tokens without conversational email context.

5. **`legit_stripe_jira_receipt` (Legit Billing)**
   - *Text Excerpt:* *"Receipt from Atlassian via Stripe: Payment of $480.00 for 40 Jira Software Cloud Standard user licenses was successfully processed on Oct 12, 2026. Payment method: Visa ending in 3192..."*
   - *Calibrated Probability:* `0.7138` (Classified: Phishing / High Risk)
   - *Root Cause:* In historical training data, financial payment notifications citing specific transaction amounts and card ending numbers are predominantly smishing/phishing lures.

6. **`legit_colocation_standard_inv` (Legit Billing)**
   - *Text Excerpt:* *"Dear Finance Team, Attached is our standard quarterly invoice #INV-7731 for server colocation services covering Q4 2026. Payment terms are net 45 per our master service agreement..."*
   - *Calibrated Probability:* `0.5524` (Classified: Phishing / Medium Risk)
   - *Root Cause:* Presence of terms like *invoice*, *remittance details*, and *master service agreement* borderline elevates risk index to 55.

7. **`legit_capitalone_savings_interest` (Legit Billing)**
   - *Text Excerpt:* *"Capital One Statement Notice: Your monthly high-yield savings interest of $34.12 was credited to account ending in 9021... Sign in to the official Capital One mobile app..."*
   - *Calibrated Probability:* `0.8106` (Classified: Phishing / High Risk)
   - *Root Cause:* Historical SMS spam corpora contain dozens of fraudulent bank statement alerts mentioning major bank brands ("Capital One", "Chase", "Wells Fargo"). Authentic short text updates closely mirror these tokens.

---

## 7. Dataset Limitations & Real-World Generalization Realities

An essential tenet of trustworthy security engineering is acknowledging the boundaries of statistical machine learning:

1. **The Historical Training Corpus Gap:**
   - The primary dataset consists of the **Enron Email Corpus (circa 2001)** and the **SMS Spam Collection (circa 2012)**. Modern enterprise cloud environments (SaaS billing receipts, Okta MFA workflows, Slack login alerts, Google Workspace security emails) were virtually non-existent when these datasets were gathered.
   - Consequently, the model exhibits a domain gap: when confronted with authentic modern security notices, it flags them because "security vocabulary" in historical corpora was disproportionately concentrated in malicious samples.

2. **Absence of Envelope & Network Protocol Headers:**
   - In production mail gateways (e.g., Proofpoint, Google Workspace, Microsoft Defender), classification relies heavily on metadata outside the email body: **SPF alignment, DKIM cryptographic signatures, DMARC policy, IP reverse DNS reputation, and recipient communication graph history**.
   - As an isolated text NLP analyzer, PhishGuard AI evaluates only the message body. In pure text, a genuine prompt ("A Duo MFA push was just sent to your phone, please approve") and an attacker's prompt are lexically identical.

3. **Vocabulary Collision in Defense & Attack:**
   - Security teams and cybercriminals use the exact same terminology (*"unauthorized login"*, *"password expiration"*, *"verify identity"*, *"security token"*). No static lexical model can achieve 100% precision and 100% recall simultaneously without external verification channels.

4. **Calibrated Probability vs. Hard Binary Decisions:**
   - The 28% False Positive Rate at a hard 0.50 threshold illustrates why PhishGuard AI's **three-tier risk classification (Low / Medium / High)** with actionable guidance is the correct paradigm. Borderline cases (scores 35–69) should be marked as "Medium Suspicion" prompting manual verification, rather than outright blocking legitimate business correspondence.

---

## 8. Verification of Stability & Operational Readiness

To confirm that evaluation activities introduced no side effects or regressions:

1. **Existing Test Suite:**
   ```bash
   python -m pytest
   ```
   **Result:** `43 passed in 3.25s` (100% passing across all 6 test modules: `test_e2e_verification.py`, `test_model.py`, `test_preprocessing.py`, `test_regressions.py`, `test_samples.py`, `test_tactics.py`).

2. **Web Application Launch:**
   ```bash
   python -m streamlit run app.py --server.headless true --server.port 8599
   ```
   **Result:** App initialized cleanly, connected to server socket `http://localhost:8599`, loaded the trained model pipeline, and rendered the user dashboard without errors.

3. **Codebase Immutability:**
   - `models/phishguard_model.joblib`: Unchanged.
   - `src/model.py`: Unchanged.
   - `src/tactics.py`: Unchanged.
   - `src/preprocessing.py`: Unchanged.
   - `data/dataset.csv`: Unchanged.
   - `app.py`: Unchanged.

---

## 9. Replication Instructions

To reproduce these exact benchmark results at any time:
```bash
python scripts/evaluate_independent.py
```
This script validates data non-overlap, evaluates [`data/independent_test_set.json`](file:///d:/PhishGuard%20AI/data/independent_test_set.json), computes all metrics, and outputs [`data/independent_evaluation_results.json`](file:///d:/PhishGuard%20AI/data/independent_evaluation_results.json).
