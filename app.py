"""
PhishGuard AI - Context-Aware Phishing & Social Engineering Detection Web App
Clean, minimal, and accessible college-project MVP dashboard.
Tech Stack: Python, Streamlit, Pandas, Scikit-learn
"""

import os
import sys
import streamlit as st

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.dirname(__file__))

from src.model import (
    PhishGuardClassifier,
    DEFAULT_MODEL_PATH,
)
from src.preprocessing import validate_input
from src.tactics import analyze_tactics, generate_highlighted_html
from src.samples import SAMPLE_MESSAGES


# Streamlit Page Configuration
st.set_page_config(
    page_title="PhishGuard AI | Phishing & Social Engineering Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Clean, modern CSS with dark navy & teal theme
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    .stApp {
        background: radial-gradient(circle at 15% 10%, #0d1e38 0%, #080c15 50%, #05070d 100%);
        color: #f8fafc;
    }

    /* Header */
    .app-header {
        background: linear-gradient(135deg, rgba(14, 23, 42, 0.95) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(0, 210, 180, 0.25);
        border-radius: 14px;
        padding: 1.25rem 1.75rem;
        margin-bottom: 1.25rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .brand-title {
        background: linear-gradient(135deg, #ffffff 40%, #00d2b4 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 1.9rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin: 0;
    }

    .brand-tagline {
        margin: 0.25rem 0 0 0;
        color: #94a3b8;
        font-size: 0.9rem;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34d399;
        padding: 5px 12px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* Disclaimer */
    .disclaimer-box {
        background: rgba(14, 23, 42, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-left: 3px solid #00d2b4;
        border-radius: 8px;
        padding: 0.65rem 1rem;
        color: #94a3b8;
        font-size: 0.82rem;
        line-height: 1.45;
        margin-bottom: 1.25rem;
    }

    /* Text Area */
    .stTextArea textarea {
        background-color: #090e1a !important;
        border: 1px solid rgba(148, 163, 184, 0.22) !important;
        border-radius: 10px !important;
        color: #f1f5f9 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.9rem !important;
        line-height: 1.55 !important;
    }

    .stTextArea textarea:focus {
        border-color: #00d2b4 !important;
        box-shadow: 0 0 0 2px rgba(0, 210, 180, 0.2) !important;
    }

    /* Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00d2b4 0%, #0284c7 100%) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        font-size: 0.98rem !important;
        padding: 0.6rem 1.4rem !important;
        box-shadow: 0 4px 16px rgba(0, 210, 180, 0.3) !important;
        transition: transform 0.15s ease !important;
    }

    div.stButton > button[kind="primary"]:hover {
        transform: translateY(-1px) !important;
    }

    div.stButton > button[kind="secondary"] {
        background: rgba(15, 23, 42, 0.8) !important;
        color: #cbd5e1 !important;
        border: 1px solid rgba(148, 163, 184, 0.25) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
    }

    /* Result Cards */
    .result-section {
        background: rgba(14, 23, 42, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.25rem;
    }

    .section-heading {
        font-size: 1.1rem;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .risk-badge {
        display: inline-block;
        padding: 5px 14px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.85rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    .action-step {
        display: flex;
        align-items: flex-start;
        gap: 0.75rem;
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        font-size: 0.88rem;
    }

    .step-num {
        min-width: 22px;
        height: 22px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        font-weight: 700;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #090e1a !important;
        border-right: 1px solid rgba(148, 163, 184, 0.12) !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_classifier():
    """Initializes and caches the PhishGuardClassifier."""
    clf = PhishGuardClassifier(model_path=DEFAULT_MODEL_PATH)
    if os.path.exists(DEFAULT_MODEL_PATH):
        try:
            clf.load()
        except Exception:
            pass
    return clf


classifier = get_classifier()

# Session State for User Input & Results
if "input_text" not in st.session_state:
    st.session_state["input_text"] = ""

if "last_analyzed" not in st.session_state:
    st.session_state["last_analyzed"] = None


# ---------------- COMPACT SIDEBAR ---------------- #
with st.sidebar:
    st.markdown("### 🛡️ PhishGuard AI")
    st.caption("Context-Aware Phishing & Social Engineering Detection")
    st.divider()

    # Model Status
    st.markdown("#### System Status")
    if classifier.is_loaded():
        st.markdown(
            """
            <div class="status-badge">
                <span style="width: 7px; height: 7px; border-radius: 50%; background: #10b981;"></span>
                ML Classifier Active
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Engine ready with calibrated confidence scoring and threat tactic detection.")
    else:
        st.error("Model Not Loaded", icon="⚠️")
        if st.button("Attempt Reload", use_container_width=True, type="secondary"):
            try:
                classifier.load()
                st.rerun()
            except Exception as e:
                st.error(f"Reload failed: {str(e)}")

    st.divider()

    # Project Information
    st.markdown("#### How It Works")
    st.markdown(
        """
        <div style="font-size: 0.83rem; color: #94a3b8; line-height: 1.5;">
        PhishGuard AI analyzes message content using:
        <ul style="margin: 0.4rem 0; padding-left: 1.2rem;">
            <li><strong>Multi-View NLP:</strong> Evaluates word & character patterns</li>
            <li><strong>Tactic Detection:</strong> Identifies urgency, coercion, and impersonation</li>
            <li><strong>Calibrated Risk Score:</strong> Estimates phishing likelihood (0–100)</li>
        </ul>
        100% offline analysis — zero data leakage.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------- MAIN CONTENT ---------------- #

# 1. Header with Shield Icon & Tagline
st.markdown(
    """
    <div class="app-header">
        <div style="display: flex; align-items: center; gap: 0.9rem;">
            <div style="font-size: 2rem; background: rgba(0, 210, 180, 0.12); border: 1px solid rgba(0, 210, 180, 0.3); border-radius: 12px; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center;">
                🛡️
            </div>
            <div>
                <h1 class="brand-title">PhishGuard AI</h1>
                <p class="brand-tagline">Context-Aware Phishing & Social Engineering Detection</p>
            </div>
        </div>
        <div>
            <span class="status-badge">
                <span style="width: 7px; height: 7px; border-radius: 50%; background: #10b981;"></span>
                Online & Ready
            </span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# 2. Brief Safety Disclaimer
st.markdown(
    """
    <div class="disclaimer-box">
        <strong>⚠️ Security Notice:</strong> Predictions are statistical estimations based on trained machine learning patterns. Always verify critical requests independently via official out-of-band channels.
    </div>
    """,
    unsafe_allow_html=True,
)

# 3. Quick Demo Scenarios
st.markdown("<div style='font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.4rem;'>⚡ Quick Demo Scenarios:</div>", unsafe_allow_html=True)
sc1, sc2, sc3, sc4 = st.columns(4)

with sc1:
    if st.button("🚨 IT Support Urgent", use_container_width=True, type="secondary"):
        for s in SAMPLE_MESSAGES:
            if s["id"] == "phish_it_support":
                st.session_state["input_text"] = s["content"]
                st.rerun()

with sc2:
    if st.button("💳 CEO Gift Card (BEC)", use_container_width=True, type="secondary"):
        for s in SAMPLE_MESSAGES:
            if s["id"] == "subtle_ceo_giftcard":
                st.session_state["input_text"] = s["content"]
                st.rerun()

with sc3:
    if st.button("📄 DocuSign Contract", use_container_width=True, type="secondary"):
        for s in SAMPLE_MESSAGES:
            if s["id"] == "subtle_docusign_lure":
                st.session_state["input_text"] = s["content"]
                st.rerun()

with sc4:
    if st.button("✅ Legitimate Meeting", use_container_width=True, type="secondary"):
        for s in SAMPLE_MESSAGES:
            if s["id"] == "legit_meeting_sync":
                st.session_state["input_text"] = s["content"]
                st.rerun()

# 4. Email/SMS Text Input Area
input_text = st.text_area(
    label="Message to analyze:",
    value=st.session_state["input_text"],
    height=160,
    placeholder="Paste full email or SMS text here to inspect...",
    label_visibility="collapsed",
)

# 5. Action Buttons (Analyze & Clear)
btn_col1, btn_col2, _ = st.columns([1.5, 1, 3.5])
with btn_col1:
    analyze_btn = st.button("⚡ Analyze Message", type="primary", use_container_width=True)
with btn_col2:
    clear_btn = st.button("🗑️ Clear", type="secondary", use_container_width=True)

if clear_btn:
    st.session_state["input_text"] = ""
    st.session_state["last_analyzed"] = None
    st.rerun()

# Run Analysis Logic
if analyze_btn:
    st.session_state["input_text"] = input_text

    is_valid, validation_error = validate_input(input_text)
    if not is_valid:
        st.error(f"Validation Error: {validation_error}", icon="🚨")
    elif not classifier.is_loaded():
        st.error("ML model is not loaded. Please ensure the model file is available.", icon="⚠️")
    else:
        with st.spinner("Analyzing message content and tactics..."):
            try:
                prediction_res = classifier.predict(input_text)
                tactics_res = analyze_tactics(input_text)
                st.session_state["last_analyzed"] = {
                    "text": input_text,
                    "pred": prediction_res,
                    "tactics": tactics_res,
                }
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}", icon="💥")

# ---------------- RESULTS PRESENTATION ---------------- #
if st.session_state["last_analyzed"] is not None:
    data = st.session_state["last_analyzed"]
    pred = data["pred"]
    tactics = data["tactics"]
    analyzed_text = data["text"]

    risk_level = pred["risk_level"]  # Low, Medium, High
    badge_color = pred["badge_color"]  # Green #10b981, Amber #f59e0b, Red #ef4444
    risk_score = pred["risk_score_index"]

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 1. Risk Classification and Score Card
    st.markdown(
        f"""
        <div class="result-section" style="border: 2px solid {badge_color}; box-shadow: 0 4px 20px {badge_color}18;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <div style="flex: 1; min-width: 250px;">
                    <span class="risk-badge" style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color};">
                        {risk_level} Risk Level
                    </span>
                    <h2 style="margin: 0.4rem 0 0.25rem 0; font-size: 1.5rem; color: #f8fafc; font-weight: 700;">
                        {pred['summary']}
                    </h2>
                    <p style="margin: 0; color: #cbd5e1; font-size: 0.9rem; line-height: 1.5;">
                        {pred['guidance']}
                    </p>
                </div>
                <div style="text-align: center; min-width: 140px; background: rgba(9, 14, 26, 0.7); border: 1px solid {badge_color}44; border-radius: 12px; padding: 1rem 1.25rem;">
                    <div style="font-size: 0.74rem; text-transform: uppercase; color: #94a3b8; font-weight: 700; letter-spacing: 0.06em;">
                        Risk Score
                    </div>
                    <div style="font-size: 2.8rem; font-weight: 800; color: {badge_color}; line-height: 1.1;">
                        {risk_score}<span style="font-size: 1.1rem; color: #64748b; font-weight: 600;">/100</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #94a3b8;">
                        Classification: <strong style="color: #f8fafc;">{pred['class_name']}</strong>
                    </div>
                </div>
            </div>
            <!-- Progress Bar -->
            <div style="margin-top: 1rem; width: 100%; height: 8px; background: #0f172a; border-radius: 9999px; overflow: hidden; border: 1px solid rgba(148, 163, 184, 0.15);">
                <div style="width: {risk_score}%; height: 100%; background: {badge_color};"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.72rem; color: #64748b; margin-top: 4px;">
                <span style="color: #10b981;">Low Risk (0–34)</span>
                <span style="color: #f59e0b;">Medium Risk (35–69)</span>
                <span style="color: #ef4444;">High Threat (70–100)</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Suspicious Phrase Highlighting
    st.markdown(
        """
        <div class="section-heading">
            <span>🔍 Suspicious Phrase Inspection</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    highlighted_html = generate_highlighted_html(analyzed_text, tactics)
    st.markdown(highlighted_html, unsafe_allow_html=True)

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 3. Detected Social Engineering Tactics with Explanations
    st.markdown(
        """
        <div class="section-heading">
            <span>🧠 Detected Social Engineering Tactics</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not tactics:
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 1rem 1.25rem; color: #a7f3d0; font-size: 0.9rem;">
                ✅ <strong>No Manipulation Tactics Detected:</strong> The message does not exhibit artificial urgency, coercion, authority impersonation, or credential harvesting patterns.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        for t_key, t_data in tactics.items():
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(148, 163, 184, 0.15); border-left: 4px solid {t_data['badge_color']}; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                        <strong style="color: #f8fafc; font-size: 1rem;">
                            {t_data['icon']} {t_data['title']}
                        </strong>
                        <span style="background: {t_data['badge_color']}22; color: {t_data['badge_color']}; padding: 2px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700;">
                            {t_data['match_count']} Trigger(s)
                        </span>
                    </div>
                    <p style="margin: 0.25rem 0 0.5rem 0; color: #cbd5e1; font-size: 0.88rem; line-height: 1.45;">
                        {t_data['description']}
                    </p>
                    <div style="font-size: 0.82rem; color: #94a3b8;">
                        <strong style="color: #e2e8f0;">Matched Phrases:</strong> 
                        {", ".join(f"<code style='color: {t_data['badge_color']};'>{p}</code>" for p in t_data['phrases'])}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 1.25rem;'></div>", unsafe_allow_html=True)

    # 4. Recommended Safety Actions
    st.markdown(
        """
        <div class="section-heading">
            <span>🛡️ Recommended Safety Actions</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if risk_level == "High":
        st.markdown(
            """
            <div class="action-step">
                <span class="step-num" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444;">1</span>
                <div>
                    <strong style="color: #f8fafc;">Do Not Click Any Links or Open Attachments</strong><br>
                    <span style="color: #94a3b8;">Links may lead to credential harvesting portals or automated malware delivery.</span>
                </div>
            </div>
            <div class="action-step">
                <span class="step-num" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444;">2</span>
                <div>
                    <strong style="color: #f8fafc;">Never Disclose Credentials, Passwords, or 2FA Codes</strong><br>
                    <span style="color: #94a3b8;">Legitimate organizations will never request passwords or one-time passcodes over email or SMS.</span>
                </div>
            </div>
            <div class="action-step">
                <span class="step-num" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444;">3</span>
                <div>
                    <strong style="color: #f8fafc;">Verify Through a Known Independent Channel</strong><br>
                    <span style="color: #94a3b8;">Contact the sender using an official phone number or trusted directory (do not reply directly to this message).</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif risk_level == "Medium":
        st.markdown(
            """
            <div class="action-step">
                <span class="step-num" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b;">1</span>
                <div>
                    <strong style="color: #f8fafc;">Inspect the Sender Address & Domain</strong><br>
                    <span style="color: #94a3b8;">Verify that the email domain matches the official organization domain without subtle typosquatting.</span>
                </div>
            </div>
            <div class="action-step">
                <span class="step-num" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b;">2</span>
                <div>
                    <strong style="color: #f8fafc;">Hover Over Hyperlinks Before Clicking</strong><br>
                    <span style="color: #94a3b8;">Confirm the destination URL matches the expected official website before interacting.</span>
                </div>
            </div>
            <div class="action-step">
                <span class="step-num" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b;">3</span>
                <div>
                    <strong style="color: #f8fafc;">Confirm Sensitive Requests Verbally</strong><br>
                    <span style="color: #94a3b8;">If the message requests financial transfers, password resets, or personal data, confirm with the sender directly.</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class="action-step">
                <span class="step-num" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981;">1</span>
                <div>
                    <strong style="color: #f8fafc;">Authentic Message Characteristics</strong><br>
                    <span style="color: #94a3b8;">The message exhibits structural and linguistic patterns consistent with benign communications.</span>
                </div>
            </div>
            <div class="action-step">
                <span class="step-num" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981;">2</span>
                <div>
                    <strong style="color: #f8fafc;">Standard Security Hygiene</strong><br>
                    <span style="color: #94a3b8;">Continue adhering to good cyber practices: never submit passwords on unsolicited web forms.</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
