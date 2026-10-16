"""
Social engineering tactics and suspicious phrase detection for PhishGuard AI.
Explains detected tactics:
- Urgency & Time Pressure
- Threats, Penalties & Coercion
- Authority & Brand Impersonation
- Sensitive Information & Financial Exploitation
- Deceptive Cloud & E-Sign Lures
"""

import html
import re
from typing import Dict, List, Tuple


TACTIC_DEFINITIONS = {
    "urgency": {
        "title": "Artificial Urgency & Time Pressure",
        "badge_color": "#f59e0b",  # Amber
        "icon": "⏳",
        "description": "Attackers manufacture tight deadlines (e.g., 'within 24 hours', 'immediate action required', 'before cutoff') to induce panic and prevent victims from verifying claims through normal channels.",
        "patterns": [
            r"\b(?:act|respond|reply|verify|click|call|pay|update)\s+now\b",
            r"\bimmediate(?:ly)?(?:\s+(?:action|attention|response|update|verification))?\b",
            r"\burgent(?:ly)?(?:\s+(?:notice|alert|action|attention|message|reminder|payment|request))?\b",
            r"\b(?:within|in)\s+(?:\d{1,2}|24|48|12|one|two)\s+(?:hours?|hrs?|minutes?|days?)\b",
            r"\b(?:expires?|valid)\s+(?:today|tonight|in\s+\d+\s+hours?|soon)\b",
            r"\b(?:last|final)\s+(?:chance|notice|reminder|warning)\b",
            r"\btime\s+sensitive\b",
            r"\basap\b",
            r"\bas\s+soon\s+as\s+possible\b",
            r"\bwithout\s+delay\b",
            r"\bdon['']?t\s+delay\b",
            r"\bcritical\s+(?:alert|deadline)\b",
            r"\blimited\s+time\s+(?:offer|window)\b",
            r"\b(?:before|by)\s+(?:this\s+friday\s+)?payroll\s+cutoff\b",
            r"\b(?:before|by)\s+(?:the\s+)?(?:next|this\s+friday['']?s?|upcoming)\s+payroll\s+(?:cycle|cutoff|run|deadline)\b",
            r"\bmandatory\s+(?:security\s+)?(?:updates?|verification|action|re-?authentication)\b",
            r"\b(?:before|by)\s+(?:end\s+of\s+business|end\s+of\s+day|\d{1,2}\s*(?:am|pm))\b",
            r"\bright\s+away\b",
        ],
    },
    "threats": {
        "title": "Threats, Penalties & Coercion",
        "badge_color": "#ef4444",  # Red
        "icon": "⚠️",
        "description": "Intimidation tactics using threats of account closure, legal action, financial penalties, or service suspension to manipulate victims into hasty compliance.",
        "patterns": [
            r"\b(?:account|service|access|card|subscription|session)\s+(?:will\s+be\s+|has\s+been\s+|is\s+)?(?:suspended|terminated|blocked|disabled|frozen|closed|deactivated|revoked|locked|restricted)\b",
            r"\b(?:account|card|access)\s+(?:has\s+been\s+|is\s+)?(?:placed\s+on\s+hold|temporarily\s+locked)\b",
            r"\b(?:permanent|immediate)\s+(?:closure|suspension|deactivation)\b",
            r"\blegal\s+(?:action|consequences|proceedings|prosecution)\b",
            r"\blaw\s+enforcement\b",
            r"\bpolice\s+report\b",
            r"\barrest\s+(?:warrant)?\b",
            r"\bpenalt(?:y|ies)\b",
            r"\bunauthorized\s+(?:access|activity|charges?|transactions?|login|withdrawal)\b",
            r"\bsuspicious\s+(?:activity|sign-ins?|logins?|charges?|transactions?|access)\b",
            r"\bsecurity\s+(?:breach|compromise|alert|incident)\b",
            r"\byou\s+will\s+lose\s+access\b",
            r"\bfailure\s+to\s+(?:comply|sign|respond)\b",
            r"\bheld\s+in\s+quarantine\b",
            r"\bblocked\s+by\s+spam\s+filter\b",
            r"\btoken\s+has\s+expired\b",
        ],
    },
    "impersonation": {
        "title": "Authority & Brand Impersonation",
        "badge_color": "#8b5cf6",  # Purple
        "icon": "🎭",
        "description": "Fabricating legitimate entities—such as IT desks, corporate executives, banks, government agencies, or popular consumer brands—to exploit trust and authority.",
        "patterns": [
            r"\b(?:internal\s+)?(?:it\s+|tech\s+|service\s+)?help\s*desk(?:\s+(?:department|team|desk|admin|administrator|security|technician))?\b",
            r"\b(?:it|tech\s*support|service\s*desk)\s+(?:department|team|desk|admin|administrator|security|help\s*desk)\b",
            r"\b(?:security|fraud|billing|compliance|audit)\s+(?:department|team|desk|center)\b",
            r"\bofficial\s+(?:representative|notice|communication)\b",
            r"\b(?:paypal|apple|microsoft|amazon|google|netflix|wells\s+fargo|chase|bank\s+of\s+america|citibank|okta)\s+(?:support|security|billing|service|alert|team|fraud|desk|center|admin)\b",
            r"\b(?:internal\s+revenue\s+service|irs|social\s+security\s+administration|ssa|fbi|dhl|fedex|usps)\s+(?:notice|audit|alert|division|agent)?\b",
            r"\b(?:human\s+resources|hr\s+department|payroll\s+(?:team|department|office)|accounts\s+payable|finance\s+department|billing\s+team)(?:\s+(?:notice|alert|update|notification|directive|request))?\b",
            r"\b(?:ceo|cfo|executive|manager|director)\s+(?:request|instruction|directive)\b",
            r"\bsystem\s+administrator\b",
            r"\bare\s+you\s+(?:at\s+your\s+desk|available\s+right\s+now)\b",
            r"\bdo\s+not\s+call\s+me\b",
            r"\b(?:tied\s+up|in\s+a\s+meeting|in\s+a\s+conference)\s+(?:and\s+)?(?:unable\s+to\s+(?:step\s+out|call|take\s+calls?)|can['']?t\s+talk)\b",
        ],
    },
    "sensitive_info": {
        "title": "Sensitive Information & Financial Exploitation",
        "badge_color": "#ec4899",  # Pink
        "icon": "🔑",
        "description": "Soliciting passwords, 2FA codes, payment cards, direct deposit routing, wire transfers, or gift card codes via deceptive links or urgent replies.",
        "patterns": [
            r"\b(?:enter|provide|confirm|verify|submit|send|share|reply\s+with|email)\s+(?:us\s+(?:with\s+)?)?(?:your\s+)?(?:password|passcode|pin|credentials|login\s+details)\b",
            r"\b(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\b",
            r"\b(?:social\s+security\s+(?:number)?|ssn)\b",
            r"\b(?:credit|debit)\s+card\s+(?:number|details|information|cvv|pin)\b",
            r"\b(?:bank\s+account|routing)\s+number\b",
            r"\b(?:direct\s+deposit|bank\s+routing\s+information|voided\s+check|banking\s+coordinates|new\s+routing\s+details)\b",
            r"\b(?:bank|banking|account)\s+details\s+(?:have\s+(?:been\s+)?(?:changed|updated)|changed)\b",
            r"\b(?:new|updated|changed)\s+(?:bank|banking)\s+(?:details|coordinates|information|account)\b",
            r"\b(?:iban|swift|bic|sort\s+code)\b(?:\s*[:#]?\s*[a-z0-9]{8,34})?",
            r"\b(?:process|remit|route|send)\s+(?:the\s+)?(?:payment|wire|funds)\s+(?:to\s+(?:our\s+)?new\s+account|today|immediately)\b",
            r"\b(?:2fa|mfa|otp|verification)\s+code\b",
            r"\b(?:duo|okta|microsoft|authenticator)?\s*(?:2fa|mfa|push)\s+(?:push|notification|prompt|request)?\s*(?:was\s+just\s+sent|sent\s+to\s+your\s+phone|approval)\b",
            r"\b(?:approve|accept)\s+(?:the\s+)?(?:duo\s+|okta\s+)?(?:mfa|2fa|push|prompt|login\s+request|notification)\b",
            r"\b(?:please\s+)?approve\s+(?:it|the\s+push|this\s+request|the\s+prompt)\b",
            r"\b(?:duo\s+|okta\s+)?(?:mfa|2fa)\s+push\b",
            r"\bpush\s+approval\b",
            r"\b(?:route|remit|send|process)\s+(?:the\s+)?(?:upcoming\s+)?(?:invoice\s+(?:#?\d+\s+)?)?payment\s+to\s+(?:our\s+)?new\s+account\b",
            r"\bclick\s+(?:here|the\s+link|below|this\s+link)\s+to\s+(?:login|sign\s*in|verify|confirm|update|unlock|restore)\b",
            r"\bupdate\s+your\s+(?:billing|payment|account|direct\s+deposit)\s+information\b",
            r"\b(?:initiate\s+(?:an?\s+|the\s+)?(?:domestic\s+|international\s+|outbound\s+|electronic\s+|emergency\s+)?|urgent\s+)?wire\s*(?:transfer|funds|money|deposit|payment)?\b",
            r"\b(?:retainer\s+fee|escrow\s+deposit|escrow\s+wire|closing\s+balance|travel\s+stipend)\b",
            r"\b(?:revolut|wise)\s+account\b",
            r"\b(?:updated|new|revised)\s+(?:remittance\s+instructions?|ach\s+banking\s+details|w-9\s+form|banking\s+instructions?)\b",
            r"\b(?:remitted|route\s+all\s+(?:future\s+)?payments?)\s+to\s+(?:our\s+)?(?:new\s+)?(?:chase\s+treasury\s+|commercial\s+)?account\b",
            r"\bupdate\s+(?:your\s+)?(?:erp\s+system|vendor\s+profile|vendor\s+records?)\b",
            r"\b(?:purchase|buy|pick\s+up|grab|get|order|acquire)\s+(?:(?:\d+|several|a\s+few)\s+)?(?:apple|google\s*play|steam|amazon|itunes|electronic|store|prepaid)?\s*(?:gift\s*cards?|store\s*vouchers?|gift\s*vouchers?|gift\s*certificates?|e-?gift\s*cards?)\b",
            r"\b(?:will\s+reimburse(?:\s+you)?|expense\s+reimbursement|reimburse\s+you\s+(?:promptly|immediately|today))\b",
            r"\b(?:swap|switch|change|update|divert|modify)\s+(?:my\s+)?(?:monthly\s+|bi-?weekly\s+)?(?:salary|paycheck|direct\s+deposit|payroll|direct\s+transfer)\s*(?:account|routing|information|details)?\b",
            r"\b(?:salary|paycheck|direct\s+deposit)\s+(?:direct\s+transfer|transfer\s+account|deposit\s+account)\b",
            r"\breset\s+(?:your\s+)?password\b",
            r"\bre-authenticate\s+(?:your\s+)?corporate\s+device\b",
            r"\bdispute\s+transaction\s+and\s+freeze\b",
            r"\b(?:operating\s+liquidity|re-?confirmation\s+of\s+(?:our\s+)?operating\s+liquidity)\b",
        ],
    },
    "deceptive_lures": {
        "title": "Deceptive Document & E-Sign Lures",
        "badge_color": "#06b6d4",  # Cyan
        "icon": "📑",
        "description": "Exploiting modern workplace collaboration tools (OneDrive, SharePoint, DocuSign, Adobe Sign, quarantine portals) to bait victims into clicking credential harvesters.",
        "patterns": [
            r"\bshared\s+a\s+(?:confidential\s+)?document\b",
            r"\bclick\s+here\s+to\s+view\s+document\b",
            r"\b(?:review\s+and\s+)?electronically\s+sign\b",
            r"\bdocusign(?:\s+envelope|\s+security|\s+portal)?\b",
            r"\badobe\s+sign\b",
            r"\bview\s+and\s+sign\s+envelope\b",
            r"\brelease\s+messages\s+to\s+your\s+inbox\b",
            r"\bheld\s+in\s+quarantine\s+server\b",
            r"\bquarantine\s+portal\b",
        ],
    },
}


def analyze_tactics(text: str) -> Dict[str, dict]:
    """
    Analyzes raw text for social engineering tactics and extracts suspicious phrases with exact offsets.

    Returns a dictionary of tactics found, each with details, list of matched phrases, and offsets.
    """
    if not text or not isinstance(text, str):
        return {}

    detected = {}

    for tactic_key, config in TACTIC_DEFINITIONS.items():
        matches_found = []
        seen_spans = set()

        for pattern in config["patterns"]:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                span = match.span()
                matched_str = match.group().strip()

                # Deduplicate overlapping spans
                if any(start <= span[0] and span[1] <= end for start, end in seen_spans):
                    continue

                # Safety check: if preceded by negative assertions (e.g. "we will never ask you to send your password", "never ask for your PIN")
                if tactic_key in ("sensitive_info", "threats"):
                    prefix_window = text[max(0, span[0] - 60):span[0]].lower()
                    if re.search(
                        r"\b(?:never|not|won['']?t|don['']?t)(?:\s+(?:ask|request|solicit|require|demand|contact))?(?:\s+you)?(?:\s+(?:to|for))?\s*$",
                        prefix_window,
                    ):
                        continue

                seen_spans.add(span)
                matches_found.append({
                    "phrase": matched_str,
                    "start": span[0],
                    "end": span[1],
                })

        if matches_found:
            matches_found.sort(key=lambda m: m["start"])
            detected[tactic_key] = {
                "key": tactic_key,
                "title": config["title"],
                "badge_color": config["badge_color"],
                "icon": config["icon"],
                "description": config["description"],
                "matches": matches_found,
                "match_count": len(matches_found),
                "phrases": [m["phrase"] for m in matches_found],
            }

    return detected


def get_all_matched_spans(detected_tactics: Dict[str, dict]) -> List[Tuple[int, int, str, str, str]]:
    """
    Consolidates and non-overlappingly sorts all matched spans across all tactics.
    Returns: List of tuples (start, end, tactic_key, badge_color, title).
    """
    raw_spans = []
    for tactic_key, data in detected_tactics.items():
        for m in data["matches"]:
            raw_spans.append((m["start"], m["end"], tactic_key, data["badge_color"], data["title"]))

    # Sort spans by start offset ascending, then by length descending
    raw_spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))

    filtered_spans = []
    last_end = -1
    for start, end, t_key, color, title in raw_spans:
        if start >= last_end:
            filtered_spans.append((start, end, t_key, color, title))
            last_end = end

    return filtered_spans


def generate_highlighted_html(text: str, detected_tactics: Dict[str, dict]) -> str:
    """
    Generates rich HTML with highlighted suspicious phrases and hover metadata.
    Preserves original casing, newlines, and escapes special HTML characters.
    """
    if not text:
        return ""

    spans = get_all_matched_spans(detected_tactics)
    if not spans:
        return (
            f"<div style='white-space: pre-wrap; font-family: monospace; font-size: 0.95rem; "
            f"line-height: 1.6; background-color: #0f172a; color: #f8fafc; padding: 1.25rem; "
            f"border-radius: 0.5rem; border: 1px solid #334155; max-height: 400px; overflow-y: auto;'>"
            f"{html.escape(text)}</div>"
        )

    html_parts = []
    current_idx = 0

    for start, end, t_key, color, title in spans:
        # Append preceding plain text
        if start > current_idx:
            html_parts.append(html.escape(text[current_idx:start]))

        # Highlighted chunk
        matched_text = html.escape(text[start:end])
        badge_html = (
            f"<mark style='background-color: {color}33; color: inherit; "
            f"border-bottom: 2px solid {color}; padding: 2px 4px; border-radius: 4px; "
            f"font-weight: 600;' title='Tactic: {html.escape(title)}'>{matched_text}"
            f"<span style='font-size: 0.72em; background: {color}; color: white; "
            f"padding: 1px 4px; border-radius: 3px; margin-left: 4px; vertical-align: middle;'>"
            f"{t_key.replace('_', ' ').capitalize()}</span></mark>"
        )
        html_parts.append(badge_html)
        current_idx = end

    # Append trailing plain text
    if current_idx < len(text):
        html_parts.append(html.escape(text[current_idx:]))

    return (
        f"<div style='white-space: pre-wrap; font-family: monospace; font-size: 0.95rem; "
        f"line-height: 1.7; background-color: #0f172a; color: #f8fafc; padding: 1.25rem; "
        f"border-radius: 0.5rem; border: 1px solid #334155; max-height: 400px; overflow-y: auto;'>"
        f"{''.join(html_parts)}</div>"
    )
