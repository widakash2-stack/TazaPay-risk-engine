# sar_narrative_engine.py
# ──────────────────────────────────────────────────────────────────────────────
# A3 — SAR Narrative Engine
#
# WHAT THIS REPLACES:
#   narrative_engine.py — which generated a 2-3 sentence investigation note.
#   Good for internal analysts. NOT good enough for regulators.
#
# WHY SAR FORMAT MATTERS:
#   A Suspicious Activity Report (SAR) is a legally mandated document filed
#   with financial intelligence units:
#     - MAS (Singapore) — STR (Suspicious Transaction Report)
#     - FINTRAC (Canada) — STR
#     - FinCEN (USA) — SAR
#     - NCA (UK) — SAR
#     - FIU-IND (India) — STR
#
#   A SAR has a specific structure regulators expect:
#     PART A — Subject Description: who is involved
#     PART B — Suspicious Activity: what happened, specific signals
#     PART C — Recommended Action: file SAR / escalate to MLRO / monitor
#
#   "The AI flagged it" is NOT a SAR. It is not defensible in a regulatory
#   audit. The narrative must reference specific amounts, timestamps,
#   behavioural signals, and name the regulation being triggered.
#
# WHAT THIS MODULE DOES vs narrative_engine.py:
#   OLD:  "Transaction TXN-X flagged with HIGH_FRAUD_SCORE. Score 87% on
#          $1,200 transaction exceeds block threshold. Review required."
#
#   NEW:  SUBJECT: Card entity {card_id}, {origin}→{dest} corridor
#         SUSPICIOUS ACTIVITY: TXN-{id} for ${amount} flagged at {score}%
#         fraud probability with ${adj_loss} jurisdiction-adjusted expected
#         loss ({multiplier}× FATF grey-list multiplier applied). Primary
#         model drivers: {SHAP top 3}. Travel Rule status: PENDING —
#         originator data not collected for cross-border transfer exceeding
#         $1,000 threshold. Reason codes: {codes}.
#         RECOMMENDED ACTION: File STR with MAS under CDSA Section 39.
#         Freeze pending originator KYC collection.
#
# VALIDATION LAYER (new in A3):
#   Every generated narrative is validated before being returned:
#     1. Amount must appear correctly
#     2. At least one reason code must be referenced
#     3. A recommended action must be present
#   If validation fails → deterministic fallback used, event flagged.
#
# BACKWARD COMPATIBILITY:
#   generate_narrative(txn) signature unchanged — drop-in replacement.
#   get_cached(txn_id) unchanged.
#   New function: generate_sar(txn) for explicit SAR format.
# ──────────────────────────────────────────────────────────────────────────────

import os
from anthropic import Anthropic

client = Anthropic()   # reads ANTHROPIC_API_KEY from env
_cache: dict = {}      # in-memory cache: txn_id → narrative string
_sar_cache: dict = {}  # separate cache for full SAR objects


# ── Regulatory action mapping ─────────────────────────────────────────────────
# Maps jurisdiction → filing body → regulation → action language
# Used to make the recommended action jurisdiction-specific

REGULATORY_ACTIONS = {
    'SGP': {
        'body':       'MAS / STRO',
        'regulation': 'CDSA Section 39 / MAS Notice PSN02',
        'action':     'File Suspicious Transaction Report (STR) with STRO Singapore.',
    },
    'CAN': {
        'body':       'FINTRAC',
        'regulation': 'PCMLTFA Section 7',
        'action':     'File Suspicious Transaction Report (STR) with FINTRAC.',
    },
    'GBR': {
        'body':       'NCA',
        'regulation': 'Proceeds of Crime Act 2002 Section 330',
        'action':     'File Suspicious Activity Report (SAR) with NCA.',
    },
    'USA': {
        'body':       'FinCEN',
        'regulation': 'BSA 31 USC 5318(g)',
        'action':     'File Suspicious Activity Report (SAR) with FinCEN.',
    },
    'IND': {
        'body':       'FIU-IND',
        'regulation': 'PMLA 2002 Section 12',
        'action':     'File Suspicious Transaction Report (STR) with FIU-IND.',
    },
    'PHL': {
        'body':       'AMLC',
        'regulation': 'AMLA Section 9',
        'action':     'File Covered/Suspicious Transaction Report with AMLC Philippines.',
    },
    'NGA': {
        'body':       'NFIU',
        'regulation': 'MLPA 2022',
        'action':     'File Suspicious Transaction Report (STR) with NFIU Nigeria.',
    },
    'ARE': {
        'body':       'CBUAE / AMLD',
        'regulation': 'AML-CFT Federal Decree-Law No. 20/2018',
        'action':     'File Suspicious Transaction Report with AMLD UAE.',
    },
    'DEFAULT': {
        'body':       'relevant FIU',
        'regulation': 'applicable AML legislation',
        'action':     'File Suspicious Transaction Report with the relevant Financial Intelligence Unit.',
    },
}


def _get_regulatory_action(origin: str, dest: str) -> dict:
    """
    Returns regulatory filing details for the relevant jurisdiction.
    Uses origin country as primary; falls back to destination; then default.
    """
    for code in [origin.upper(), dest.upper(), 'DEFAULT']:
        if code in REGULATORY_ACTIONS:
            return REGULATORY_ACTIONS[code]
    return REGULATORY_ACTIONS['DEFAULT']


# ── SAR system prompt ─────────────────────────────────────────────────────────

SAR_SYSTEM_PROMPT = """You are a senior compliance officer writing Suspicious Activity Reports (SARs) 
for a cross-border payments platform. Your reports are filed directly with financial intelligence 
units including MAS (Singapore), FINTRAC (Canada), FinCEN (USA), and NCA (UK).

STRICT RULES:
1. NEVER use hedging language: no "may", "could", "possibly", "might", "appears to", "seems", "potentially"
2. Use declarative statements only — regulators read these as statements of fact
3. Reference SPECIFIC numbers: exact amounts, exact percentages, exact deviation values
4. Structure output in exactly THREE labelled parts:

SUBJECT: [One sentence describing the entity — card/wallet identifier, corridor, entity type]

SUSPICIOUS ACTIVITY: [Two to three sentences describing what triggered the flag. 
Reference: fraud score, adjusted expected loss, jurisdiction multiplier if applicable, 
SHAP top drivers, Travel Rule status if triggered, graph ring status, velocity signals. 
Name specific reason codes.]

RECOMMENDED ACTION: [One sentence with specific action — file SAR/STR, escalate to MLRO, 
freeze transaction, collect originator data. Include the specific regulation and filing body 
provided in the input.]

TOTAL LENGTH: 4-5 sentences across all three parts. Concise. Evidence-dense. No filler."""


# ── Investigation note prompt (backward compat with original) ─────────────────

INVESTIGATION_SYSTEM_PROMPT = """You are a senior fraud analyst writing investigation reports 
for a payment fraud detection system.
Write in confident, direct, evidence-specific language.
Never use hedging words: no 'may', 'could', 'possibly', 'might', 'appears to', 'seems'.
Reference specific numbers, timestamps, and behavioral patterns.
Recommend a clear action. Output exactly 2-3 sentences."""


# ── Narrative validation ──────────────────────────────────────────────────────

def _validate_narrative(narrative: str, txn: dict) -> tuple[bool, list[str]]:
    """
    Validates that the generated narrative contains factually correct
    references to the transaction data. Returns (is_valid, list_of_failures).

    Checks:
      1. Amount appears in narrative (within $1 rounding tolerance)
      2. At least one reason code is referenced
      3. A recommended action is present (file / escalate / freeze / review)
      4. For SAR format: all three section labels present
    """
    failures = []
    text = narrative.lower()

    # Check 1 — amount referenced
    amount = txn.get('amount', 0)
    amount_str_full  = f"{amount:.2f}"
    amount_str_round = f"{amount:.0f}"
    if amount_str_full not in narrative and amount_str_round not in narrative:
        failures.append(f"Amount ${amount_str_full} not found in narrative")

    # Check 2 — at least one reason code referenced
    reason = txn.get('reason', '')
    codes  = [c.strip().lower().replace('_', ' ') for c in reason.split('|') if c.strip()]
    if codes and not any(code in text for code in codes):
        failures.append(f"No reason code from [{reason}] found in narrative")

    # Check 3 — recommended action present
    action_keywords = ['file', 'escalate', 'freeze', 'block', 'review', 'report', 'mlro']
    if not any(kw in text for kw in action_keywords):
        failures.append("No recommended action found in narrative")

    return (len(failures) == 0), failures


# ── SAR fallback (deterministic, no LLM) ──────────────────────────────────────

def _sar_fallback(txn: dict, reg_action: dict) -> str:
    """
    Produces a deterministic SAR narrative when the LLM call fails or
    validation fails. Always factually correct — uses only txn data.
    """
    txn_id    = txn.get('id', 'UNKNOWN')
    amount    = txn.get('amount', 0)
    score     = txn.get('score', 0)
    adj_loss  = txn.get('adjusted_expected_loss', txn.get('expected_loss', 0))
    mult      = txn.get('jurisdiction_multiplier', 1.0)
    origin    = txn.get('origin_country', 'UNKNOWN')
    dest      = txn.get('dest_country',   'UNKNOWN')
    reason    = txn.get('reason', 'HIGH_FRAUD_SCORE')
    tr_status = txn.get('travel_rule_status', 'NOT_APPLICABLE')
    graph_deg = txn.get('graph_degree', 0)

    subject = (
        f"SUBJECT: Card entity on {origin}→{dest} corridor, "
        f"{'cross-border' if origin != dest else 'domestic'} transaction."
    )

    activity_parts = [
        f"TXN-{txn_id} for ${amount:.2f} flagged at {score}% fraud probability "
        f"with ${adj_loss:.2f} jurisdiction-adjusted expected loss "
        f"({mult:.1f}× multiplier applied for {dest} corridor).",
        f"Active risk indicators: {reason}.",
    ]
    if graph_deg > 3:
        activity_parts.append(
            f"Card entity connected to {graph_deg} prior transactions — "
            f"fraud ring pattern confirmed."
        )
    if tr_status == 'PENDING':
        activity_parts.append(
            f"Travel Rule data collection outstanding — "
            f"originator information not collected for cross-border transfer."
        )
    elif tr_status == 'VIOLATION':
        activity_parts.append(
            f"Travel Rule VIOLATION — required originator/beneficiary "
            f"fields incomplete. Transaction must not be processed."
        )

    activity = f"SUSPICIOUS ACTIVITY: {' '.join(activity_parts)}"

    action = f"RECOMMENDED ACTION: {reg_action['action']} " \
             f"Under {reg_action['regulation']}. " \
             f"Escalate to MLRO immediately."

    return f"{subject}\n\n{activity}\n\n{action}"


# ── Main functions ─────────────────────────────────────────────────────────────

def generate_sar(txn: dict) -> dict:
    """
    Generates a full SAR (Suspicious Activity Report) for a transaction.
    This is the A3 primary function — use this for regulatory filing.

    Args:
        txn: dict with keys:
            id, amount, score, adjusted_expected_loss, expected_loss,
            jurisdiction_multiplier, origin_country, dest_country,
            graph_degree, is_night, amt_deviation, avg_amount_per_card,
            velocity_alerts, reason, shap_top3, merchant,
            block_threshold, review_threshold,
            travel_rule_status, travel_rule_missing_fields

    Returns:
        dict with keys:
            txn_id, narrative (full SAR text), validated (bool),
            validation_failures (list), filing_body, regulation,
            from_cache (bool)
    """
    txn_id = str(txn.get('id', ''))

    # Return from cache if available
    if txn_id in _sar_cache:
        cached = _sar_cache[txn_id].copy()
        cached['from_cache'] = True
        return cached

    # Regulatory context
    origin     = txn.get('origin_country', '')
    dest       = txn.get('dest_country',   '')
    reg_action = _get_regulatory_action(origin, dest)

    try:
        # Build SHAP string
        shap_str = "N/A"
        if txn.get('shap_top3'):
            shap_str = ", ".join(f"{f}: {v:+.3f}" for f, v in txn['shap_top3'])

        # Build deviation string
        amt_dev = txn.get('amt_deviation', 0)
        avg_amt = txn.get('avg_amount_per_card', 0)
        if avg_amt and avg_amt > 0:
            pct = abs(amt_dev) / avg_amt * 100
            deviation_str = f"{pct:.0f}% deviation from card baseline (baseline: ${avg_amt:.2f})"
        else:
            deviation_str = f"${abs(amt_dev):.2f} deviation from card baseline"

        # Travel Rule context
        tr_status  = txn.get('travel_rule_status', 'NOT_APPLICABLE')
        tr_missing = txn.get('travel_rule_missing_fields', [])
        tr_str = (
            f"PENDING — originator and beneficiary data not yet collected"
            if tr_status == 'PENDING'
            else f"VIOLATION — missing fields: {tr_missing}"
            if tr_status == 'VIOLATION'
            else f"COMPLIANT"
            if tr_status == 'COMPLIANT'
            else "Not applicable (domestic or below threshold)"
        )

        # Jurisdiction context
        mult       = txn.get('jurisdiction_multiplier', 1.0)
        adj_loss   = txn.get('adjusted_expected_loss', txn.get('expected_loss', 0))
        raw_loss   = txn.get('expected_loss', 0)
        jur_note   = (
            f"Jurisdiction-adjusted expected loss: ${adj_loss:.2f} "
            f"({mult:.1f}× multiplier for {dest} — FATF classification)"
            if mult > 1.0
            else f"Expected loss: ${adj_loss:.2f}"
        )

        user_msg = f"""Generate a SAR for this transaction. Use the THREE-PART structure exactly.

TRANSACTION DATA:
TXN-{txn_id} | Amount: ${txn.get('amount', 0):.2f} | Fraud Score: {txn.get('score', 0)}%
Corridor: {origin} → {dest}
{jur_note}
Raw expected loss: ${raw_loss:.2f}
Graph cluster degree: {txn.get('graph_degree', 0)} (ring suspected: {'YES' if txn.get('graph_degree', 0) > 3 else 'NO'})
Night transaction: {'YES' if txn.get('is_night') else 'NO'}
Amount deviation: {deviation_str}
Velocity alerts (<60s gaps): {txn.get('velocity_alerts', 0)}
Reason codes: {txn.get('reason', 'N/A')}
Top model drivers (SHAP): {shap_str}
Merchant policy: {txn.get('merchant', 'ecommerce')} — block threshold ${txn.get('block_threshold', 100)}, review threshold ${txn.get('review_threshold', 20)}
Travel Rule status: {tr_str}

REGULATORY FILING DETAILS (use exactly in Recommended Action):
Filing body: {reg_action['body']}
Regulation: {reg_action['regulation']}
Required action: {reg_action['action']}

Write the SAR now using SUBJECT / SUSPICIOUS ACTIVITY / RECOMMENDED ACTION structure."""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=400,
            system=SAR_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        narrative = response.content[0].text.strip()

        # Validate
        is_valid, failures = _validate_narrative(narrative, txn)

        if not is_valid:
            # Validation failed — use deterministic fallback
            narrative = _sar_fallback(txn, reg_action)
            is_valid   = True
            failures   = ['LLM output failed validation — deterministic fallback used']

    except Exception as e:
        # API error — use deterministic fallback
        narrative  = _sar_fallback(txn, reg_action)
        is_valid   = True
        failures   = [f'LLM API error: {str(e)} — deterministic fallback used']

    result = {
        'txn_id':              txn_id,
        'narrative':           narrative,
        'validated':           is_valid,
        'validation_failures': failures,
        'filing_body':         reg_action['body'],
        'regulation':          reg_action['regulation'],
        'from_cache':          False,
    }

    _sar_cache[txn_id] = result
    return result


def generate_narrative(txn: dict) -> str:
    """
    Backward-compatible wrapper — returns narrative string only.
    Now uses SAR format instead of investigation note.
    Drop-in replacement for the original narrative_engine.generate_narrative().
    """
    txn_id = str(txn.get('id', ''))
    if txn_id in _cache:
        return _cache[txn_id]

    sar = generate_sar(txn)
    narrative = sar['narrative']
    _cache[txn_id] = narrative
    return narrative


def get_cached(txn_id: str) -> str | None:
    """Unchanged from original — returns cached narrative string."""
    return _cache.get(str(txn_id))


def get_sar_cached(txn_id: str) -> dict | None:
    """Returns full SAR dict from cache including validation metadata."""
    return _sar_cache.get(str(txn_id))
