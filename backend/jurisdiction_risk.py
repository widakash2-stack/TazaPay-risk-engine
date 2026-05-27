# jurisdiction_risk.py
# ──────────────────────────────────────────────────────────────────────────────
# A1 — Jurisdiction Risk Multiplier
#
# WHY THIS EXISTS:
#   The base engine treats every transaction identically regardless of where
#   the money comes from or goes to. That is wrong for cross-border compliance.
#   A $500 transaction from a FATF grey-listed country carries far more
#   regulatory risk than a $5,000 transaction from Singapore.
#
#   This module adds a jurisdiction_multiplier to every transaction so that:
#       adjusted_expected_loss = fraud_score × amount × jurisdiction_multiplier
#
#   The BLOCK/REVIEW/ALLOW decision is then made on adjusted_expected_loss,
#   not raw expected_loss. Same ML score — smarter action.
#
# HOW MULTIPLIERS ARE SET (FATF framework):
#   1.0×  — MAS / FCA / FinCEN regulated, low-risk (Singapore, UK, US, EU)
#   1.5×  — Standard monitored jurisdictions
#   2.5×  — FATF grey-list (Enhanced Due Diligence required)
#   5.0×  — FATF black-list / high-risk non-cooperative
#   3.0×  — Crypto-high-risk (legal but high stablecoin abuse history)
#
# TAZAPAY RELEVANCE:
#   Tazapay operates in 173 countries across APAC, LATAM, Africa, Middle East.
#   Each corridor has a different regulatory risk profile. This multiplier
#   makes the decisioning engine geography-aware — which is table stakes
#   for a cross-border compliance platform.
# ──────────────────────────────────────────────────────────────────────────────

# ── FATF and regulatory tier classifications ───────────────────────────────────
# Source: FATF October 2023 list + MAS guidance + internal risk tiering logic

JURISDICTION_TIERS = {

    # ── TIER 1: Low risk — MAS / FCA / FinCEN regulated (1.0×) ──────────────
    'SGP': 1.0,   # Singapore — MAS licensed, Tazapay HQ
    'GBR': 1.0,   # United Kingdom — FCA regulated
    'USA': 1.0,   # United States — FinCEN / OCC
    'DEU': 1.0,   # Germany — BaFin
    'FRA': 1.0,   # France — ACPR
    'NLD': 1.0,   # Netherlands — DNB
    'AUS': 1.0,   # Australia — AUSTRAC
    'JPN': 1.0,   # Japan — FSA
    'CAN': 1.0,   # Canada — FINTRAC (Tazapay licensed here)
    'HKG': 1.0,   # Hong Kong — HKMA
    'NZL': 1.0,   # New Zealand — FMA
    'CHE': 1.0,   # Switzerland — FINMA
    'SWE': 1.0,   # Sweden — Finansinspektionen
    'NOR': 1.0,   # Norway — Finanstilsynet
    'DNK': 1.0,   # Denmark — Finanstilsynet
    'FIN': 1.0,   # Finland — FIN-FSA
    'KOR': 1.0,   # South Korea — FSC
    'ISR': 1.0,   # Israel — Bank of Israel

    # ── TIER 2: Standard monitored — normal scrutiny (1.5×) ─────────────────
    'IND': 1.5,   # India — RBI monitored, high volume for Tazapay
    'BRA': 1.5,   # Brazil — Banco Central
    'MEX': 1.5,   # Mexico — CNBV
    'ZAF': 1.5,   # South Africa — SARB
    'MYS': 1.5,   # Malaysia — BNM
    'THA': 1.5,   # Thailand — BOT
    'IDN': 1.5,   # Indonesia — OJK
    'VNM': 1.5,   # Vietnam — SBV
    'BGD': 1.5,   # Bangladesh — BB
    'KHM': 1.5,   # Cambodia — NBC
    'LKA': 1.5,   # Sri Lanka — CBSL
    'GHA': 1.5,   # Ghana — BOG
    'KEN': 1.5,   # Kenya — CBK
    'TZA': 1.5,   # Tanzania — BOT
    'UGA': 1.5,   # Uganda — BOU
    'ETH': 1.5,   # Ethiopia — NBE
    'EGY': 1.5,   # Egypt — CBE
    'SAU': 1.5,   # Saudi Arabia — SAMA
    'QAT': 1.5,   # Qatar — QCB
    'KWT': 1.5,   # Kuwait — CBK
    'OMN': 1.5,   # Oman — CBO

    # ── TIER 3: FATF grey-list — Enhanced Due Diligence required (2.5×) ─────
    # FATF grey-list as of October 2023
    'PHL': 2.5,   # Philippines — AMLC (grey-listed, major Tazapay corridor)
    'NGA': 2.5,   # Nigeria — NFIU (grey-listed, major Africa corridor)
    'PAK': 2.5,   # Pakistan — FMU
    'ARE': 2.5,   # UAE — CBUAE (grey-listed until 2024, treat as elevated)
    'TUR': 2.5,   # Turkey — MASAK
    'SYR': 2.5,   # Syria
    'YEM': 2.5,   # Yemen
    'MLI': 2.5,   # Mali
    'MOZ': 2.5,   # Mozambique
    'TZA': 2.5,   # Tanzania (uplisted)
    'KHM': 2.5,   # Cambodia (uplisted)
    'HTI': 2.5,   # Haiti
    'JAM': 2.5,   # Jamaica
    'VEN': 2.5,   # Venezuela
    'PAN': 2.5,   # Panama
    'GIB': 2.5,   # Gibraltar
    'HRV': 2.5,   # Croatia (recently added)
    'NMI': 2.5,   # Nigeria (duplicate ISO guard)

    # ── TIER 4: Crypto high-risk — legal but elevated stablecoin abuse (3.0×)
    'RUS': 3.0,   # Russia — sanctioned entities prevalent, stablecoin evasion
    'BLR': 3.0,   # Belarus
    'IRN': 5.0,   # Iran — FATF black-list (see Tier 5 below)
    'PRK': 5.0,   # North Korea — FATF black-list
    'MMR': 3.0,   # Myanmar — coup, financial instability
    'AFG': 3.0,   # Afghanistan — Taliban governance

    # ── TIER 5: FATF black-list — high-risk non-cooperative (5.0×) ──────────
    # Transactions from these jurisdictions should almost always be BLOCKED
    # regardless of ML score
    'IRN': 5.0,   # Iran
    'PRK': 5.0,   # North Korea
    'MYA': 5.0,   # Myanmar (alt ISO)
}

# Default multiplier for any country not in the table
DEFAULT_MULTIPLIER = 1.5   # treat unknown as standard monitored

# Hard-block jurisdictions regardless of ML score
# These get BLOCK (jurisdiction) decision before ML score is even consulted
HARD_BLOCK_JURISDICTIONS = {'IRN', 'PRK'}


def get_multiplier(country_code: str) -> float:
    """
    Returns the jurisdiction risk multiplier for a given ISO 3166-1 alpha-3
    country code.

    Args:
        country_code: Three-letter ISO country code e.g. 'SGP', 'NGA', 'IND'

    Returns:
        float: Risk multiplier in range [1.0, 5.0]

    Example:
        >>> get_multiplier('SGP')
        1.0
        >>> get_multiplier('NGA')
        2.5
        >>> get_multiplier('IRN')
        5.0
    """
    code = country_code.upper().strip() if country_code else ''
    return JURISDICTION_TIERS.get(code, DEFAULT_MULTIPLIER)


def is_hard_block(country_code: str) -> bool:
    """
    Returns True if this jurisdiction is on the hard-block list.
    These transactions are blocked BEFORE the ML model is even consulted.
    OFAC and UN sanctions make these non-negotiable.

    Args:
        country_code: Three-letter ISO country code

    Returns:
        bool
    """
    code = country_code.upper().strip() if country_code else ''
    return code in HARD_BLOCK_JURISDICTIONS


def get_adjusted_expected_loss(
    fraud_score: float,
    amount: float,
    origin_country: str,
    destination_country: str,
) -> dict:
    """
    Computes jurisdiction-adjusted expected loss for a cross-border transaction.

    Uses the HIGHER of origin and destination multipliers — because a transaction
    is only as safe as its riskiest endpoint.

    Args:
        fraud_score:        ML fraud probability in [0, 1]
        amount:             Transaction amount in USD
        origin_country:     ISO 3-letter code of sender country
        destination_country: ISO 3-letter code of receiver country

    Returns:
        dict with keys:
            raw_expected_loss       — score × amount (no geo adjustment)
            adjusted_expected_loss  — score × amount × multiplier
            multiplier              — the applied multiplier
            origin_multiplier       — multiplier for origin country
            destination_multiplier  — multiplier for destination country
            dominant_country        — which endpoint drove the multiplier
            hard_block              — True if either endpoint is hard-blocked

    Example:
        >>> get_adjusted_expected_loss(0.10, 5000, 'SGP', 'NGA')
        {
          'raw_expected_loss': 500.0,
          'adjusted_expected_loss': 1250.0,   # 500 × 2.5
          'multiplier': 2.5,
          'origin_multiplier': 1.0,
          'destination_multiplier': 2.5,
          'dominant_country': 'NGA',
          'hard_block': False
        }
    """
    origin_m = get_multiplier(origin_country)
    dest_m   = get_multiplier(destination_country)

    # Use the riskier endpoint — a transaction is only as safe as its worst end
    multiplier = max(origin_m, dest_m)
    dominant   = origin_country if origin_m >= dest_m else destination_country

    raw_loss      = fraud_score * amount
    adjusted_loss = raw_loss * multiplier

    hard_block = is_hard_block(origin_country) or is_hard_block(destination_country)

    return {
        'raw_expected_loss':      round(raw_loss, 2),
        'adjusted_expected_loss': round(adjusted_loss, 2),
        'multiplier':             multiplier,
        'origin_multiplier':      origin_m,
        'destination_multiplier': dest_m,
        'dominant_country':       dominant,
        'hard_block':             hard_block,
    }


def get_jurisdiction_reason_code(country_code: str) -> str | None:
    """
    Returns a reason code string if the jurisdiction warrants one,
    or None if it's a standard low-risk country.

    Plugs directly into the existing get_reason_codes() function in
    fraud_engine.py and dashboard.py.

    Args:
        country_code: ISO 3-letter code

    Returns:
        str reason code or None
    """
    if is_hard_block(country_code):
        return 'SANCTIONED_JURISDICTION'

    m = get_multiplier(country_code)
    if m >= 5.0:
        return 'SANCTIONED_JURISDICTION'
    elif m >= 3.0:
        return 'CRYPTO_HIGH_RISK_JURISDICTION'
    elif m >= 2.5:
        return 'FATF_GREY_LIST'
    elif m >= 1.5:
        return 'ELEVATED_JURISDICTION_RISK'
    else:
        return None   # 1.0× — no reason code needed


def get_tier_label(country_code: str) -> str:
    """Human-readable tier label for dashboard display."""
    m = get_multiplier(country_code)
    if m >= 5.0: return 'SANCTIONED (5.0×)'
    if m >= 3.0: return 'CRYPTO HIGH-RISK (3.0×)'
    if m >= 2.5: return 'FATF GREY-LIST (2.5×)'
    if m >= 1.5: return 'ELEVATED (1.5×)'
    return 'LOW RISK (1.0×)'


# ── Self-test — run: python jurisdiction_risk.py ───────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("JURISDICTION RISK MODULE — SELF TEST")
    print("=" * 60)

    test_cases = [
        # (origin, destination, score, amount, description)
        ('SGP', 'SGP', 0.10, 5000,  'Singapore domestic — low risk'),
        ('IND', 'SGP', 0.10, 5000,  'India → Singapore — standard'),
        ('SGP', 'NGA', 0.10, 5000,  'Singapore → Nigeria — FATF grey'),
        ('NGA', 'NGA', 0.10, 5000,  'Nigeria → Nigeria — FATF grey'),
        ('RUS', 'SGP', 0.10, 5000,  'Russia → Singapore — crypto high-risk'),
        ('SGP', 'IRN', 0.10, 5000,  'Singapore → Iran — hard block'),
        ('IND', 'PHL', 0.08, 1200,  'India → Philippines — Tazapay corridor'),
        ('USA', 'VEN', 0.15, 3000,  'USA → Venezuela — FATF grey'),
    ]

    print(f"\n{'Origin':>6} {'Dest':>6} {'Score':>6} {'Amount':>8} "
          f"{'Raw Loss':>10} {'Adj Loss':>10} {'Mult':>5} {'Reason Code':<30} Description")
    print("-" * 120)

    for origin, dest, score, amount, desc in test_cases:
        result = get_adjusted_expected_loss(score, amount, origin, dest)
        reason = (
            get_jurisdiction_reason_code(dest) or
            get_jurisdiction_reason_code(origin) or
            'NORMAL'
        )
        hard = ' ⛔ HARD BLOCK' if result['hard_block'] else ''
        print(
            f"{origin:>6} {dest:>6} {score:>6.0%} ${amount:>7,.0f} "
            f"  ${result['raw_expected_loss']:>8,.2f} "
            f"  ${result['adjusted_expected_loss']:>8,.2f} "
            f"  {result['multiplier']:>4.1f}× "
            f"  {reason:<30} {desc}{hard}"
        )

    print("\n" + "=" * 60)
    print("INTEGRATION INSTRUCTIONS")
    print("=" * 60)
    print("""
STEP 1 — Import in fraud_engine.py and dashboard.py:
    from jurisdiction_risk import get_adjusted_expected_loss, get_jurisdiction_reason_code, is_hard_block

STEP 2 — Add origin/destination country to each transaction.
    In the live system these come from the merchant's KYC record and
    the transaction routing metadata.
    For the demo, assign countries based on card_id buckets:
        DEMO_COUNTRY_MAP = { ... }  (see fraud_engine_a1.py)

STEP 3 — Replace expected_loss with adjusted_expected_loss in decisioning:
    # BEFORE:
    expected_loss = score * amount

    # AFTER:
    jur = get_adjusted_expected_loss(score, amount, origin_country, dest_country)
    expected_loss       = jur['raw_expected_loss']
    adjusted_loss       = jur['adjusted_expected_loss']
    jur_multiplier      = jur['multiplier']
    jur_hard_block      = jur['hard_block']
    jur_dominant        = jur['dominant_country']

STEP 4 — Add jurisdiction reason code:
    jur_code = get_jurisdiction_reason_code(dest_country) or get_jurisdiction_reason_code(origin_country)
    if jur_code:
        codes.append(jur_code)

STEP 5 — Hard block gate BEFORE ML score:
    if jur_hard_block:
        decision = "BLOCK (sanctions)"
        # Skip ML scoring entirely
""")
