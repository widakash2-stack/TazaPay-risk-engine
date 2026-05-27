# travel_rule.py
# ──────────────────────────────────────────────────────────────────────────────
# A2 — Travel Rule Compliance Flag
#
# WHY THIS EXISTS:
#   The FATF Travel Rule (Recommendation 16) requires that for any cross-border
#   transaction above $1,000 (or local equivalent), the originating institution
#   MUST collect and transmit the following data to the receiving institution:
#
#   ORIGINATOR (sender):
#     - Full legal name
#     - Account number (wallet address or IBAN)
#     - Physical address OR national identity number OR date+place of birth
#
#   BENEFICIARY (receiver):
#     - Full legal name
#     - Account number (wallet address or IBAN)
#
#   As of 2025, 73% of jurisdictions globally have passed Travel Rule
#   legislation. 100% of surveyed VASPs expect to be compliant by year-end.
#
# TAZAPAY RELEVANCE:
#   Tazapay processes cross-border transactions in 173 countries across fiat
#   AND stablecoin rails. Every transaction above $1,000 on their platform
#   is legally subject to Travel Rule. The compliance platform PM owns this.
#   Not having a Travel Rule flag in the engine is a regulatory gap MAS
#   would flag immediately in an audit.
#
# WHAT THIS MODULE DOES:
#   1. Checks if a transaction triggers Travel Rule (cross-border + amount)
#   2. Returns the exact data fields that must be collected
#   3. Generates a TRAVEL_RULE_REQUIRED reason code
#   4. Checks which fields are already present vs missing
#   5. Assigns a compliance status: COMPLIANT / PENDING / VIOLATION
#   6. Logs all Travel Rule events to travel_rule_log.json
# ──────────────────────────────────────────────────────────────────────────────

import json
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Travel Rule thresholds by jurisdiction ────────────────────────────────────
# Most jurisdictions use $1,000 USD equivalent
# Some have lower thresholds — we use the strictest applicable threshold
# Source: FATF 2023, MAS PSN02, EU TFR, FinCEN CVC Guidance

TRAVEL_RULE_THRESHOLDS = {
    # Jurisdiction: threshold in USD equivalent
    'SGP': 1000,   # MAS: SGD 1,500 ≈ $1,100 — use $1,000 for safety
    'USA': 3000,   # FinCEN: $3,000 for banks, $1,000 for VASPs — use $1,000
    'GBR': 1000,   # FCA: £1,000 ≈ $1,250 — use $1,000
    'EUR': 1000,   # EU TFR: €1,000 ≈ $1,080 — use $1,000
    'DEU': 1000,
    'FRA': 1000,
    'NLD': 1000,
    'CHE': 1000,   # FINMA: CHF 1,000 ≈ $1,100
    'JPN': 1000,   # FSA: ¥100,000 ≈ $670 — use $670 (stricter)
    'KOR': 1000,
    'AUS': 1000,   # AUSTRAC: AUD 1,000 ≈ $650 — use $650
    'CAN': 1000,   # FINTRAC: CAD 1,000 ≈ $740
    'HKG': 1000,
    'IND': 1000,   # RBI: ₹1L ≈ $1,200 — use $1,000
    'PHL': 1000,   # AMLC: PHP 50,000 ≈ $900 — use $900
    'NGA': 1000,
    'ARE': 1000,
    'TUR': 1000,
}

DEFAULT_THRESHOLD = 1000   # USD — applies to any jurisdiction not listed


# ── Required data fields per Travel Rule standard ─────────────────────────────

ORIGINATOR_REQUIRED_FIELDS = [
    'originator_name',           # Full legal name
    'originator_account',        # Account number / wallet address / IBAN
    'originator_address',        # Physical address OR one of the below
    # OR: 'originator_national_id'
    # OR: 'originator_dob' + 'originator_birth_place'
]

ORIGINATOR_ALTERNATIVE_FIELDS = [
    ['originator_national_id'],
    ['originator_dob', 'originator_birth_place'],
]

BENEFICIARY_REQUIRED_FIELDS = [
    'beneficiary_name',          # Full legal name
    'beneficiary_account',       # Account number / wallet address / IBAN
]

# For stablecoin / VASP-to-VASP transfers: additional fields required
VASP_ADDITIONAL_FIELDS = [
    'originator_vasp_name',      # Name of originating VASP
    'originator_vasp_did',       # DID or LEI of originating VASP
    'beneficiary_vasp_name',
    'beneficiary_vasp_did',
]

LOG_FILE = 'travel_rule_log.json'


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TravelRuleResult:
    """
    Result of a Travel Rule check for a single transaction.
    """
    transaction_id:     str
    amount:             float
    origin_country:     str
    dest_country:       str
    is_cross_border:    bool
    threshold_applied:  float
    triggers_travel_rule: bool

    # Compliance status
    # COMPLIANT  — all required fields present
    # PENDING    — triggers rule but fields not yet collected
    # VIOLATION  — triggers rule, fields collected but incomplete
    # NOT_APPLICABLE — domestic or below threshold
    compliance_status:  str

    # Missing fields (empty if compliant or not applicable)
    missing_originator_fields: list = field(default_factory=list)
    missing_beneficiary_fields: list = field(default_factory=list)

    # Reason codes to inject into the fraud engine
    reason_codes: list = field(default_factory=list)

    # Human-readable compliance note for the SAR narrative
    compliance_note: str = ''

    # Timestamp
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # Is this a VASP-to-VASP stablecoin transfer?
    is_vasp_transfer: bool = False


def get_threshold(country_code: str) -> float:
    """Returns the Travel Rule threshold in USD for a given jurisdiction."""
    return TRAVEL_RULE_THRESHOLDS.get(
        country_code.upper().strip() if country_code else '',
        DEFAULT_THRESHOLD
    )


def check_travel_rule(
    transaction_id: str,
    amount: float,
    origin_country: str,
    dest_country: str,
    provided_fields: Optional[dict] = None,
    is_vasp_transfer: bool = False,
) -> TravelRuleResult:
    """
    Checks whether a transaction triggers the Travel Rule and
    whether the required data fields have been collected.

    Args:
        transaction_id:   Unique transaction identifier
        amount:           Transaction amount in USD
        origin_country:   ISO 3-letter origin country code
        dest_country:     ISO 3-letter destination country code
        provided_fields:  Dict of field_name → value already collected
                          Pass None or {} to simulate "nothing collected yet"
        is_vasp_transfer: True if this is a VASP-to-VASP stablecoin transfer
                          (triggers additional VASP fields requirement)

    Returns:
        TravelRuleResult dataclass

    Example — Singapore to Nigeria, $1,500, nothing collected:
        check_travel_rule('TXN-001', 1500, 'SGP', 'NGA')
        → triggers_travel_rule = True
        → compliance_status = 'PENDING'
        → missing_originator_fields = ['originator_name', 'originator_account', ...]
        → reason_codes = ['TRAVEL_RULE_REQUIRED']

    Example — Singapore domestic, $5,000, nothing collected:
        check_travel_rule('TXN-002', 5000, 'SGP', 'SGP')
        → triggers_travel_rule = False
        → compliance_status = 'NOT_APPLICABLE'
        → reason_codes = []
    """
    provided = provided_fields or {}
    origin   = (origin_country or '').upper().strip()
    dest     = (dest_country   or '').upper().strip()

    # Step 1 — Is this cross-border?
    is_cross_border = (origin != dest) and bool(origin) and bool(dest)

    if not is_cross_border:
        return TravelRuleResult(
            transaction_id      = transaction_id,
            amount              = amount,
            origin_country      = origin,
            dest_country        = dest,
            is_cross_border     = False,
            threshold_applied   = DEFAULT_THRESHOLD,
            triggers_travel_rule= False,
            compliance_status   = 'NOT_APPLICABLE',
            compliance_note     = 'Domestic transaction — Travel Rule does not apply.',
            is_vasp_transfer    = is_vasp_transfer,
        )

    # Step 2 — Does amount exceed the threshold?
    # Use the LOWER of the two jurisdictions' thresholds (strictest applies)
    threshold = min(get_threshold(origin), get_threshold(dest))

    if amount < threshold:
        return TravelRuleResult(
            transaction_id      = transaction_id,
            amount              = amount,
            origin_country      = origin,
            dest_country        = dest,
            is_cross_border     = True,
            threshold_applied   = threshold,
            triggers_travel_rule= False,
            compliance_status   = 'NOT_APPLICABLE',
            compliance_note     = (
                f'Amount ${amount:.2f} below Travel Rule threshold '
                f'${threshold:.0f} for {origin}→{dest} corridor.'
            ),
            is_vasp_transfer    = is_vasp_transfer,
        )

    # Step 3 — Travel Rule TRIGGERED. Check which fields are present.
    missing_orig = []
    missing_bene = []
    reason_codes = ['TRAVEL_RULE_REQUIRED']

    # Check originator required fields
    for f_name in ORIGINATOR_REQUIRED_FIELDS:
        if not provided.get(f_name):
            missing_orig.append(f_name)

    # If originator_address is missing, check if an alternative satisfies it
    if 'originator_address' in missing_orig:
        alt_satisfied = any(
            all(provided.get(alt_f) for alt_f in alt_group)
            for alt_group in ORIGINATOR_ALTERNATIVE_FIELDS
        )
        if alt_satisfied:
            missing_orig.remove('originator_address')

    # Check beneficiary required fields
    for f_name in BENEFICIARY_REQUIRED_FIELDS:
        if not provided.get(f_name):
            missing_bene.append(f_name)

    # Check VASP-specific fields if applicable
    missing_vasp = []
    if is_vasp_transfer:
        for f_name in VASP_ADDITIONAL_FIELDS:
            if not provided.get(f_name):
                missing_vasp.append(f_name)
        if missing_vasp:
            reason_codes.append('VASP_FIELDS_MISSING')

    # Step 4 — Determine compliance status
    all_missing = missing_orig + missing_bene + missing_vasp

    if not provided:
        # Nothing collected at all
        compliance_status = 'PENDING'
        compliance_note = (
            f'Travel Rule triggered: ${amount:.2f} cross-border '
            f'{origin}→{dest} exceeds ${threshold:.0f} threshold. '
            f'Originator and beneficiary data collection required before processing.'
        )
        reason_codes.append('DATA_COLLECTION_REQUIRED')

    elif all_missing:
        # Some fields collected but incomplete
        compliance_status = 'VIOLATION'
        compliance_note = (
            f'Travel Rule violation: {len(all_missing)} required field(s) missing '
            f'for ${amount:.2f} {origin}→{dest} transaction. '
            f'Transaction must not be processed until complete.'
        )
        reason_codes.append('TRAVEL_RULE_INCOMPLETE')

    else:
        # All required fields present
        compliance_status = 'COMPLIANT'
        compliance_note = (
            f'Travel Rule satisfied: all required originator and beneficiary '
            f'data collected for ${amount:.2f} {origin}→{dest} transaction.'
        )

    return TravelRuleResult(
        transaction_id        = transaction_id,
        amount                = amount,
        origin_country        = origin,
        dest_country          = dest,
        is_cross_border       = True,
        threshold_applied     = threshold,
        triggers_travel_rule  = True,
        compliance_status     = compliance_status,
        missing_originator_fields = missing_orig,
        missing_beneficiary_fields= missing_bene,
        reason_codes          = reason_codes,
        compliance_note       = compliance_note,
        is_vasp_transfer      = is_vasp_transfer,
    )


def get_travel_rule_reason_codes(result: TravelRuleResult) -> list[str]:
    """
    Returns list of reason codes from a TravelRuleResult.
    Plugs directly into get_reason_codes() in fraud_engine.
    """
    return result.reason_codes if result.triggers_travel_rule else []


def log_travel_rule_event(result: TravelRuleResult) -> None:
    """
    Appends a Travel Rule event to travel_rule_log.json.
    Only logs transactions that actually trigger the rule.
    Used for MAS audit trail and MLRO reporting.
    """
    if not result.triggers_travel_rule:
        return

    log = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                log = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            log = []

    log.append(asdict(result))

    with open(LOG_FILE, 'w') as f:
        json.dump(log, f, indent=2)


def get_travel_rule_summary(log_file: str = LOG_FILE) -> dict:
    """
    Returns aggregate Travel Rule compliance stats from the log.
    Used in dashboard display and MLRO reports.
    """
    try:
        with open(log_file) as f:
            log = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'total_triggered': 0,
            'compliant': 0,
            'pending': 0,
            'violation': 0,
            'not_applicable': 0,
        }

    return {
        'total_triggered': sum(1 for e in log if e.get('triggers_travel_rule')),
        'compliant':       sum(1 for e in log if e.get('compliance_status') == 'COMPLIANT'),
        'pending':         sum(1 for e in log if e.get('compliance_status') == 'PENDING'),
        'violation':       sum(1 for e in log if e.get('compliance_status') == 'VIOLATION'),
        'not_applicable':  sum(1 for e in log if e.get('compliance_status') == 'NOT_APPLICABLE'),
    }


# ── Self-test — run: python travel_rule.py ────────────────────────────────────
if __name__ == '__main__':
    print("=" * 70)
    print("TRAVEL RULE MODULE — SELF TEST")
    print("=" * 70)

    test_cases = [
        # (txn_id, amount, origin, dest, provided_fields, is_vasp, description)
        (
            'TXN-001', 1500, 'SGP', 'NGA', {},
            False,
            'SGP→NGA $1,500 — triggers, nothing collected → PENDING'
        ),
        (
            'TXN-002', 500, 'SGP', 'NGA', {},
            False,
            'SGP→NGA $500 — below threshold → NOT_APPLICABLE'
        ),
        (
            'TXN-003', 5000, 'SGP', 'SGP', {},
            False,
            'SGP→SGP $5,000 — domestic → NOT_APPLICABLE'
        ),
        (
            'TXN-004', 2000, 'IND', 'PHL',
            {
                'originator_name': 'Raj Kumar',
                'originator_account': 'IN123456789',
                'originator_national_id': 'AABPK1234A',  # satisfies address alternative
                'beneficiary_name': 'Maria Santos',
                # missing beneficiary_account
            },
            False,
            'IND→PHL $2,000 — partial data → VIOLATION'
        ),
        (
            'TXN-005', 3000, 'GBR', 'IND',
            {
                'originator_name': 'John Smith',
                'originator_account': 'GB29NWBK60161331926819',
                'originator_address': '10 Downing St, London',
                'beneficiary_name': 'Priya Sharma',
                'beneficiary_account': 'IN987654321',
            },
            False,
            'GBR→IND $3,000 — all fields present → COMPLIANT'
        ),
        (
            'TXN-006', 1200, 'SGP', 'PHL',
            {},
            True,   # VASP-to-VASP stablecoin transfer
            'SGP→PHL $1,200 VASP transfer — triggers + VASP fields required'
        ),
        (
            'TXN-007', 999, 'USA', 'NGA', {},
            False,
            'USA→NGA $999 — $1 below threshold → NOT_APPLICABLE'
        ),
        (
            'TXN-008', 1001, 'USA', 'NGA', {},
            False,
            'USA→NGA $1,001 — $1 above threshold → PENDING'
        ),
    ]

    for txn_id, amount, origin, dest, fields, is_vasp, desc in test_cases:
        result = check_travel_rule(txn_id, amount, origin, dest, fields, is_vasp)

        status_symbol = {
            'COMPLIANT':      '✅',
            'PENDING':        '⏳',
            'VIOLATION':      '🚨',
            'NOT_APPLICABLE': '—',
        }.get(result.compliance_status, '?')

        print(f"\n{status_symbol} {desc}")
        print(f"   Status:         {result.compliance_status}")
        print(f"   Triggers rule:  {result.triggers_travel_rule}")
        print(f"   Threshold:      ${result.threshold_applied:.0f}")
        if result.triggers_travel_rule:
            print(f"   Reason codes:   {result.reason_codes}")
        if result.missing_originator_fields:
            print(f"   Missing orig:   {result.missing_originator_fields}")
        if result.missing_beneficiary_fields:
            print(f"   Missing bene:   {result.missing_beneficiary_fields}")
        print(f"   Note:           {result.compliance_note}")

    print("\n" + "=" * 70)
    print("INTEGRATION INSTRUCTIONS")
    print("=" * 70)
    print("""
STEP 1 — Import in fraud_engine_a1.py:
    from travel_rule import check_travel_rule, get_travel_rule_reason_codes, log_travel_rule_event

STEP 2 — After computing origin_country, dest_country for each transaction:
    tr_result = check_travel_rule(
        transaction_id = f'TXN-{idx}',
        amount         = amount,
        origin_country = origin_country,
        dest_country   = dest_country,
        provided_fields= {},          # empty = nothing collected yet (PENDING)
        is_vasp_transfer = False,     # set True for stablecoin VASP transfers
    )

STEP 3 — Inject Travel Rule reason codes into existing reason codes:
    tr_codes = get_travel_rule_reason_codes(tr_result)
    # These are added AFTER jurisdiction codes, BEFORE ML codes in get_reason_codes()

STEP 4 — Log the event for MAS audit trail:
    log_travel_rule_event(tr_result)

STEP 5 — If compliance_status == 'VIOLATION', force REVIEW minimum:
    if tr_result.compliance_status == 'VIOLATION':
        decision = max_severity(decision, 'REVIEW')
        # A transaction with missing Travel Rule data cannot be ALLOW'd
""")
