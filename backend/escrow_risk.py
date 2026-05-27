# escrow_risk.py
# ──────────────────────────────────────────────────────────────────────────────
# A7 — Escrow-Specific Risk Rules
#
# WHY THIS EXISTS:
#   Tazapay's escrow product is their most differentiated offering.
#   No competitor at this scale has it.
#
#   But escrow has fundamentally different compliance treatment than a payment:
#
#   PAYMENT:
#     Money moves A → B. Risk window: seconds to minutes.
#     AML question: is the money clean? Is A/B sanctioned?
#
#   ESCROW:
#     Money moves A → HELD BY TAZAPAY → B (on condition).
#     Risk window: days to weeks.
#     AML question: is the money clean? Are A/B sanctioned?
#     PLUS: Is this escrow being used to park dirty money?
#     PLUS: Is the underlying trade real or fictitious?
#     PLUS: What if there's a dispute — whose money is it while frozen?
#     PLUS: Does the jurisdictional AML clock start at deposit or release?
#
#   MAS Notice PSN02 requires that funds held in trust (escrow) have:
#     1. Segregated accounts (cannot be commingled with operating funds)
#     2. Enhanced due diligence on BOTH counterparties
#     3. Source of funds documentation for amounts > $20,000
#     4. Specific reporting timeline for frozen/disputed funds
#
#   This module adds a risk layer specifically for escrow transactions —
#   different thresholds, different reason codes, different escalation path.
#
# ESCROW-SPECIFIC RISK SIGNALS:
#   1. COUNTERPARTY_UNVERIFIED — one side not KYC'd yet
#   2. FICTITIOUS_TRADE_RISK   — trade details inconsistent / missing
#   3. ESCROW_AMOUNT_SPIKE     — amount far above this counterparty's history
#   4. EXTENDED_HOLD_RISK      — funds held > 30 days = enhanced monitoring
#   5. DISPUTE_FREEZE_RISK     — disputed escrow triggers separate SAR obligation
#   6. SOURCE_OF_FUNDS_REQUIRED — amounts > $20,000 require SOF documentation
#   7. CROSS_BORDER_ESCROW     — cross-border escrow has dual jurisdiction AML
# ──────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


# ── Escrow risk thresholds ────────────────────────────────────────────────────
ESCROW_SOURCE_OF_FUNDS_THRESHOLD = 20_000   # USD — SOF documentation required
ESCROW_ENHANCED_DD_THRESHOLD     = 10_000   # USD — enhanced due diligence
ESCROW_EXTENDED_HOLD_DAYS        = 30       # days held before enhanced monitoring
ESCROW_DISPUTE_FREEZE_HOURS      = 72       # hours to resolve dispute before SAR

# Escrow-specific block threshold (tighter than regular transactions)
# Escrow funds held in trust = higher regulatory accountability
ESCROW_BLOCK_THRESHOLD           = 50       # expected loss (tighter than ecommerce $100)
ESCROW_REVIEW_THRESHOLD          = 10       # expected loss


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class EscrowContext:
    """
    All escrow-specific context for a transaction.
    In production populated from Tazapay's escrow management system.
    """
    escrow_id:              str
    amount_usd:             float

    # Counterparty verification status
    buyer_kyc_status:       str     # VERIFIED / PENDING / FAILED
    seller_kyc_status:      str     # VERIFIED / PENDING / FAILED

    # Trade details
    trade_description:      str     # what goods/services are being exchanged
    trade_document_present: bool    # PO / invoice / contract uploaded
    incoterms:              str     # EXW / FOB / CIF / DDP etc (or NONE)

    # History
    buyer_prior_escrows:    int     = 0     # number of prior escrow transactions
    seller_prior_escrows:   int     = 0
    buyer_avg_escrow_usd:   float   = 0.0   # buyer's average escrow amount
    seller_avg_escrow_usd:  float   = 0.0

    # Timing
    created_at:             str     = field(default_factory=lambda: datetime.now().isoformat())
    expected_release_days:  int     = 14    # expected hold period
    actual_hold_days:       int     = 0     # how long funds have been held so far

    # Dispute status
    dispute_raised:         bool    = False
    dispute_raised_at:      str     = ''

    # Geography
    origin_country:         str     = ''
    dest_country:           str     = ''
    is_cross_border:        bool    = False


@dataclass
class EscrowRiskResult:
    """
    Result of escrow-specific risk assessment.
    """
    escrow_id:              str
    amount_usd:             float

    # Risk scores
    counterparty_risk:      float   # [0, 1] — KYC verification risk
    trade_legitimacy_risk:  float   # [0, 1] — fictitious trade risk
    amount_spike_risk:      float   # [0, 1] — anomalous amount for this entity
    hold_duration_risk:     float   # [0, 1] — extended hold risk
    dispute_risk:           float   # [0, 1] — active dispute risk
    composite_escrow_risk:  float   # weighted composite [0, 1]

    # Compliance requirements triggered
    source_of_funds_required:   bool = False
    enhanced_dd_required:       bool = False
    direct_mlro_escalation:     bool = False
    segregated_account_required:bool = True   # always True for escrow

    # Reason codes
    reason_codes:           list = field(default_factory=list)

    # Decision
    escrow_decision:        str  = 'ALLOW'   # ALLOW / REVIEW / BLOCK / HOLD_PENDING_SOF

    # SAR obligations
    sar_required:           bool = False
    sar_obligation_note:    str  = ''

    # Summary
    escrow_summary:         str  = ''


def assess_escrow_risk(
    context: EscrowContext,
    base_fraud_score: float,    # ML score from the base engine
) -> EscrowRiskResult:
    """
    Runs escrow-specific risk assessment on top of the base fraud score.

    Args:
        context:          EscrowContext with all escrow metadata
        base_fraud_score: ML fraud probability from the main engine [0, 1]

    Returns:
        EscrowRiskResult
    """
    reason_codes     = []
    sar_required     = False
    sar_note         = ''

    # ── Signal 1: Counterparty verification ───────────────────────────────────
    unverified_count = sum([
        context.buyer_kyc_status  != 'VERIFIED',
        context.seller_kyc_status != 'VERIFIED',
    ])
    counterparty_risk = unverified_count * 0.5   # 0, 0.5, or 1.0

    if context.buyer_kyc_status != 'VERIFIED':
        reason_codes.append('BUYER_UNVERIFIED')
    if context.seller_kyc_status != 'VERIFIED':
        reason_codes.append('SELLER_UNVERIFIED')
    if unverified_count == 2:
        reason_codes.append('BOTH_COUNTERPARTIES_UNVERIFIED')
        sar_required = True
        sar_note     = 'Both counterparties unverified — escrow cannot be released.'

    # ── Signal 2: Trade legitimacy ────────────────────────────────────────────
    trade_risk_score = 0.0
    if not context.trade_document_present:
        trade_risk_score += 0.40
        reason_codes.append('TRADE_DOCUMENT_MISSING')
    if not context.trade_description or len(context.trade_description.strip()) < 10:
        trade_risk_score += 0.30
        reason_codes.append('TRADE_DESCRIPTION_INSUFFICIENT')
    if context.incoterms == 'NONE' and context.amount_usd > 5000:
        trade_risk_score += 0.20
        reason_codes.append('INCOTERMS_MISSING_HIGH_VALUE')
    trade_legitimacy_risk = min(1.0, trade_risk_score)

    if trade_legitimacy_risk >= 0.60:
        reason_codes.append('FICTITIOUS_TRADE_RISK')
        sar_required = True
        sar_note = sar_note or 'Trade legitimacy risk: insufficient documentation for escrow amount.'

    # ── Signal 3: Amount spike ────────────────────────────────────────────────
    amount_spike_risk = 0.0
    buyer_baseline    = context.buyer_avg_escrow_usd
    seller_baseline   = context.seller_avg_escrow_usd

    if buyer_baseline > 0:
        buyer_ratio = context.amount_usd / buyer_baseline
        if buyer_ratio > 5.0:
            amount_spike_risk = min(1.0, (buyer_ratio - 5.0) / 10.0 + 0.5)
            reason_codes.append('BUYER_AMOUNT_SPIKE')
    elif context.buyer_prior_escrows == 0 and context.amount_usd > ESCROW_ENHANCED_DD_THRESHOLD:
        amount_spike_risk = 0.40
        reason_codes.append('BUYER_FIRST_ESCROW_HIGH_VALUE')

    if seller_baseline > 0:
        seller_ratio = context.amount_usd / seller_baseline
        if seller_ratio > 5.0:
            amount_spike_risk = max(amount_spike_risk,
                                    min(1.0, (seller_ratio - 5.0) / 10.0 + 0.5))
            reason_codes.append('SELLER_AMOUNT_SPIKE')
    elif context.seller_prior_escrows == 0 and context.amount_usd > ESCROW_ENHANCED_DD_THRESHOLD:
        amount_spike_risk = max(amount_spike_risk, 0.35)
        reason_codes.append('SELLER_FIRST_ESCROW_HIGH_VALUE')

    # ── Signal 4: Hold duration ────────────────────────────────────────────────
    hold_duration_risk = 0.0
    if context.actual_hold_days >= ESCROW_EXTENDED_HOLD_DAYS:
        hold_duration_risk = min(1.0, (context.actual_hold_days - ESCROW_EXTENDED_HOLD_DAYS) / 30.0 + 0.3)
        reason_codes.append('ESCROW_EXTENDED_HOLD')
        if context.actual_hold_days >= 60:
            sar_required = True
            sar_note     = sar_note or f'Funds held {context.actual_hold_days} days — MAS STR obligation triggered.'

    # ── Signal 5: Active dispute ───────────────────────────────────────────────
    dispute_risk = 0.0
    if context.dispute_raised:
        dispute_risk = 0.70
        reason_codes.append('ESCROW_DISPUTE_ACTIVE')

        if context.dispute_raised_at:
            dispute_hours = (
                datetime.now() - datetime.fromisoformat(context.dispute_raised_at)
            ).total_seconds() / 3600

            if dispute_hours > ESCROW_DISPUTE_FREEZE_HOURS:
                dispute_risk = 0.90
                reason_codes.append('DISPUTE_FREEZE_RISK')
                sar_required = True
                sar_note     = sar_note or (
                    f'Escrow dispute unresolved after {dispute_hours:.0f}h '
                    f'— SAR obligation triggered under MAS Notice PSN02.'
                )

    # ── Compliance requirements ────────────────────────────────────────────────
    source_of_funds_required = context.amount_usd >= ESCROW_SOURCE_OF_FUNDS_THRESHOLD
    enhanced_dd_required     = context.amount_usd >= ESCROW_ENHANCED_DD_THRESHOLD
    direct_mlro              = (
        sar_required
        or counterparty_risk >= 1.0
        or trade_legitimacy_risk >= 0.60
        or context.actual_hold_days >= 60
    )

    if source_of_funds_required:
        reason_codes.append('SOURCE_OF_FUNDS_REQUIRED')
    if enhanced_dd_required and 'SOURCE_OF_FUNDS_REQUIRED' not in reason_codes:
        reason_codes.append('ENHANCED_DD_REQUIRED')
    if context.is_cross_border:
        reason_codes.append('CROSS_BORDER_ESCROW')

    # ── Composite risk score ───────────────────────────────────────────────────
    # Weighted: counterparty and trade legitimacy are highest weight
    # because they indicate whether the escrow is real or fraudulent
    composite = (
        counterparty_risk    * 0.30 +
        trade_legitimacy_risk* 0.30 +
        amount_spike_risk    * 0.15 +
        hold_duration_risk   * 0.10 +
        dispute_risk         * 0.10 +
        base_fraud_score     * 0.05   # base ML score has lowest weight in escrow context
    )
    composite = round(min(1.0, composite), 4)

    # ── Escrow-specific decision ───────────────────────────────────────────────
    escrow_exp_loss = base_fraud_score * context.amount_usd

    if sar_required or composite >= 0.70 or unverified_count == 2:
        escrow_decision = 'BLOCK'
        reason_codes.insert(0, 'ESCROW_BLOCKED')
    elif source_of_funds_required and not context.trade_document_present:
        escrow_decision = 'HOLD_PENDING_SOF'
        reason_codes.insert(0, 'ESCROW_HOLD_PENDING_SOF')
    elif composite >= 0.35 or escrow_exp_loss > ESCROW_BLOCK_THRESHOLD:
        escrow_decision = 'REVIEW'
        reason_codes.insert(0, 'ESCROW_REVIEW_REQUIRED')
    elif escrow_exp_loss > ESCROW_REVIEW_THRESHOLD or direct_mlro:
        escrow_decision = 'REVIEW'
    else:
        escrow_decision = 'ALLOW'

    # ── Summary ───────────────────────────────────────────────────────────────
    escrow_summary = (
        f"Escrow {context.escrow_id}: ${context.amount_usd:,.0f} | "
        f"Composite risk: {composite:.0%} | "
        f"Decision: {escrow_decision} | "
        f"KYC: buyer={context.buyer_kyc_status}, seller={context.seller_kyc_status} | "
        f"Trade docs: {'✓' if context.trade_document_present else '✗'} | "
        f"Hold: {context.actual_hold_days}d | "
        f"{'⚠ SAR REQUIRED' if sar_required else 'No SAR yet'}"
    )

    return EscrowRiskResult(
        escrow_id                 = context.escrow_id,
        amount_usd                = context.amount_usd,
        counterparty_risk         = round(counterparty_risk, 4),
        trade_legitimacy_risk     = round(trade_legitimacy_risk, 4),
        amount_spike_risk         = round(amount_spike_risk, 4),
        hold_duration_risk        = round(hold_duration_risk, 4),
        dispute_risk              = round(dispute_risk, 4),
        composite_escrow_risk     = composite,
        source_of_funds_required  = source_of_funds_required,
        enhanced_dd_required      = enhanced_dd_required,
        direct_mlro_escalation    = direct_mlro,
        segregated_account_required = True,
        reason_codes              = list(dict.fromkeys(reason_codes)),  # deduplicate preserving order
        escrow_decision           = escrow_decision,
        sar_required              = sar_required,
        sar_obligation_note       = sar_note,
        escrow_summary            = escrow_summary,
    )


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 70)
    print("ESCROW RISK MODULE — SELF TEST")
    print("=" * 70)

    test_escrows = [
        (EscrowContext(
            escrow_id='ESC-001', amount_usd=5000,
            buyer_kyc_status='VERIFIED', seller_kyc_status='VERIFIED',
            trade_description='Cotton fabric order, 500kg FOB Mumbai',
            trade_document_present=True, incoterms='FOB',
            buyer_prior_escrows=3, buyer_avg_escrow_usd=4800,
            seller_prior_escrows=12, seller_avg_escrow_usd=5200,
            origin_country='IND', dest_country='DEU', is_cross_border=True,
        ), 0.08, 'Clean B2B trade — should ALLOW'),

        (EscrowContext(
            escrow_id='ESC-002', amount_usd=50000,
            buyer_kyc_status='PENDING', seller_kyc_status='VERIFIED',
            trade_description='Electronics',
            trade_document_present=False, incoterms='NONE',
            buyer_prior_escrows=0, buyer_avg_escrow_usd=0,
            seller_prior_escrows=2, seller_avg_escrow_usd=3000,
            origin_country='SGP', dest_country='NGA', is_cross_border=True,
        ), 0.15, 'High-value, buyer unverified, no docs — should BLOCK'),

        (EscrowContext(
            escrow_id='ESC-003', amount_usd=25000,
            buyer_kyc_status='VERIFIED', seller_kyc_status='VERIFIED',
            trade_description='Software development services retainer',
            trade_document_present=True, incoterms='NONE',
            buyer_prior_escrows=1, buyer_avg_escrow_usd=2000,
            seller_prior_escrows=0, seller_avg_escrow_usd=0,
            actual_hold_days=0,
            origin_country='USA', dest_country='IND', is_cross_border=True,
        ), 0.06, 'SOF required (>$20k), first escrow seller, amount spike'),

        (EscrowContext(
            escrow_id='ESC-004', amount_usd=8000,
            buyer_kyc_status='VERIFIED', seller_kyc_status='VERIFIED',
            trade_description='Dispute: goods not delivered as specified',
            trade_document_present=True, incoterms='CIF',
            buyer_prior_escrows=5, buyer_avg_escrow_usd=7500,
            seller_prior_escrows=8, seller_avg_escrow_usd=8200,
            actual_hold_days=45,
            dispute_raised=True,
            dispute_raised_at=(datetime.now() - timedelta(hours=80)).isoformat(),
            origin_country='SGP', dest_country='PHL', is_cross_border=True,
        ), 0.10, 'Active dispute > 72h, extended hold — SAR required'),
    ]

    for ctx, base_score, desc in test_escrows:
        result = assess_escrow_risk(ctx, base_score)
        print(f"\n{'─' * 65}")
        print(f"  {desc}")
        print(f"  Decision:   {result.escrow_decision}")
        print(f"  Composite:  {result.composite_escrow_risk:.0%}")
        print(f"  SAR:        {'⚠ REQUIRED — ' + result.sar_obligation_note if result.sar_required else 'Not required'}")
        print(f"  SOF req:    {result.source_of_funds_required}")
        print(f"  MLRO:       {result.direct_mlro_escalation}")
        print(f"  Codes:      {result.reason_codes}")
        print(f"  Summary:    {result.escrow_summary}")
