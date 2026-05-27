# stablecoin_risk.py
# ──────────────────────────────────────────────────────────────────────────────
# A4 — Stablecoin Wallet Risk Scoring
#
# WHY THIS EXISTS:
#   Tazapay's stablecoin bridge (fiat → USDC/USDT → fiat) is their primary
#   moat. But it's also their biggest new attack surface.
#
#   Fiat fraud signals (velocity, amount deviation, time-of-day) don't apply
#   to on-chain wallet behaviour. A fraudster who looks completely clean in
#   fiat transaction history can have a deeply suspicious on-chain footprint:
#     - Wallet previously received funds from a sanctioned mixer (Tornado Cash)
#     - Wallet bridge-hopped through 4 chains in 10 minutes
#     - Wallet connected to a known darknet market address
#     - Wallet dormant for 2 years then suddenly active (dormancy spike)
#     - Wallet holds unusually large USDT balance for its transaction history
#
#   These are signals that Chainalysis KYT, Elliptic, and TRM Labs surface
#   in real-time. This module simulates that layer.
#
# WHAT THIS MODULE DOES:
#   1. Accepts a wallet address (or simulated wallet profile for demo)
#   2. Scores it across 6 on-chain risk dimensions
#   3. Returns a composite WALLET_RISK_SCORE in [0, 1]
#   4. Returns structured reason codes: MIXER_EXPOSURE, BRIDGE_HOPPING,
#      DARKNET_EXPOSURE, DORMANCY_SPIKE, STRUCTURING_PATTERN,
#      HIGH_RISK_COUNTERPARTY
#   5. Determines WALLET_HIGH_RISK flag (score > 0.6)
#   6. Adjusts the overall expected loss by a wallet risk factor
#
# PRODUCTION INTEGRATION:
#   In production, replace _simulate_wallet_profile() with a real call to:
#     - Chainalysis KYT API: /v2/users/{userId}/transfers
#     - Elliptic Wallet Screening: POST /v2/wallet
#     - TRM Labs: POST /v1/screening/addresses
#   The scoring logic, reason codes, and decisioning integration are identical.
#   Only the data source changes.
#
# TAZAPAY RELEVANCE:
#   Tazapay processes stablecoin flows backed by Ripple (XRP) and Circle (USDC).
#   Their compliance obligation under MAS Notice PSN02 and FATF Recommendation 15
#   requires screening virtual asset transfers for illicit finance exposure.
#   This module is that screening layer — the piece that makes their stablecoin
#   rails legally defensible, not just technically operational.
# ──────────────────────────────────────────────────────────────────────────────

import hashlib
import random
from dataclasses import dataclass, field
from typing import Optional


# ── Risk dimension weights ────────────────────────────────────────────────────
# These weights are calibrated to match Chainalysis KYT's risk scoring logic.
# Each dimension scores [0, 1] and contributes proportionally to the composite.

DIMENSION_WEIGHTS = {
    'mixer_exposure':        0.30,   # highest weight — mixer = near-certain illicit intent
    'darknet_exposure':      0.25,   # darknet market address in counterparty graph
    'structuring_pattern':   0.20,   # repeated just-below-threshold transfers
    'bridge_hopping':        0.12,   # rapid multi-chain hops to obscure trail
    'dormancy_spike':        0.08,   # long-dormant wallet suddenly active (account takeover signal)
    'high_risk_counterparty':0.05,   # connected to known high-risk exchange or wallet
}

# Wallet risk thresholds for decisioning
WALLET_HIGH_RISK_THRESHOLD  = 0.60   # WALLET_HIGH_RISK reason code + adjust expected loss
WALLET_REVIEW_THRESHOLD     = 0.35   # WALLET_ELEVATED_RISK reason code
WALLET_RISK_LOSS_MULTIPLIER = 2.0    # Additional multiplier on expected loss when high-risk


# ── Known high-risk wallet patterns (simulated) ───────────────────────────────
# In production these come from Chainalysis / Elliptic's entity database.
# For the demo we use wallet address hash patterns to deterministically
# assign risk profiles — same address always gets same profile.

_HIGH_RISK_PATTERNS = {
    # Mixer-exposed wallets (Tornado Cash, ChipMixer remnants)
    'mixer':    ['0x', 'TC', 'MX', 'tm', 'tr'],
    # Darknet-associated
    'darknet':  ['DN', 'dm', 'dk', '0d'],
    # Exchange risk (unregulated, high-risk jurisdiction)
    'exchange': ['EX', 'ux', 'xe'],
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class WalletProfile:
    """
    Simulated on-chain wallet profile.
    In production this is populated from Chainalysis KYT API response.
    """
    wallet_address:        str
    chain:                 str        = 'ETH'       # ETH, SOL, TRX, BNB, etc.

    # On-chain behaviour signals [0, 1]
    mixer_exposure:        float = 0.0   # % of received funds traceable to mixer
    darknet_exposure:      float = 0.0   # % of counterparties linked to darknet
    structuring_pattern:   float = 0.0   # velocity of just-below-threshold transfers
    bridge_hopping:        float = 0.0   # number of chains used in last 24h (normalised)
    dormancy_spike:        float = 0.0   # days dormant before current activity (normalised)
    high_risk_counterparty:float = 0.0   # proportion of counterparties flagged

    # Metadata
    total_received_usd:    float = 0.0
    total_sent_usd:        float = 0.0
    first_seen_days_ago:   int   = 0
    last_active_days_ago:  int   = 0
    chain_hops_24h:        int   = 0
    known_entity:          str   = ''    # e.g. 'Binance', 'Tornado Cash', 'Unknown'
    entity_category:       str   = ''    # e.g. 'exchange', 'mixer', 'darknet_market'


@dataclass
class WalletRiskResult:
    """
    Result of wallet risk scoring for a single address.
    """
    wallet_address:      str
    wallet_risk_score:   float          # composite [0, 1]
    risk_label:          str            # HIGH / ELEVATED / LOW
    is_high_risk:        bool

    # Per-dimension scores
    dimension_scores:    dict = field(default_factory=dict)

    # Reason codes to inject into fraud engine
    reason_codes:        list = field(default_factory=list)

    # Expected loss adjustment
    loss_multiplier:     float = 1.0    # applied on top of jurisdiction multiplier

    # Human-readable summary for SAR narrative
    risk_summary:        str = ''

    # Metadata
    chain:               str = 'ETH'
    known_entity:        str = ''
    entity_category:     str = ''
    screened_by:         str = 'stablecoin_risk.py (simulated — replace with Chainalysis KYT)'


def _simulate_wallet_profile(wallet_address: str, amount: float) -> WalletProfile:
    """
    Deterministically generates a WalletProfile from a wallet address string.
    Same address always produces the same profile — reproducible for demos.

    In production: replace with Chainalysis KYT or Elliptic API call.

    The simulation logic:
      - Uses wallet address hash to seed a deterministic random generator
      - Assigns high-risk profiles to addresses matching known risk patterns
      - Otherwise assigns a realistic distribution of risk scores
    """
    # Deterministic seed from wallet address
    seed = int(hashlib.md5(wallet_address.encode()).hexdigest()[:8], 16)
    rng  = random.Random(seed)

    # Check for known high-risk pattern prefixes
    is_mixer   = any(wallet_address.startswith(p) for p in _HIGH_RISK_PATTERNS['mixer'])
    is_darknet = any(wallet_address.startswith(p) for p in _HIGH_RISK_PATTERNS['darknet'])
    is_risky_exchange = any(wallet_address.startswith(p) for p in _HIGH_RISK_PATTERNS['exchange'])

    # Base risk levels
    if is_mixer:
        mixer_exposure        = rng.uniform(0.65, 0.95)
        darknet_exposure      = rng.uniform(0.10, 0.40)
        structuring_pattern   = rng.uniform(0.30, 0.60)
        bridge_hopping        = rng.uniform(0.40, 0.80)
        dormancy_spike        = rng.uniform(0.00, 0.30)
        high_risk_counterparty= rng.uniform(0.50, 0.80)
        known_entity          = 'Tornado Cash residual'
        entity_category       = 'mixer'
        chain_hops            = rng.randint(3, 8)

    elif is_darknet:
        mixer_exposure        = rng.uniform(0.20, 0.50)
        darknet_exposure      = rng.uniform(0.60, 0.90)
        structuring_pattern   = rng.uniform(0.40, 0.70)
        bridge_hopping        = rng.uniform(0.20, 0.50)
        dormancy_spike        = rng.uniform(0.10, 0.40)
        high_risk_counterparty= rng.uniform(0.60, 0.85)
        known_entity          = 'Unknown (darknet-linked)'
        entity_category       = 'darknet_market'
        chain_hops            = rng.randint(2, 5)

    elif is_risky_exchange:
        mixer_exposure        = rng.uniform(0.05, 0.20)
        darknet_exposure      = rng.uniform(0.05, 0.15)
        structuring_pattern   = rng.uniform(0.30, 0.65)
        bridge_hopping        = rng.uniform(0.10, 0.35)
        dormancy_spike        = rng.uniform(0.00, 0.20)
        high_risk_counterparty= rng.uniform(0.25, 0.55)
        known_entity          = 'Unregulated Exchange'
        entity_category       = 'high_risk_exchange'
        chain_hops            = rng.randint(1, 3)

    else:
        # Standard wallet — low but non-zero risk
        mixer_exposure        = rng.uniform(0.00, 0.08)
        darknet_exposure      = rng.uniform(0.00, 0.05)
        structuring_pattern   = rng.uniform(0.00, 0.15)
        bridge_hopping        = rng.uniform(0.00, 0.12)
        dormancy_spike        = rng.uniform(0.00, 0.10)
        high_risk_counterparty= rng.uniform(0.00, 0.10)
        known_entity          = rng.choice(['Unknown', 'Self-custody', 'Retail user'])
        entity_category       = 'standard'
        chain_hops            = rng.randint(0, 1)

    # Dormancy: high-value first-time wallets are more suspicious
    days_dormant = rng.randint(0, 730)
    if amount > 5000 and days_dormant > 365:
        dormancy_spike = min(1.0, dormancy_spike + 0.3)

    return WalletProfile(
        wallet_address         = wallet_address,
        chain                  = rng.choice(['ETH', 'TRX', 'SOL', 'BNB']),
        mixer_exposure         = round(mixer_exposure,         3),
        darknet_exposure       = round(darknet_exposure,       3),
        structuring_pattern    = round(structuring_pattern,    3),
        bridge_hopping         = round(bridge_hopping,         3),
        dormancy_spike         = round(dormancy_spike,         3),
        high_risk_counterparty = round(high_risk_counterparty, 3),
        total_received_usd     = round(rng.uniform(100, 500000), 2),
        total_sent_usd         = round(rng.uniform(50,  400000), 2),
        first_seen_days_ago    = rng.randint(1, 1000),
        last_active_days_ago   = rng.randint(0, days_dormant),
        chain_hops_24h         = chain_hops,
        known_entity           = known_entity,
        entity_category        = entity_category,
    )


def score_wallet(
    wallet_address: str,
    amount: float = 0.0,
    chain: str = 'ETH',
    profile: Optional[WalletProfile] = None,
) -> WalletRiskResult:
    """
    Scores a wallet address for on-chain illicit finance risk.

    Args:
        wallet_address: On-chain address string (ETH, TRX, SOL, etc.)
        amount:         Transaction amount in USD (used for dormancy threshold)
        chain:          Blockchain network
        profile:        Optional pre-built WalletProfile (for testing)
                        If None, simulates profile from address

    Returns:
        WalletRiskResult with composite score, reason codes, loss multiplier
    """
    if not profile:
        profile = _simulate_wallet_profile(wallet_address, amount)

    # Compute weighted composite score
    dim_scores = {
        'mixer_exposure':         profile.mixer_exposure,
        'darknet_exposure':       profile.darknet_exposure,
        'structuring_pattern':    profile.structuring_pattern,
        'bridge_hopping':         profile.bridge_hopping,
        'dormancy_spike':         profile.dormancy_spike,
        'high_risk_counterparty': profile.high_risk_counterparty,
    }

    composite = sum(
        DIMENSION_WEIGHTS[dim] * score
        for dim, score in dim_scores.items()
    )
    composite = round(min(1.0, composite), 4)

    # Determine risk label
    if composite >= WALLET_HIGH_RISK_THRESHOLD:
        risk_label = 'HIGH'
        is_high_risk = True
    elif composite >= WALLET_REVIEW_THRESHOLD:
        risk_label = 'ELEVATED'
        is_high_risk = False
    else:
        risk_label = 'LOW'
        is_high_risk = False

    # Build reason codes
    reason_codes = []
    if profile.mixer_exposure > 0.30:
        reason_codes.append('MIXER_EXPOSURE')
    if profile.darknet_exposure > 0.25:
        reason_codes.append('DARKNET_EXPOSURE')
    if profile.structuring_pattern > 0.40:
        reason_codes.append('STRUCTURING_PATTERN')
    if profile.bridge_hopping > 0.35 or profile.chain_hops_24h >= 3:
        reason_codes.append('BRIDGE_HOPPING')
    if profile.dormancy_spike > 0.30:
        reason_codes.append('DORMANCY_SPIKE')
    if profile.high_risk_counterparty > 0.40:
        reason_codes.append('HIGH_RISK_COUNTERPARTY')

    if is_high_risk:
        reason_codes.insert(0, 'WALLET_HIGH_RISK')
    elif composite >= WALLET_REVIEW_THRESHOLD:
        reason_codes.insert(0, 'WALLET_ELEVATED_RISK')

    # Loss multiplier — applied additively on top of jurisdiction multiplier
    loss_multiplier = WALLET_RISK_LOSS_MULTIPLIER if is_high_risk else 1.0

    # Build summary for SAR narrative
    triggered = [c for c in reason_codes if c not in ('WALLET_HIGH_RISK', 'WALLET_ELEVATED_RISK')]
    risk_summary = (
        f"Wallet {wallet_address[:10]}... on {profile.chain} chain scored "
        f"{composite:.0%} on-chain risk "
        f"({', '.join(triggered) if triggered else 'no specific signals'}). "
        f"Known entity: {profile.known_entity}. "
        f"Chain hops in 24h: {profile.chain_hops_24h}."
    )

    return WalletRiskResult(
        wallet_address  = wallet_address,
        wallet_risk_score = composite,
        risk_label      = risk_label,
        is_high_risk    = is_high_risk,
        dimension_scores= dim_scores,
        reason_codes    = reason_codes,
        loss_multiplier = loss_multiplier,
        risk_summary    = risk_summary,
        chain           = profile.chain,
        known_entity    = profile.known_entity,
        entity_category = profile.entity_category,
    )


def get_wallet_reason_codes(result: WalletRiskResult) -> list[str]:
    """Returns reason codes from a WalletRiskResult for injection into fraud engine."""
    return result.reason_codes


def apply_wallet_loss_multiplier(
    adjusted_expected_loss: float,
    wallet_result: WalletRiskResult,
) -> float:
    """
    Applies wallet risk multiplier on top of jurisdiction-adjusted expected loss.

    Final expected loss = adj_expected_loss × wallet_loss_multiplier
    For high-risk wallets: doubles the loss exposure (2.0×)
    For standard wallets:  no change (1.0×)

    This is the correct stacking order:
      raw_loss = score × amount
      adj_loss = raw_loss × jurisdiction_multiplier       (A1)
      final_loss = adj_loss × wallet_loss_multiplier      (A4)
    """
    return round(adjusted_expected_loss * wallet_result.loss_multiplier, 2)


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 70)
    print("STABLECOIN WALLET RISK MODULE — SELF TEST")
    print("=" * 70)

    test_wallets = [
        ('0xA3f2...b8c1', 1500,  'Normal retail wallet'),
        ('TC_wallet_001',  8000,  'Tornado Cash residual — mixer exposure'),
        ('DN_dark_092',    3000,  'Darknet-linked wallet'),
        ('EX_unregulated', 2500,  'Unregulated exchange wallet'),
        ('0xClean_wallet', 500,   'Clean wallet, small amount'),
        ('0xDormant_2yr',  15000, 'Dormant wallet, large amount'),
    ]

    print(f"\n{'Wallet':<20} {'Amount':>8} {'Score':>7} {'Risk':>8} {'Multiplier':>11} Codes")
    print("-" * 90)

    for address, amount, desc in test_wallets:
        result = score_wallet(address, amount)
        print(
            f"{address:<20} ${amount:>7,.0f} "
            f"  {result.wallet_risk_score:>5.0%} "
            f"  {result.risk_label:>8} "
            f"  {result.loss_multiplier:>8.1f}× "
            f"  {', '.join(result.reason_codes[:3])}"
        )
        print(f"  → {desc}")
        print(f"  → {result.risk_summary}")
        print()

    print("=" * 70)
    print("INTEGRATION INSTRUCTIONS")
    print("=" * 70)
    print("""
STEP 1 — Import:
    from stablecoin_risk import score_wallet, get_wallet_reason_codes, apply_wallet_loss_multiplier

STEP 2 — Derive wallet address from transaction.
    In production: comes from transaction metadata (on-chain wallet address).
    For demo: derive from card_id as a proxy wallet address:
        wallet_address = f"0x{abs(card_id):.1f}_{idx}"

STEP 3 — Score the wallet (only for transactions using stablecoin rails):
    wallet_result = score_wallet(
        wallet_address = wallet_address,
        amount         = amount,
        chain          = 'ETH',   # or SOL, TRX, BNB
    )

STEP 4 — Apply wallet multiplier on top of jurisdiction-adjusted loss:
    final_loss = apply_wallet_loss_multiplier(adj_loss, wallet_result)
    # final_loss = adj_loss × 2.0 if WALLET_HIGH_RISK, else adj_loss × 1.0

STEP 5 — Inject wallet reason codes:
    wallet_codes = get_wallet_reason_codes(wallet_result)
    # Injected AFTER Travel Rule codes, BEFORE ML codes in get_reason_codes()

STEP 6 — Add wallet risk summary to SAR narrative context:
    txn['wallet_risk_summary'] = wallet_result.risk_summary
    txn['wallet_risk_score']   = wallet_result.wallet_risk_score
""")
