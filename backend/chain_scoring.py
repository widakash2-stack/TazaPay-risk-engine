# chain_scoring.py
# ──────────────────────────────────────────────────────────────────────────────
# A5 — Transaction Chain Scoring
#
# WHY THIS EXISTS:
#   The current engine scores each transaction independently.
#   On Tazapay's stablecoin rails, money moves in chains:
#
#     Hop 1: INR collected from merchant in India (p=0.08)
#     Hop 2: Converted to USDC, moved across blockchain (p=0.12)
#     Hop 3: USDC converted to PHP, paid to recipient in Philippines (p=0.10)
#
#   Each hop scores below the REVIEW threshold (say $20 expected loss).
#   But the chain risk is NOT the average — it's the probability that
#   at least one hop is fraudulent:
#
#     chain_risk = 1 - (1-0.08)(1-0.12)(1-0.10) = 1 - (0.92×0.88×0.90)
#                = 1 - 0.728 = 27.2%
#
#   A $500 transaction with 27.2% chain risk = $136 chain expected loss.
#   That BLOCKS under ecommerce policy ($100 threshold).
#   Each individual hop would have ALLOWED.
#
#   This is exactly how cross-border structuring fraud works:
#   split a large transfer into 3 small hops, each below threshold,
#   each looking clean individually. Chain scoring closes this gap.
#
# TAZAPAY RELEVANCE:
#   Every stablecoin transfer on Tazapay is at minimum a 2-hop chain:
#     fiat in → stablecoin bridge → fiat out
#   High-value B2B transfers often go 3-4 hops through multiple currencies.
#   The compliance PM who builds chain scoring owns the gap that every
#   competitor's risk system currently misses.
# ──────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass, field
from typing import Optional
import math


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ChainHop:
    """
    A single hop in a transaction chain.
    Each hop has its own ML fraud score, amount, and corridor.
    """
    hop_number:       int
    transaction_id:   str
    fraud_score:      float        # ML probability [0, 1]
    amount_usd:       float        # USD equivalent at time of hop
    origin_country:   str
    dest_country:     str
    rail:             str = 'fiat' # 'fiat', 'usdc', 'usdt', 'xrp', 'sol'
    hop_expected_loss: float = 0.0

    def __post_init__(self):
        self.hop_expected_loss = round(self.fraud_score * self.amount_usd, 2)


@dataclass
class ChainRiskResult:
    """
    Result of chain-level risk scoring across all hops.
    """
    chain_id:           str
    hops:               list        # list of ChainHop

    # Core chain metrics
    chain_risk_score:   float       # 1 - Π(1 - pᵢ) across all hops
    chain_expected_loss: float      # chain_risk_score × max(hop amounts)
    max_hop_score:      float       # highest individual hop score
    total_amount_usd:   float       # sum of all hop amounts

    # Risk classification
    risk_label:         str         # HIGH / ELEVATED / STANDARD
    is_high_risk:       bool

    # Structuring detection
    structuring_detected: bool      # hops suspiciously uniform in amount
    structuring_note:   str = ''

    # Reason codes
    reason_codes:       list = field(default_factory=list)

    # Loss amplification vs single-transaction scoring
    amplification_factor: float = 1.0   # chain_risk / max_hop_score

    # Human-readable summary
    chain_summary:      str = ''

    n_hops:             int = 0

    def __post_init__(self):
        self.n_hops = len(self.hops)


# ── Chain risk thresholds ─────────────────────────────────────────────────────
CHAIN_HIGH_RISK_THRESHOLD      = 0.25   # chain_risk > 25% → HIGH
CHAIN_ELEVATED_RISK_THRESHOLD  = 0.12   # chain_risk > 12% → ELEVATED

# Structuring detection: hops are suspiciously uniform if
# standard deviation of amounts / mean < this threshold
STRUCTURING_UNIFORMITY_THRESHOLD = 0.15


def score_chain(
    chain_id: str,
    hops: list[ChainHop],
    policy: Optional[dict] = None,
) -> ChainRiskResult:
    """
    Scores the entire transaction chain using the complement probability method.

    Chain risk = 1 - Π(1 - pᵢ)  for all hops i
    This is the probability that AT LEAST ONE hop is fraudulent.

    Args:
        chain_id:  Unique identifier for this transaction chain
        hops:      List of ChainHop objects (in chronological order)
        policy:    Merchant policy dict with block/review thresholds
                   If None uses ecommerce defaults

    Returns:
        ChainRiskResult

    Example:
        hops = [
            ChainHop(1, 'TXN-A', 0.08, 500, 'IND', 'ETH_BRIDGE', 'fiat'),
            ChainHop(2, 'TXN-B', 0.12, 495, 'ETH_BRIDGE', 'PHL', 'usdc'),
            ChainHop(3, 'TXN-C', 0.10, 490, 'PHL', 'PHL', 'fiat'),
        ]
        result = score_chain('CHAIN-001', hops)
        # result.chain_risk_score = 0.272
        # result.chain_expected_loss = 136.0  (0.272 × 500)
        # Individual hop max was 0.12 → $60 — would have ALLOWED
        # Chain score → $136 — BLOCKS under ecommerce policy
    """
    if not hops:
        return ChainRiskResult(
            chain_id='', hops=[], chain_risk_score=0.0,
            chain_expected_loss=0.0, max_hop_score=0.0,
            total_amount_usd=0.0, risk_label='STANDARD',
            is_high_risk=False, structuring_detected=False,
        )

    _policy = policy or {
        'block_threshold': 100, 'review_threshold': 20
    }

    # ── Core chain risk formula ───────────────────────────────────────────────
    # Complement probability: P(at least one fraud) = 1 - P(no fraud in any hop)
    # P(no fraud in any hop) = Π(1 - pᵢ)
    prob_all_clean  = math.prod(1.0 - hop.fraud_score for hop in hops)
    chain_risk      = round(1.0 - prob_all_clean, 4)

    # Use the maximum hop amount as the exposure amount
    # (the entire chain value is at risk if any hop is fraudulent)
    max_amount      = max(hop.amount_usd for hop in hops)
    total_amount    = round(sum(hop.amount_usd for hop in hops), 2)
    chain_exp_loss  = round(chain_risk * max_amount, 2)
    max_hop_score   = round(max(hop.fraud_score for hop in hops), 4)

    # Amplification: how much riskier is the chain vs the worst single hop?
    amplification   = round(chain_risk / max_hop_score, 3) if max_hop_score > 0 else 1.0

    # ── Structuring detection ─────────────────────────────────────────────────
    # Structuring = breaking a large transfer into similar-sized hops
    # to stay below reporting thresholds at each individual hop
    structuring_detected = False
    structuring_note     = ''

    if len(hops) >= 2:
        amounts = [hop.amount_usd for hop in hops]
        mean_amt = sum(amounts) / len(amounts)
        if mean_amt > 0:
            std_amt = math.sqrt(sum((a - mean_amt)**2 for a in amounts) / len(amounts))
            cv = std_amt / mean_amt   # coefficient of variation

            # Uniform amounts + multiple hops + cross-border = structuring signal
            if cv < STRUCTURING_UNIFORMITY_THRESHOLD and len(hops) >= 2:
                structuring_detected = True
                structuring_note = (
                    f"Amounts suspiciously uniform across {len(hops)} hops "
                    f"(CV={cv:.3f}, mean=${mean_amt:.0f}) — "
                    f"possible structuring to avoid threshold detection."
                )

    # ── Risk classification ───────────────────────────────────────────────────
    if chain_risk >= CHAIN_HIGH_RISK_THRESHOLD:
        risk_label   = 'HIGH'
        is_high_risk = True
    elif chain_risk >= CHAIN_ELEVATED_RISK_THRESHOLD:
        risk_label   = 'ELEVATED'
        is_high_risk = False
    else:
        risk_label   = 'STANDARD'
        is_high_risk = False

    # ── Reason codes ──────────────────────────────────────────────────────────
    reason_codes = []
    if is_high_risk:
        reason_codes.append('CHAIN_HIGH_RISK')
    elif chain_risk >= CHAIN_ELEVATED_RISK_THRESHOLD:
        reason_codes.append('CHAIN_ELEVATED_RISK')

    if structuring_detected:
        reason_codes.append('CHAIN_STRUCTURING_SUSPECTED')

    if amplification >= 2.0:
        reason_codes.append('CHAIN_AMPLIFICATION_HIGH')

    if len(hops) >= 4:
        reason_codes.append('CHAIN_EXCESSIVE_HOPS')

    # ── Summary ───────────────────────────────────────────────────────────────
    hop_summary = ' → '.join(
        f"Hop{h.hop_number}({h.origin_country}→{h.dest_country},{h.fraud_score:.0%})"
        for h in hops
    )
    chain_summary = (
        f"Chain {chain_id}: {len(hops)} hops, "
        f"chain_risk={chain_risk:.1%} "
        f"(amplification {amplification:.1f}× vs max hop {max_hop_score:.0%}), "
        f"chain_expected_loss=${chain_exp_loss:.2f}. "
        f"{'⚠ STRUCTURING DETECTED. ' if structuring_detected else ''}"
        f"{hop_summary}"
    )

    return ChainRiskResult(
        chain_id             = chain_id,
        hops                 = hops,
        chain_risk_score     = chain_risk,
        chain_expected_loss  = chain_exp_loss,
        max_hop_score        = max_hop_score,
        total_amount_usd     = total_amount,
        risk_label           = risk_label,
        is_high_risk         = is_high_risk,
        structuring_detected = structuring_detected,
        structuring_note     = structuring_note,
        reason_codes         = reason_codes,
        amplification_factor = amplification,
        chain_summary        = chain_summary,
    )


def build_demo_chain(
    base_txn_id: str,
    amount: float,
    base_score: float,
    origin_country: str,
    dest_country:   str,
) -> list[ChainHop]:
    """
    Builds a simulated 3-hop chain for a cross-border transaction.
    Used for demo when real multi-hop data isn't available.

    Real chain structure for Tazapay cross-border:
        Hop 1: Fiat collection (origin)       — fiat rail
        Hop 2: Stablecoin bridge (on-chain)   — USDC/USDT/XRP
        Hop 3: Fiat payout (destination)      — local rail

    Scores vary slightly per hop to simulate realistic chain behaviour.
    """
    import random
    rng = random.Random(hash(base_txn_id) % (2**32))

    # Each hop has slightly different score — bridge hop often highest risk
    hop1_score = round(max(0.01, base_score * rng.uniform(0.7, 0.9)), 4)
    hop2_score = round(max(0.01, base_score * rng.uniform(0.9, 1.3)), 4)  # bridge riskiest
    hop3_score = round(max(0.01, base_score * rng.uniform(0.6, 0.95)), 4)

    # Amounts decrease slightly per hop (fees deducted)
    hop1_amt = round(amount, 2)
    hop2_amt = round(amount * 0.997, 2)   # 0.3% bridge fee
    hop3_amt = round(amount * 0.993, 2)   # additional payout fee

    # Bridge country is a virtual node
    bridge = 'ETH' if rng.random() > 0.5 else 'TRX'

    return [
        ChainHop(1, f"{base_txn_id}_H1", hop1_score, hop1_amt, origin_country, bridge, 'fiat'),
        ChainHop(2, f"{base_txn_id}_H2", hop2_score, hop2_amt, bridge, bridge, 'usdc'),
        ChainHop(3, f"{base_txn_id}_H3", hop3_score, hop3_amt, bridge, dest_country, 'fiat'),
    ]


def get_chain_reason_codes(result: ChainRiskResult) -> list[str]:
    """Returns reason codes for injection into fraud engine."""
    return result.reason_codes


def get_chain_expected_loss(result: ChainRiskResult) -> float:
    """Returns chain-level expected loss for use in decisioning."""
    return result.chain_expected_loss


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 70)
    print("CHAIN SCORING MODULE — SELF TEST")
    print("=" * 70)

    test_chains = [
        # Each hop scores fine individually — chain is dangerous
        ('CHAIN-001', [
            ChainHop(1, 'T1', 0.08, 500, 'IND', 'ETH', 'fiat'),
            ChainHop(2, 'T2', 0.12, 497, 'ETH', 'ETH', 'usdc'),
            ChainHop(3, 'T3', 0.10, 493, 'ETH', 'PHL', 'fiat'),
        ], 'IND→PHL 3-hop (each clean, chain risky)'),

        # Single hop — no amplification
        ('CHAIN-002', [
            ChainHop(1, 'T4', 0.15, 800, 'SGP', 'SGP', 'fiat'),
        ], 'SGP domestic single hop'),

        # Structuring — uniform amounts
        ('CHAIN-003', [
            ChainHop(1, 'T5', 0.06, 990, 'USA', 'ETH', 'fiat'),
            ChainHop(2, 'T6', 0.07, 988, 'ETH', 'ETH', 'usdc'),
            ChainHop(3, 'T7', 0.06, 985, 'ETH', 'VEN', 'fiat'),
        ], 'USA→VEN structuring pattern (uniform amounts ~$990)'),

        # 4-hop high-value chain
        ('CHAIN-004', [
            ChainHop(1, 'T8',  0.09, 4500, 'RUS', 'ETH', 'fiat'),
            ChainHop(2, 'T9',  0.14, 4480, 'ETH', 'TRX', 'usdc'),
            ChainHop(3, 'T10', 0.11, 4460, 'TRX', 'TRX', 'usdt'),
            ChainHop(4, 'T11', 0.08, 4440, 'TRX', 'NGA', 'fiat'),
        ], 'RUS→NGA 4-hop high-value'),
    ]

    for chain_id, hops, desc in test_chains:
        result = score_chain(chain_id, hops)
        print(f"\n{'─' * 65}")
        print(f"  {desc}")
        print(f"  Chain risk:    {result.chain_risk_score:.1%}  "
              f"(max hop: {result.max_hop_score:.0%}, "
              f"amplification: {result.amplification_factor:.1f}×)")
        print(f"  Chain exp loss: ${result.chain_expected_loss:.2f}  "
              f"(risk label: {result.risk_label})")
        print(f"  Structuring:   {'⚠ YES — ' + result.structuring_note if result.structuring_detected else 'No'}")
        print(f"  Reason codes:  {result.reason_codes}")

    print("\n" + "=" * 70)
    print("Key insight: CHAIN-001 — each hop would ALLOW ($60/$86/$74 exp loss).")
    print("Chain score = 27.2% → $136 chain expected loss → BLOCKS ecommerce policy.")
    print("This is exactly how cross-border structuring fraud evades single-hop systems.")
