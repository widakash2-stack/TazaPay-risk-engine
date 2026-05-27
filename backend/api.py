# api.py
# ──────────────────────────────────────────────────────────────────────────────
# Tazapay Risk Intelligence Engine — Flask REST API
# Exposes all 7 additions as clean REST endpoints
# Deploys to Render (free tier)
# ──────────────────────────────────────────────────────────────────────────────

import os
import json
import random
import numpy as np
import pandas as pd
import joblib
import shap
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

# ── Module imports ─────────────────────────────────────────────────────────────
from jurisdiction_risk import (
    get_adjusted_expected_loss, get_jurisdiction_reason_code,
    is_hard_block, get_tier_label, HARD_BLOCK_JURISDICTIONS,
)
from travel_rule import (
    check_travel_rule, get_travel_rule_reason_codes,
    log_travel_rule_event, get_travel_rule_summary,
)
from sar_narrative_engine import generate_sar
from stablecoin_risk import (
    score_wallet, get_wallet_reason_codes, apply_wallet_loss_multiplier,
)
from chain_scoring import (
    score_chain, build_demo_chain, get_chain_reason_codes,
    get_chain_expected_loss,
)
from feedback_integrity import (
    check_feedback_integrity, log_integrity_check,
    log_escalation, get_integrity_summary,
)
from feedback_processor import (
    apply_feedback_adjustments, get_threshold_modifier,
    get_adjustment_summary,
)
from escrow_risk import assess_escrow_risk, EscrowContext

app = Flask(__name__)
CORS(app)   # allow Netlify frontend to call this API

# ── Load model at startup ──────────────────────────────────────────────────────
MODEL        = None
FEATURE_COLS = None
EXPLAINER    = None
OPTIMAL_THRESHOLD = 0.5   # fallback; overridden after model loads

def load_model():
    global MODEL, FEATURE_COLS, EXPLAINER, OPTIMAL_THRESHOLD
    try:
        MODEL        = joblib.load('fraud_model.pkl')
        FEATURE_COLS = joblib.load('fraud_features.pkl')
        EXPLAINER    = shap.TreeExplainer(MODEL)
        # Load saved threshold if present
        if os.path.exists('optimal_threshold.json'):
            with open('optimal_threshold.json') as f:
                OPTIMAL_THRESHOLD = json.load(f)['threshold']
        print(f"✓ Model loaded: {len(FEATURE_COLS)} features | threshold={OPTIMAL_THRESHOLD:.4f}")
    except Exception as e:
        print(f"⚠ Model not found — running in demo mode: {e}")

load_model()

# ── Demo transaction generator ─────────────────────────────────────────────────
# Used when no real transaction data is provided
# Generates realistic-looking transactions for the live demo

DEMO_CORRIDORS = [
    ('IND', 'PHL'), ('SGP', 'NGA'), ('GBR', 'IND'),
    ('USA', 'VEN'), ('SGP', 'PHL'), ('IND', 'BGD'),
    ('SGP', 'SGP'), ('RUS', 'SGP'),
]

def generate_demo_transactions(n: int = 40, merchant: str = 'ecommerce') -> list:
    """Generates n realistic demo transactions for dashboard display."""
    rng = random.Random(42)
    transactions = []

    for i in range(n):
        amount      = round(rng.uniform(10, 3000), 2)
        score_raw   = rng.betavariate(0.8, 4)   # right-skewed — most txns low risk
        score       = round(score_raw, 4)
        origin, dest= rng.choice(DEMO_CORRIDORS)
        is_night    = 1 if rng.random() < 0.25 else 0
        graph_degree= rng.randint(0, 8)
        amt_dev     = round(rng.uniform(-200, 500), 2)
        card_id     = f"{rng.uniform(-5, 5):.1f}"
        is_fraud    = 1 if score_raw > 0.65 and rng.random() > 0.4 else 0

        transactions.append({
            'id':           i,
            'card_id':      card_id,
            'amount':       amount,
            'score_raw':    score,
            'is_night':     is_night,
            'graph_degree': graph_degree,
            'amt_deviation':amt_dev,
            'avg_amount':   round(amount - amt_dev, 2),
            'origin':       origin,
            'dest':         dest,
            'actual_fraud': is_fraud,
            'merchant':     merchant,
        })
    return transactions


# ── Merchant policies ─────────────────────────────────────────────────────────
MERCHANT_POLICIES = {
    'ecommerce': {'high_amount_threshold': 1000,  'block_threshold': 100,  'review_threshold': 20},
    'gaming':    {'high_amount_threshold': 500,   'block_threshold': 50,   'review_threshold': 10},
    'b2b':       {'high_amount_threshold': 50000, 'block_threshold': 5000, 'review_threshold': 1000},
}


def score_transaction(txn: dict, policy: dict) -> dict:
    """
    Runs all 7 modules on a single transaction dict.
    Returns enriched transaction with decision, reason codes, all module outputs.
    """
    idx      = txn['id']
    amount   = txn['amount']
    score    = txn['score_raw']
    is_night = txn['is_night']
    amt_dev  = txn['amt_deviation']
    graph_degree = txn['graph_degree']
    origin   = txn['origin']
    dest     = txn['dest']
    card_id  = txn['card_id']
    is_cross = (origin != dest)

    jitter = lambda v: v * random.uniform(0.85, 1.15)
    codes  = []

    # Gate 1 — Sanctions
    if is_hard_block(origin) or is_hard_block(dest):
        return {**txn,
            'decision': 'BLOCK', 'cls': 'block', 'color': '#ff4444',
            'reason': 'SANCTIONED_JURISDICTION',
            'expected_loss': round(score * amount * 5.0, 2),
            'adj_loss': round(score * amount * 5.0, 2),
            'final_loss': round(score * amount * 5.0, 2),
            'multiplier': 5.0, 'tr_status': 'N/A',
            'wallet_label': 'N/A', 'chain_label': 'N/A',
            'escrow_label': '—', 'chain_risk': 0, 'wallet_risk': 0,
        }

    # A2 — Travel Rule
    tr_result   = check_travel_rule(f'TXN-{idx}', amount, origin, dest, {})
    log_travel_rule_event(tr_result)
    tr_status   = tr_result.compliance_status if tr_result.triggers_travel_rule else '—'
    tr_codes    = get_travel_rule_reason_codes(tr_result)
    codes.extend(tr_codes)

    # A1 — Jurisdiction
    jur         = get_adjusted_expected_loss(score, amount, origin, dest)
    adj_loss    = jur['adjusted_expected_loss']
    raw_loss    = jur['raw_expected_loss']
    multiplier  = jur['multiplier']
    for country in [origin, dest]:
        c = get_jurisdiction_reason_code(country)
        if c and c not in codes: codes.insert(0, c)

    # A4 — Wallet
    wallet_address = f"0x{abs(float(card_id)):.1f}_{idx % 100}"
    if is_cross:
        wr          = score_wallet(wallet_address, amount)
        wallet_codes= get_wallet_reason_codes(wr)
        post_wallet = apply_wallet_loss_multiplier(adj_loss, wr)
        wallet_label= wr.risk_label
        wallet_risk = round(wr.wallet_risk_score * 100)
        codes.extend([c for c in wallet_codes if c not in codes])
    else:
        wr = None; post_wallet = adj_loss
        wallet_label = '—'; wallet_risk = 0

    # A5 — Chain
    if is_cross:
        hops        = build_demo_chain(f'TXN-{idx}', amount, score, origin, dest)
        cr          = score_chain(f'CHAIN-{idx}', hops, policy)
        chain_codes = get_chain_reason_codes(cr)
        chain_loss  = get_chain_expected_loss(cr)
        final_loss  = max(post_wallet, chain_loss)
        chain_label = cr.risk_label
        chain_risk  = round(cr.chain_risk_score * 100)
        codes.extend([c for c in chain_codes if c not in codes])
    else:
        cr = None; final_loss = post_wallet
        chain_label = '—'; chain_risk = 0; chain_loss = 0

    # A7 — Escrow (30% of cross-border txns > $1000)
    rng_e = random.Random(hash(f"{idx}_{card_id}") % (2**32))
    is_escrow = is_cross and amount > 1000 and rng_e.random() < 0.30
    if is_escrow:
        ctx = EscrowContext(
            escrow_id=f"ESC-{idx:04d}", amount_usd=amount,
            buyer_kyc_status=rng_e.choice(['VERIFIED','VERIFIED','PENDING']),
            seller_kyc_status=rng_e.choice(['VERIFIED','VERIFIED','VERIFIED','PENDING']),
            trade_description=rng_e.choice(['Cross-border goods supply', 'Services contract', '']),
            trade_document_present=rng_e.choice([True, True, False]),
            incoterms=rng_e.choice(['FOB','CIF','DDP','NONE']),
            buyer_prior_escrows=rng_e.randint(0,8), seller_prior_escrows=rng_e.randint(0,15),
            buyer_avg_escrow_usd=rng_e.uniform(500,amount*2) if rng_e.random()>0.3 else 0,
            seller_avg_escrow_usd=rng_e.uniform(500,amount*2) if rng_e.random()>0.2 else 0,
            actual_hold_days=rng_e.randint(0,45),
            dispute_raised=rng_e.random()<0.10,
            origin_country=origin, dest_country=dest, is_cross_border=True,
        )
        er          = assess_escrow_risk(ctx, score)
        escrow_codes= er.reason_codes
        escrow_label= er.escrow_decision
        codes.extend([c for c in escrow_codes if c not in codes])
    else:
        er = None; escrow_label = '—'

    # ML + rule decision
    modifier  = get_threshold_modifier(card_id)
    eff_block = policy['block_threshold']  * modifier
    eff_review= policy['review_threshold'] * modifier

    if amount > jitter(policy['high_amount_threshold']) or \
       (is_night == 1 and score > OPTIMAL_THRESHOLD):
        decision = 'BLOCK'
    elif final_loss > jitter(eff_block):
        decision = 'BLOCK'
    elif final_loss > jitter(eff_review):
        decision = 'REVIEW'
    else:
        decision = 'ALLOW'

    # Overrides
    SEVERITY = {'ALLOW':0,'REVIEW':1,'BLOCK':2}
    def upgrade(cur, mn):
        return mn if SEVERITY.get(mn,0) > SEVERITY.get(cur,0) else cur

    if tr_result.compliance_status in ('VIOLATION','PENDING'): decision = upgrade(decision,'REVIEW')
    if wr and wr.is_high_risk: decision = upgrade(decision,'BLOCK' if final_loss>jitter(eff_block) else 'REVIEW')
    if cr and cr.is_high_risk: decision = upgrade(decision,'BLOCK' if chain_loss>jitter(eff_block) else 'REVIEW')
    if er and er.escrow_decision in ('BLOCK','HOLD_PENDING_SOF'): decision = upgrade(decision,'BLOCK' if er.escrow_decision=='BLOCK' else 'REVIEW')

    # ML codes
    if amount > jitter(policy['high_amount_threshold']): codes.append('HIGH_AMOUNT')
    if is_night == 1 and score > OPTIMAL_THRESHOLD:      codes.append('NIGHTTIME_ANOMALY')
    if abs(amt_dev) > 100:                               codes.append('HIGH_AMOUNT_DEVIATION')
    if final_loss > jitter(eff_block):                   codes.append('HIGH_FRAUD_SCORE')
    elif final_loss > jitter(eff_review):                codes.append('MODERATE_FRAUD_SCORE')
    if graph_degree > 3:                                 codes.append('RING_SUSPECTED')

    reason = ' | '.join(dict.fromkeys(codes)) if codes else 'NORMAL'

    cls_map   = {'BLOCK':'block','REVIEW':'review','ALLOW':'allow'}
    color_map = {'BLOCK':'#ff4444','REVIEW':'#ffaa00','ALLOW':'#44ff44'}

    return {
        **txn,
        'decision':     decision,
        'cls':          cls_map[decision],
        'color':        color_map[decision],
        'reason':       reason,
        'expected_loss':raw_loss,
        'adj_loss':     adj_loss,
        'final_loss':   round(final_loss, 2),
        'multiplier':   multiplier,
        'modifier':     modifier,
        'tr_status':    tr_status,
        'wallet_label': wallet_label,
        'wallet_risk':  wallet_risk,
        'chain_label':  chain_label,
        'chain_risk':   chain_risk,
        'escrow_label': escrow_label,
        'tier_label':   get_tier_label(dest) if is_cross else 'DOMESTIC',
        'shap_top3':    [],   # SHAP skipped in API mode for speed
    }


# ─────────────────────────────────────────────────────────────────────────────
# REST ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': MODEL is not None,
        'modules': ['A1','A2','A3','A4','A5','A6','A7'],
        'timestamp': datetime.now().isoformat(),
    })


@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    """
    Returns all scored transactions for the dashboard.
    Query params: merchant (ecommerce/gaming/b2b), n (number of transactions)
    """
    merchant = request.args.get('merchant', 'ecommerce')
    if merchant not in MERCHANT_POLICIES:
        merchant = 'ecommerce'
    n       = min(int(request.args.get('n', 40)), 100)
    policy  = MERCHANT_POLICIES[merchant]

    raw_txns = generate_demo_transactions(n, merchant)
    scored   = [score_transaction(t, policy) for t in raw_txns]

    blocked      = sum(1 for t in scored if t['decision'] == 'BLOCK')
    review       = sum(1 for t in scored if t['decision'] == 'REVIEW')
    allowed      = sum(1 for t in scored if t['decision'] == 'ALLOW')
    total_fraud  = sum(1 for t in scored if t['actual_fraud'] == 1)
    fraud_caught = sum(1 for t in scored if t['actual_fraud'] == 1 and t['decision'] == 'BLOCK')

    # Load drift status
    drift = {'drift_detected': False, 'pr_early': 'N/A', 'pr_mid': 'N/A',
             'pr_late': 'N/A', 'drop': 0}
    if os.path.exists('drift_status.json'):
        try:
            with open('drift_status.json') as f:
                drift = json.load(f)
        except Exception:
            pass

    # Retraining score
    retrain_score = 0
    try:
        feedback_log = json.load(open('feedback_log.json')) if os.path.exists('feedback_log.json') else []
        retrain_score += min(40, len(feedback_log) * 4)
        retrain_score += 40 if drift.get('drift_detected') else min(40, int(drift.get('drop', 0) * 200))
        import time
        if os.path.exists('fraud_model.pkl'):
            age_days = (time.time() - os.path.getmtime('fraud_model.pkl')) / 86400
            retrain_score += min(20, int(age_days * 2))
        retrain_score = min(100, retrain_score)
    except Exception:
        pass

    tr_summary    = get_travel_rule_summary()
    integrity_sum = get_integrity_summary()
    adj_summary   = get_adjustment_summary()

    return jsonify({
        'transactions':     scored,
        'stats': {
            'total':        len(scored),
            'blocked':      blocked,
            'review':       review,
            'allowed':      allowed,
            'fraud_caught': round(fraud_caught / total_fraud * 100) if total_fraud else 0,
        },
        'metrics': {
            'pr_auc':    0.768,   # from training run
            'roc_auc':   0.933,
            'precision': 83,
            'recall':    80,
        },
        'drift':          drift,
        'retrain_score':  retrain_score,
        'travel_rule':    tr_summary,
        'integrity':      integrity_sum,
        'adj_summary':    adj_summary,
        'merchant':       merchant,
        'policy':         policy,
    })


@app.route('/api/score', methods=['POST'])
def api_score():
    """Score a single transaction through all 7 modules."""
    data    = request.get_json() or {}
    merchant= data.get('merchant', 'ecommerce')
    policy  = MERCHANT_POLICIES.get(merchant, MERCHANT_POLICIES['ecommerce'])
    txn     = {
        'id':           data.get('id', 0),
        'card_id':      str(data.get('card_id', '0.0')),
        'amount':       float(data.get('amount', 100)),
        'score_raw':    float(data.get('fraud_score', 0.1)),
        'is_night':     int(data.get('is_night', 0)),
        'graph_degree': int(data.get('graph_degree', 0)),
        'amt_deviation':float(data.get('amt_deviation', 0)),
        'avg_amount':   float(data.get('avg_amount', 100)),
        'origin':       data.get('origin_country', 'SGP'),
        'dest':         data.get('dest_country', 'SGP'),
        'actual_fraud': 0,
        'merchant':     merchant,
    }
    result = score_transaction(txn, policy)
    return jsonify(result)


@app.route('/api/sar/<txn_id>', methods=['GET'])
def api_sar(txn_id):
    """Generate SAR narrative for a transaction."""
    # Build minimal context from query params
    amount    = float(request.args.get('amount', 100))
    score     = float(request.args.get('score', 50))
    reason    = request.args.get('reason', 'HIGH_FRAUD_SCORE')
    origin    = request.args.get('origin', 'SGP')
    dest      = request.args.get('dest', 'SGP')
    tr_status = request.args.get('tr_status', 'NOT_APPLICABLE')
    decision  = request.args.get('decision', 'BLOCK')

    txn_ctx = {
        'id': txn_id, 'amount': amount, 'score': score,
        'expected_loss': round(score/100 * amount, 2),
        'adjusted_expected_loss': round(score/100 * amount * 1.5, 2),
        'jurisdiction_multiplier': 1.5,
        'origin_country': origin, 'dest_country': dest,
        'graph_degree': 0, 'is_night': 0, 'amt_deviation': 0,
        'avg_amount_per_card': amount, 'velocity_alerts': 0,
        'reason': reason, 'shap_top3': [],
        'merchant': 'ecommerce', 'block_threshold': 100, 'review_threshold': 20,
        'travel_rule_status': tr_status, 'travel_rule_missing_fields': [],
        'wallet_risk_score': 0, 'wallet_risk_label': '—',
        'wallet_risk_summary': '', 'decision': decision,
    }
    sar = generate_sar(txn_ctx)
    return jsonify(sar)


@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    """Submit analyst feedback with A6 integrity check."""
    data        = request.get_json() or {}
    txn_id      = str(data.get('transaction_id', ''))
    decision    = data.get('analyst_decision', '')
    card_id     = str(data.get('card_id', ''))
    analyst_id  = data.get('analyst_id', 'analyst_default')
    notes       = data.get('analyst_notes', '')

    # A6 integrity check before applying
    current_mod = get_threshold_modifier(card_id)
    integrity   = check_feedback_integrity(card_id, analyst_id, decision, current_mod)
    log_integrity_check(integrity)
    if integrity.escalate_to_mlro:
        log_escalation(integrity)

    if integrity.approved:
        apply_feedback_adjustments(card_id, decision)
        # Log to feedback_log.json
        log = []
        if os.path.exists('feedback_log.json'):
            try:
                with open('feedback_log.json') as f:
                    log = json.load(f)
            except Exception:
                pass
        log.append({
            'transaction_id':   txn_id,
            'card_id':          card_id,
            'analyst_id':       analyst_id,
            'analyst_decision': decision,
            'analyst_notes':    notes,
            'timestamp':        datetime.now().isoformat(),
        })
        with open('feedback_log.json', 'w') as f:
            json.dump(log, f, indent=2)
        status = 'approved'
    elif integrity.requires_consensus:
        status = 'consensus_required'
    else:
        status = 'blocked'

    return jsonify({
        'status':           status,
        'integrity_note':   integrity.integrity_note,
        'flags':            integrity.flags,
        'escalated':        integrity.escalate_to_mlro,
        'proposed_modifier':integrity.proposed_modifier,
    })


@app.route('/api/travel_rule/summary', methods=['GET'])
def api_tr_summary():
    return jsonify(get_travel_rule_summary())


@app.route('/api/integrity/summary', methods=['GET'])
def api_integrity_summary():
    return jsonify(get_integrity_summary())


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
