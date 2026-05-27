# feedback_integrity.py
# ──────────────────────────────────────────────────────────────────────────────
# A6 — Feedback Loop Integrity Check
#
# WHY THIS EXISTS:
#   The feedback_processor.py (original) adjusts per-card thresholds based on
#   analyst decisions. It is powerful — but completely unguarded.
#
#   Current attack vector:
#     1. Compromised analyst logs into the compliance dashboard
#     2. Marks merchant_id_X as FALSE_POSITIVE 5 times in 3 days
#     3. merchant_id_X modifier reaches 2.0 (maximum)
#     4. merchant_id_X can now pass through transactions at 2× the normal threshold
#     5. Fraudster knew this because they own the analyst account
#
#   This is called feedback poisoning — using the learning loop as a back door.
#   It's the compliance equivalent of a SQL injection attack.
#   Tazapay's MAS license requires that all risk adjustments be auditable
#   and resistant to single-point-of-failure human override.
#
# WHAT THIS MODULE ADDS:
#   1. Velocity cap — max modifier change per entity per 24-hour window
#   2. Consensus gate — loosening above 1.5× requires 2 different analysts
#   3. Escalation trigger — suspicious feedback patterns alert the MLRO
#   4. Audit trail — every integrity check logged with analyst ID + timestamp
#   5. Auto-revert — if an entity's modifier moves 0.5+ from baseline in
#      < 48 hours, the change is flagged and the modifier is temporarily frozen
#
# WORKS ALONGSIDE feedback_processor.py:
#   This module wraps feedback_processor — it intercepts every feedback
#   submission, runs integrity checks, and either approves, flags, or blocks
#   the modifier update before feedback_processor applies it.
# ──────────────────────────────────────────────────────────────────────────────

import json
import os
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Configuration ─────────────────────────────────────────────────────────────
INTEGRITY_LOG_FILE         = 'feedback_integrity_log.json'
ESCALATION_LOG_FILE        = 'feedback_escalations.json'

# Max modifier movement per entity per 24-hour rolling window
MAX_MODIFIER_CHANGE_24H    = 0.30

# Consensus required when modifier would exceed this level after loosening
CONSENSUS_REQUIRED_ABOVE   = 1.50

# Auto-freeze trigger: if modifier moves this far from 1.0 in < 48 hours
RAPID_DRIFT_THRESHOLD      = 0.50
RAPID_DRIFT_WINDOW_HOURS   = 48

# Max number of times the same analyst can submit feedback for the same entity
# in a 7-day window before triggering an escalation review
SAME_ANALYST_ENTITY_LIMIT  = 3

# Modifier bounds (matches feedback_processor.py)
MODIFIER_MIN = 0.30
MODIFIER_MAX = 2.00


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class IntegrityCheckResult:
    """
    Result of an integrity check on a feedback submission.
    """
    entity_id:          str
    analyst_id:         str
    analyst_decision:   str         # CONFIRM_FRAUD / FALSE_POSITIVE / CONFIRM_LEGIT
    proposed_modifier:  float       # what the modifier would become
    current_modifier:   float       # current modifier before this feedback

    # Gate results
    approved:           bool        # True = allow modifier update
    blocked:            bool        # True = block modifier update entirely
    requires_consensus: bool        # True = second analyst required

    # Flags raised
    flags:              list = field(default_factory=list)

    # Escalation
    escalate_to_mlro:   bool   = False
    escalation_reason:  str    = ''

    # Audit
    checked_at:         str    = field(default_factory=lambda: datetime.now().isoformat())
    integrity_note:     str    = ''


@dataclass
class ConsensusRecord:
    """
    Tracks pending consensus requirements.
    A loosening that requires 2 analysts stores here until confirmed.
    """
    entity_id:          str
    requested_by:       str         # analyst_id of first approval
    proposed_modifier:  float
    requested_at:       str
    confirmed_by:       str    = ''
    confirmed_at:       str    = ''
    status:             str    = 'PENDING'   # PENDING / CONFIRMED / EXPIRED


# ── Log helpers ───────────────────────────────────────────────────────────────

def _load_json(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def _save_json(path: str, data: list) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def _append_json(path: str, record: dict) -> None:
    log = _load_json(path)
    log.append(record)
    _save_json(path, log)


# ── Core integrity checks ──────────────────────────────────────────────────────

def _check_velocity(
    entity_id: str,
    proposed_modifier: float,
    current_modifier: float,
) -> tuple[bool, str]:
    """
    Check 1: Modifier velocity cap.
    No entity's modifier can change by more than MAX_MODIFIER_CHANGE_24H
    in any rolling 24-hour window.

    Returns (passes, reason_if_blocked)
    """
    log = _load_json(INTEGRITY_LOG_FILE)
    cutoff = datetime.now() - timedelta(hours=24)

    recent_changes = [
        entry for entry in log
        if entry.get('entity_id') == str(entity_id)
        and entry.get('approved') is True
        and datetime.fromisoformat(entry.get('checked_at', '2000-01-01')) > cutoff
    ]

    # Sum of absolute modifier changes in last 24h
    total_change_24h = sum(
        abs(entry.get('proposed_modifier', 1.0) - entry.get('current_modifier', 1.0))
        for entry in recent_changes
    )

    proposed_change = abs(proposed_modifier - current_modifier)
    if total_change_24h + proposed_change > MAX_MODIFIER_CHANGE_24H:
        return False, (
            f"Velocity cap exceeded: {total_change_24h:.3f} change already applied "
            f"in last 24h for entity {entity_id}. "
            f"Max allowed: {MAX_MODIFIER_CHANGE_24H}. "
            f"Proposed additional change: {proposed_change:.3f}."
        )
    return True, ''


def _check_consensus(
    entity_id: str,
    analyst_id: str,
    proposed_modifier: float,
    current_modifier: float,
) -> tuple[bool, bool, str]:
    """
    Check 2: Consensus gate.
    Loosening (modifier increasing) beyond CONSENSUS_REQUIRED_ABOVE requires
    confirmation from a second analyst.

    Returns (passes, requires_consensus, reason)
    """
    # Only applies to loosening actions
    if proposed_modifier <= current_modifier:
        return True, False, ''

    if proposed_modifier > CONSENSUS_REQUIRED_ABOVE:
        # Check if there's already a pending consensus record for this entity
        consensus_log = _load_json('feedback_consensus.json')
        pending = [
            r for r in consensus_log
            if r.get('entity_id') == str(entity_id)
            and r.get('status') == 'PENDING'
            and r.get('requested_by') != analyst_id
        ]

        if pending:
            # Second analyst confirming — approve
            return True, False, 'Consensus confirmed by second analyst.'

        # First analyst — store pending, require second
        pending_record = asdict(ConsensusRecord(
            entity_id        = str(entity_id),
            requested_by     = analyst_id,
            proposed_modifier= proposed_modifier,
            requested_at     = datetime.now().isoformat(),
        ))
        consensus_log.append(pending_record)
        _save_json('feedback_consensus.json', consensus_log)

        return False, True, (
            f"Modifier {proposed_modifier:.2f} exceeds consensus threshold "
            f"{CONSENSUS_REQUIRED_ABOVE}. "
            f"Second analyst confirmation required. "
            f"Request logged for entity {entity_id}."
        )

    return True, False, ''


def _check_analyst_concentration(
    entity_id: str,
    analyst_id: str,
) -> tuple[bool, str]:
    """
    Check 3: Same-analyst concentration.
    One analyst cannot submit more than SAME_ANALYST_ENTITY_LIMIT feedback
    entries for the same entity in a 7-day rolling window.

    This is the primary insider fraud detection check.
    Legitimate use case: analyst reviews an entity once, maybe twice.
    Insider fraud: same analyst reviews same entity 5-10 times to
    systematically loosen its threshold.
    """
    log = _load_json(INTEGRITY_LOG_FILE)
    cutoff = datetime.now() - timedelta(days=7)

    same_analyst_same_entity = [
        entry for entry in log
        if entry.get('entity_id') == str(entity_id)
        and entry.get('analyst_id') == str(analyst_id)
        and datetime.fromisoformat(entry.get('checked_at', '2000-01-01')) > cutoff
    ]

    if len(same_analyst_same_entity) >= SAME_ANALYST_ENTITY_LIMIT:
        return False, (
            f"Analyst {analyst_id} has submitted {len(same_analyst_same_entity)} "
            f"feedback entries for entity {entity_id} in the last 7 days. "
            f"Limit is {SAME_ANALYST_ENTITY_LIMIT}. "
            f"Escalating to MLRO for review."
        )
    return True, ''


def _check_rapid_drift(
    entity_id: str,
    proposed_modifier: float,
) -> tuple[bool, str]:
    """
    Check 4: Rapid drift detection.
    If an entity's modifier has moved more than RAPID_DRIFT_THRESHOLD
    from the baseline (1.0) in less than RAPID_DRIFT_WINDOW_HOURS,
    freeze further changes and alert MLRO.

    Catches coordinated multi-analyst insider attacks where two compromised
    analysts take turns loosening the same entity's threshold.
    """
    drift_from_baseline = abs(proposed_modifier - 1.0)

    if drift_from_baseline >= RAPID_DRIFT_THRESHOLD:
        # Check when the drift started
        log = _load_json(INTEGRITY_LOG_FILE)
        cutoff = datetime.now() - timedelta(hours=RAPID_DRIFT_WINDOW_HOURS)

        recent_for_entity = [
            entry for entry in log
            if entry.get('entity_id') == str(entity_id)
            and datetime.fromisoformat(entry.get('checked_at', '2000-01-01')) > cutoff
        ]

        if recent_for_entity:
            return False, (
                f"Rapid drift detected for entity {entity_id}: "
                f"modifier has drifted {drift_from_baseline:.2f} from baseline (1.0) "
                f"within {RAPID_DRIFT_WINDOW_HOURS}h window. "
                f"Further changes frozen. MLRO escalation triggered."
            )

    return True, ''


# ── Main check function ────────────────────────────────────────────────────────

def check_feedback_integrity(
    entity_id: str,
    analyst_id: str,
    analyst_decision: str,
    current_modifier: float,
) -> IntegrityCheckResult:
    """
    Runs all integrity checks on a feedback submission before allowing
    feedback_processor.apply_feedback_adjustments() to run.

    Args:
        entity_id:         Card ID / merchant ID / wallet ID being adjusted
        analyst_id:        ID of the analyst submitting feedback
                           In production: comes from auth session
                           For demo: passed explicitly
        analyst_decision:  CONFIRM_FRAUD / FALSE_POSITIVE / CONFIRM_LEGIT
        current_modifier:  The entity's current threshold modifier

    Returns:
        IntegrityCheckResult
        If result.approved = True  → call feedback_processor normally
        If result.approved = False → block the modifier update
        If result.requires_consensus → wait for second analyst confirmation

    Usage in dashboard.py:
        integrity = check_feedback_integrity(card_id, analyst_id, decision, current_mod)
        if integrity.approved:
            feedback_processor.apply_feedback_adjustments(card_id, decision)
        elif integrity.requires_consensus:
            return jsonify({'status': 'consensus_required', 'note': integrity.integrity_note})
        else:
            return jsonify({'status': 'blocked', 'note': integrity.integrity_note})
        log_integrity_check(integrity)
    """
    # Compute proposed modifier (mirrors feedback_processor.py logic)
    if analyst_decision == 'CONFIRM_FRAUD':
        proposed = round(max(MODIFIER_MIN, min(MODIFIER_MAX, current_modifier * 0.7)), 4)
    elif analyst_decision == 'FALSE_POSITIVE':
        proposed = round(max(MODIFIER_MIN, min(MODIFIER_MAX, current_modifier * 1.4)), 4)
    else:
        proposed = current_modifier   # CONFIRM_LEGIT — no change

    flags              = []
    blocked            = False
    requires_consensus = False
    escalate           = False
    notes              = []

    # CONFIRM_LEGIT requires no integrity check
    if analyst_decision == 'CONFIRM_LEGIT':
        return IntegrityCheckResult(
            entity_id=str(entity_id), analyst_id=str(analyst_id),
            analyst_decision=analyst_decision,
            proposed_modifier=proposed, current_modifier=current_modifier,
            approved=True, blocked=False, requires_consensus=False,
            integrity_note='CONFIRM_LEGIT — no modifier change, no checks required.',
        )

    # Check 1 — Velocity cap
    vel_ok, vel_msg = _check_velocity(str(entity_id), proposed, current_modifier)
    if not vel_ok:
        flags.append('VELOCITY_CAP_EXCEEDED')
        blocked = True
        escalate = True
        notes.append(vel_msg)

    # Check 2 — Consensus gate (only for loosening)
    if not blocked:
        con_ok, req_con, con_msg = _check_consensus(
            str(entity_id), str(analyst_id), proposed, current_modifier
        )
        if not con_ok and req_con:
            flags.append('CONSENSUS_REQUIRED')
            requires_consensus = True
            notes.append(con_msg)
        elif not con_ok:
            flags.append('CONSENSUS_BLOCKED')
            blocked = True
            notes.append(con_msg)

    # Check 3 — Analyst concentration
    conc_ok, conc_msg = _check_analyst_concentration(str(entity_id), str(analyst_id))
    if not conc_ok:
        flags.append('ANALYST_CONCENTRATION')
        blocked = True
        escalate = True
        notes.append(conc_msg)

    # Check 4 — Rapid drift
    if not blocked:
        drift_ok, drift_msg = _check_rapid_drift(str(entity_id), proposed)
        if not drift_ok:
            flags.append('RAPID_DRIFT_DETECTED')
            blocked = True
            escalate = True
            notes.append(drift_msg)

    approved = not blocked and not requires_consensus

    escalation_reason = ' | '.join(notes) if escalate else ''

    result = IntegrityCheckResult(
        entity_id          = str(entity_id),
        analyst_id         = str(analyst_id),
        analyst_decision   = analyst_decision,
        proposed_modifier  = proposed,
        current_modifier   = current_modifier,
        approved           = approved,
        blocked            = blocked,
        requires_consensus = requires_consensus,
        flags              = flags,
        escalate_to_mlro   = escalate,
        escalation_reason  = escalation_reason,
        integrity_note     = ' | '.join(notes) if notes else 'All checks passed.',
    )

    return result


def log_integrity_check(result: IntegrityCheckResult) -> None:
    """
    Appends integrity check result to audit log.
    Used by MAS for compliance audit trail.
    """
    _append_json(INTEGRITY_LOG_FILE, asdict(result))


def log_escalation(result: IntegrityCheckResult) -> None:
    """
    Logs MLRO escalation events separately for immediate visibility.
    """
    if result.escalate_to_mlro:
        _append_json(ESCALATION_LOG_FILE, {
            'entity_id':         result.entity_id,
            'analyst_id':        result.analyst_id,
            'decision':          result.analyst_decision,
            'flags':             result.flags,
            'escalation_reason': result.escalation_reason,
            'escalated_at':      result.checked_at,
        })


def get_integrity_summary() -> dict:
    """Dashboard summary of integrity check stats."""
    log = _load_json(INTEGRITY_LOG_FILE)
    return {
        'total_checks':      len(log),
        'approved':          sum(1 for e in log if e.get('approved')),
        'blocked':           sum(1 for e in log if e.get('blocked')),
        'consensus_pending': sum(1 for e in log if e.get('requires_consensus')),
        'escalated':         sum(1 for e in log if e.get('escalate_to_mlro')),
    }


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 65)
    print("FEEDBACK INTEGRITY MODULE — SELF TEST")
    print("=" * 65)

    test_cases = [
        ('CARD-001', 'analyst_A', 'FALSE_POSITIVE', 1.0,  'Normal FP — should pass'),
        ('CARD-001', 'analyst_A', 'FALSE_POSITIVE', 1.0,  'Second FP same analyst same card'),
        ('CARD-001', 'analyst_A', 'FALSE_POSITIVE', 1.0,  'Third FP — concentration limit hit'),
        ('CARD-002', 'analyst_B', 'FALSE_POSITIVE', 1.4,  'Loosening above consensus threshold'),
        ('CARD-002', 'analyst_C', 'FALSE_POSITIVE', 1.4,  'Second analyst confirms consensus'),
        ('CARD-003', 'analyst_D', 'CONFIRM_FRAUD',  1.0,  'Normal confirm fraud — should pass'),
        ('CARD-004', 'analyst_E', 'CONFIRM_LEGIT',  1.2,  'Confirm legit — no check needed'),
    ]

    for entity_id, analyst_id, decision, current_mod, desc in test_cases:
        result = check_feedback_integrity(entity_id, analyst_id, decision, current_mod)
        log_integrity_check(result)
        if result.escalate_to_mlro:
            log_escalation(result)

        status = ('✅ APPROVED' if result.approved
                  else '⏳ CONSENSUS' if result.requires_consensus
                  else '🚨 BLOCKED')

        print(f"\n{status} | {desc}")
        print(f"  Entity: {entity_id} | Analyst: {analyst_id} | Decision: {decision}")
        print(f"  Modifier: {current_mod} → {result.proposed_modifier}")
        if result.flags:
            print(f"  Flags: {result.flags}")
        print(f"  Note: {result.integrity_note}")
        if result.escalate_to_mlro:
            print(f"  🔺 MLRO ESCALATION: {result.escalation_reason}")

    summary = get_integrity_summary()
    print(f"\n{'=' * 65}")
    print(f"SUMMARY: {summary}")
