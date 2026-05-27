import json
from datetime import datetime

ADJUSTMENTS_FILE = 'entity_adjustments.json'


def _load() -> dict:
    try:
        with open(ADJUSTMENTS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    with open(ADJUSTMENTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def apply_feedback_adjustments(card_id: str, analyst_decision: str) -> None:
    data = _load()
    key = str(card_id)
    entry = data.get(key, {
        'threshold_modifier': 1.0,
        'block_count': 0,
        'false_positive_count': 0,
        'last_updated': None,
    })

    if analyst_decision == 'CONFIRM_FRAUD':
        entry['threshold_modifier'] *= 0.7
        entry['block_count'] += 1
    elif analyst_decision == 'FALSE_POSITIVE':
        entry['threshold_modifier'] *= 1.4
        entry['false_positive_count'] += 1
    # CONFIRM_LEGIT: no threshold change, just persist the entry with updated timestamp

    entry['threshold_modifier'] = round(
        max(0.3, min(2.0, entry['threshold_modifier'])), 4
    )
    entry['last_updated'] = datetime.now().isoformat()

    data[key] = entry
    _save(data)


def get_threshold_modifier(card_id: str) -> float:
    data = _load()
    entry = data.get(str(card_id))
    if not entry:
        return 1.0
    return float(entry.get('threshold_modifier', 1.0))


def get_adjustment_summary() -> dict:
    data = _load()
    tightened = sum(1 for e in data.values() if e.get('threshold_modifier', 1.0) < 1.0)
    loosened  = sum(1 for e in data.values() if e.get('threshold_modifier', 1.0) > 1.0)
    return {
        'total_adjusted': len(data),
        'tightened': tightened,
        'loosened': loosened,
    }
