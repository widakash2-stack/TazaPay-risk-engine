# Tazapay Risk Intelligence Engine

Production-grade cross-border fraud & compliance decisioning platform.
Built for the Tazapay PM interview — demonstrates all 7 additions live.

## Architecture

```
GitHub repo
├── backend/          → Python Flask API → deploys to Render (free)
│   ├── api.py        → REST API exposing all 7 modules
│   ├── requirements.txt
│   └── [all .py modules]
├── frontend/         → Static HTML → deploys to Netlify (free)
│   └── index.html    → Full dashboard, calls Render API
├── render.yaml       → Render deployment config
└── netlify.toml      → Netlify deployment config
```

## What's Live

| Module | What it does |
|--------|-------------|
| A1 Jurisdiction Risk | 173-country FATF risk multiplier on expected loss |
| A2 Travel Rule | Cross-border >$1,000 compliance flag + data collection |
| A3 SAR Narrative | LLM-generated Suspicious Activity Reports (MAS/FINTRAC/FinCEN) |
| A4 Wallet Risk | On-chain stablecoin wallet scoring (mixer, darknet, bridge-hop) |
| A5 Chain Scoring | Multi-hop chain risk: 1 − Π(1 − pᵢ) — catches structuring |
| A6 Integrity Check | Feedback loop insider-fraud protection with MLRO escalation |
| A7 Escrow Risk | Escrow-specific AML rules with SAR obligation detection |

---

## Deploy in 15 minutes

### Step 1 — Fork / clone this repo

```bash
git clone https://github.com/YOUR_USERNAME/tazapay-risk-engine
cd tazapay-risk-engine
```

### Step 2 — Deploy backend to Render

1. Go to **https://render.com** → Sign up (free)
2. Click **New** → **Web Service**
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` — click **Apply**
5. Under **Environment Variables**, add:
   ```
   ANTHROPIC_API_KEY = sk-ant-...your key...
   ```
6. Click **Deploy** — takes ~3 minutes first time
7. Copy your Render URL: `https://tazapay-risk-engine.onrender.com`

### Step 3 — Update API_BASE in frontend

Open `frontend/index.html`, find line ~12:
```javascript
: 'https://tazapay-risk-engine.onrender.com';  // ← UPDATE THIS
```
Replace with your actual Render URL. Commit and push.

### Step 4 — Deploy frontend to Netlify

1. Go to **https://netlify.com** → Sign up (free)
2. Click **Add new site** → **Import from Git**
3. Connect your GitHub repo
4. Netlify auto-detects `netlify.toml`:
   - Build command: *(leave empty)*
   - Publish directory: `frontend`
5. Click **Deploy** — done in ~30 seconds
6. Your dashboard is live at: `https://[random-name].netlify.app`

### Step 5 — Custom domain (optional)

In Netlify → Domain settings → Add custom domain.

---

## Local development

```bash
# Backend
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python api.py
# Runs on http://localhost:5000

# Frontend
# Open frontend/index.html in browser
# API_BASE auto-detects localhost:5000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check + model status |
| `/api/dashboard` | GET | All scored transactions + stats |
| `/api/score` | POST | Score a single transaction |
| `/api/sar/:txnId` | GET | Generate SAR narrative |
| `/api/feedback` | POST | Submit analyst feedback (with A6 integrity) |
| `/api/travel_rule/summary` | GET | Travel Rule compliance stats |
| `/api/integrity/summary` | GET | Feedback integrity stats |

## Files in backend/

| File | Purpose |
|------|---------|
| `api.py` | Flask REST API — main entry point |
| `jurisdiction_risk.py` | A1 — 173-country FATF risk tiers |
| `travel_rule.py` | A2 — Travel Rule compliance checker |
| `sar_narrative_engine.py` | A3 — LLM SAR generator with validation |
| `stablecoin_risk.py` | A4 — On-chain wallet risk scoring |
| `chain_scoring.py` | A5 — Multi-hop chain risk formula |
| `feedback_integrity.py` | A6 — Insider fraud protection |
| `feedback_processor.py` | Original threshold modifier logic |
| `escrow_risk.py` | A7 — Escrow-specific AML rules |
| `requirements.txt` | Python dependencies |

## Notes

- Render free tier spins down after 15 minutes of inactivity — first request after sleep takes ~30s
- To keep it warm: use UptimeRobot (free) to ping `/health` every 14 minutes
- ANTHROPIC_API_KEY is only needed for A3 SAR narrative generation — all other modules work without it
- Model runs in demo mode (no `fraud_model.pkl`) — generates realistic synthetic transactions
