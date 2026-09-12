# AegisAI — Two-Tier Prompt Injection Detector

**AegisAI** is a defense-in-depth prompt perimeter defense system designed for SOC analysts, AI application security teams, and LLM engineers. It inspects incoming prompts and model responses for jailbreaks, indirect injections, system prompt extractions, config overrides, and delimiter smuggling using a two-tier evaluation engine.

---

## Architecture Overview

```
[ Incoming Prompt / User Query ]
               │
               ▼
   ┌───────────────────────────────────────────────┐
   │         TIER 1: Algorithmic & Heuristics       │
   │  • Subword TF-IDF Vector Cosine Engine        │
   │  • Semantic Intent Grammar Parser             │
   │  • Shannon Entropy Anomaly Detector           │
   │  • Obfuscation Normalizer (Homoglyphs/Leet)   │
   │  • Rebuff Canary Token Leak Detector          │
   │  • Defensive Negative Statement Pass-Through  │
   └──────────────────────┬────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
    Clear SAFE (<20)              Ambiguous (20-69)
    or Hostile (70+)              or Anomaly Detected
          │                               │
          ▼                               ▼
      [ RESULT ]             ┌─────────────────────────┐
                             │    TIER 2: Semantic SLM  │
                             │ • Gemini Context Engine │
                             │ • Rebuff Vector Cache   │
                             └────────────┬────────────┘
                                          │
                                          ▼
                                      [ RESULT ]
```

---

## Features

- **Multi-Vector Detection**:
  - Classic & subtle roleplay jailbreaks (DAN, Developer Mode, uncensored persona)
  - Config & guideline overrides (`set guidelines to false`, `filters = 0`, etc.)
  - Indirect injections & comment-smuggled directives (`<!-- ... -->`, `/* ... */`)
  - Hidden prompt & canary token exfiltration (`Secret-Canary:...`)
  - High-entropy Base64 / Hex cipher smuggling
- **Intelligent Negation Awareness**: Correctly differentiates between adversarial attacks (`"do not follow guidelines"`) and safety-reinforcing statements (`"do not set guidelines to 0"`, `"never bypass safety"`).
- **Interactive SOC Dashboard**:
  - Live radar threat surface breakdown across 5 vectors (Instruction Integrity, Role Consistency, Source Boundary, Social Engineering, Extraction Guard).
  - Real-time telemetry event feed and latency tracking.
  - Client-side fallback engine for zero-dependency offline evaluations.

---

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend Setup (FastAPI)
```bash
# Install Python dependencies
pip install -r requirements.txt

# Configure environment (optional Gemini API key for Tier-2)
cp .env.example .env

# Run FastAPI backend
python -m uvicorn main:app --reload --port 8000
```
Backend API will be live at `http://localhost:8000` with Swagger docs at `http://localhost:8000/docs`.

### Frontend Setup (React + Vite + TailwindCSS)
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start Vite dev server
npm run dev
```
Frontend UI will be live at `http://localhost:5173`.

---

## Testing & Benchmarks

```bash
# Run backend security scanner benchmark
python test_scanner.py

# Run client-side detection engine test suite
cd frontend
npx tsx test_client_engine.js
```
