<div align="center">

# 🛡️ Password Guardian Pro

**Professional-grade password security analyser and cryptographic generator**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)

*Built with entropy analysis · Breach detection · Crack-time estimation · CSPRNG generation*

</div>

---

## 📋 Overview

Password Guardian Pro is a full-stack cybersecurity tool that goes far beyond a basic strength checker. It combines information-theoretic entropy analysis, pattern-based heuristics, breach dataset lookup, and multi-scenario crack-time estimation into a single professional dashboard — built without any frontend framework.

This project demonstrates practical application of:
- **Cryptographic principles** — entropy, CSPRNG, secure hashing
- **Threat modelling** — five real-world attack scenarios with realistic speed assumptions
- **Secure engineering practices** — no raw password storage, parameterised SQL, security headers
- **Full-stack architecture** — REST API, SQLite persistence, SPA frontend

---

## ✨ Features

### 🔍 Password Analysis Engine
- **Dual-engine scoring** — custom heuristic (70%) blended with [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) (30%)
- **True entropy calculation** — raw entropy penalised for repeats, sequences, and keyboard walks
- **10 security checks** — length, character classes, patterns, breach status
- **Weighted 0–100 score** with letter grade (F → A+)

### ⏱ Crack Time Estimation
Five attack scenarios modelled across realistic threat actors:

| Scenario | Speed | Example |
|---|---|---|
| Online (throttled) | 100/s | Rate-limited login form |
| Online (unthrottled) | 10,000/s | No rate limiting |
| Offline (bcrypt) | 1,000,000/s | Stolen bcrypt hash DB |
| Offline (MD5/GPU) | 100,000,000/s | Stolen MD5 hash DB |
| GPU Cluster | 100,000,000,000/s | Nation-state attacker |

### ⚠️ Breach Detection
- Checks against **~10,000 most common/breached passwords** (NCSC dataset)
- O(1) lookup via Python `set` — no per-request file scanning
- Breached passwords hard-capped at score 15 regardless of entropy

### 🔑 Secure Password Generator
- **`secrets` module** — OS CSPRNG, not `random` (Mersenne Twister)
- **Custom Fisher-Yates shuffle** using `secrets.randbelow()` — PRNG-safe shuffle
- **Four modes**: Random · Pronounceable (CV syllables) · Passphrase (Diceware-style) · PIN
- **Ambiguous character filtering** — removes 0/O/1/l/I from pool

### 📊 Analytics Dashboard
- Total analyses · Average score · Strong/Weak percentages
- Strength breakdown pie chart + score distribution bar chart
- Full paginated analysis history (SHA-256 hash only — never raw passwords)

### 🎓 Security Education
Explains: Entropy · Brute Force · Dictionary Attack · Rainbow Tables · Credential Stuffing · Password Reuse · Best Practices

### 🌙 Dark / Light Theme
- Full glassmorphism UI with animated SVG score ring
- Theme persisted to `localStorage`
- `prefers-reduced-motion` respected

---

## 🖼 Screenshots

> *Run the app and visit `http://localhost:5000` to see it in action.*

| Analyser Tab | Generator Tab |
|---|---|
| `[screenshot: analyser]` | `[screenshot: generator]` |

| Dashboard Tab | Education Tab |
|---|---|
| `[screenshot: dashboard]` | `[screenshot: education]` |

---

## 🗂 Project Structure

```
PasswordGuardian/
│
├── app.py                    # Flask app factory + REST API routes
├── requirements.txt          # Pinned Python dependencies
├── README.md
├── .gitignore
│
├── utils/
│   ├── entropy.py            # Entropy calculation + crack time estimation
│   ├── checker.py            # Core analysis engine (scoring, checks, suggestions)
│   ├── generator.py          # CSPRNG password/passphrase/PIN generator
│   └── database.py           # SQLite persistence layer
│
├── templates/
│   └── index.html            # Single-page application shell
│
├── static/
│   ├── css/
│   │   └── style.css         # Full design system (dark/light, glassmorphism)
│   └── js/
│       └── main.js           # SPA controller (Api · UI · Charts modules)
│
├── datasets/
│   └── common_passwords.txt  # ~10,000 NCSC common/breached passwords
│
└── database/
    └── guardian.db           # SQLite DB (auto-created, git-ignored)
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- pip

### 1 — Clone the repository

```bash
git clone https://github.com/yourusername/PasswordGuardianPro.git
cd PasswordGuardianPro
```

### 2 — Create a virtual environment

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### 4 — Run the application

```bash
python app.py
```

Visit **http://localhost:5000** in your browser.

### Optional — Development mode with auto-reload

```bash
FLASK_DEBUG=true python app.py
```

---

## 🔌 REST API Reference

All endpoints return JSON. Error responses follow `{ "error": str, "status": int }`.

### `POST /api/analyze`

Analyse a password and return a full security report.

**Request**
```json
{
  "password": "MyP@ssw0rd!",
  "save": true
}
```

**Response**
```json
{
  "score":         72,
  "strength":      "Strong",
  "grade":         "B",
  "color":         "#22c55e",
  "entropy":       65.4,
  "true_entropy":  58.2,
  "crack_time": {
    "summary":              "3 months",
    "online_throttled":     "Millions of years",
    "online_unthrottled":   "300 years",
    "offline_slow":         "3 months",
    "offline_fast":         "2 days",
    "offline_gpu_cluster":  "Instant"
  },
  "checks": {
    "has_uppercase": true,
    "has_lowercase": true,
    "has_digits":    true,
    "has_symbols":   true,
    "length":        11,
    "has_repeats":   false,
    "has_sequences": false,
    "..."
  },
  "suggestions":   ["🔤 Simple leet-speak substitutions are well-known to attackers."],
  "breached":      false,
  "hash":          "a3f9c1b2d4e6f8...",
  "saved":         true,
  "elapsed_ms":    14.3
}
```

---

### `POST /api/generate`

Generate a cryptographically secure password.

**Request**
```json
{
  "mode":            "random",
  "length":          20,
  "use_uppercase":   true,
  "use_lowercase":   true,
  "use_digits":      true,
  "use_symbols":     true,
  "avoid_ambiguous": false,
  "pronounceable":   false
}
```

**Passphrase mode**
```json
{ "mode": "passphrase", "word_count": 4, "separator": "-" }
```

**PIN mode**
```json
{ "mode": "pin", "length": 6 }
```

**Response**
```json
{
  "password":  "K#9mL$vQ2@Xr4&nT8!pA",
  "length":    20,
  "entropy":   131.1,
  "pool_size": 92,
  "mode":      "random"
}
```

---

### `GET /api/history`

Paginated analysis history.

```
GET /api/history?limit=20&offset=0
```

**Response**
```json
{
  "records": [
    {
      "id":         42,
      "created_at": "2024-11-15T14:32:07+00:00",
      "hash":       "a3f9c1b2d4e6f8...",
      "score":      72,
      "strength":   "Strong",
      "entropy":    58.2,
      "grade":      "B",
      "length":     11,
      "breached":   0
    }
  ],
  "count":  1,
  "limit":  20,
  "offset": 0
}
```

---

### `GET /api/stats`

Aggregated dashboard statistics.

**Response**
```json
{
  "total_checked":      47,
  "average_score":      54.3,
  "strong_count":       18,
  "weak_count":         12,
  "fair_count":         17,
  "strong_percent":     38.3,
  "weak_percent":       25.5,
  "strength_breakdown": { "Weak": 12, "Fair": 17, "Strong": 18 },
  "score_distribution": { "0-19": 3, "20-39": 9, "40-59": 17, "60-79": 11, "80-100": 7 }
}
```

---

### `POST /api/clear`

Clear all analysis history and reset statistics.

**Response**
```json
{ "deleted": 47, "message": "Successfully deleted 47 records." }
```

---

## 🔐 Security Design Decisions

| Decision | Rationale |
|---|---|
| `secrets` not `random` | OS CSPRNG vs predictable Mersenne Twister PRNG |
| SHA-256 hash storage only | Raw passwords never touch the database |
| Parameterised SQL queries | Zero string interpolation — SQL injection impossible |
| WAL journal mode | Concurrent reads during writes; no blocking |
| `Cache-Control: no-store` | Browser never caches analysis responses containing hashes |
| `X-Frame-Options: DENY` | Clickjacking prevention |
| Input length cap (512 chars) | Prevents memory exhaustion from pathological inputs |
| Breach score cap (15/100) | Ensures breached passwords never appear "strong" |

---

## 🛠 Technologies Used

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Python 3.10+ | Application logic |
| Web framework | Flask 3.0 | REST API + template serving |
| Entropy analysis | zxcvbn-python | Pattern-based strength estimation |
| Hashing | hashlib (SHA-256) | Password fingerprinting |
| Secure generation | secrets (stdlib) | CSPRNG password generation |
| Database | SQLite 3 | Analysis history persistence |
| Charts | Chart.js 4.4 | Dashboard visualisations |
| Frontend | Vanilla JS (ES2022) | SPA without framework overhead |
| Styling | CSS3 Custom Properties | Design token system, glassmorphism |

---

## 🔭 Future Improvements

- [ ] **HaveIBeenPwned API integration** — k-anonymity SHA-1 prefix lookup for real breach checking
- [ ] **Rate limiting** — `Flask-Limiter` on `/api/analyze` to prevent abuse
- [ ] **Authentication** — protect history and dashboard behind a login
- [ ] **Export** — download analysis history as CSV or PDF
- [ ] **Browser extension** — analyse passwords inline in login forms
- [ ] **Docker support** — `Dockerfile` + `docker-compose.yml` for containerised deployment
- [ ] **CI/CD** — GitHub Actions with `pytest` unit tests for all utils modules
- [ ] **Argon2 benchmarking** — add offline Argon2id scenario to crack time estimates
- [ ] **Internationalisation** — i18n for suggestions and UI labels

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built as a professional cybersecurity portfolio project · Suitable for internship interviews and GitHub showcasing

**⭐ Star this repo if you found it useful**

</div>
