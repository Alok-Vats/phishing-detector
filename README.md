# Phishing Detection Major Project

## 1. Project Overview
The Major Project is a production-grade, hybrid ML architecture designed to detect malicious URLs and phishing emails. It utilizes a layered approach that combines classical Machine Learning (Random Forests, Linear SVM, TF-IDF), deterministic heuristic rules, and live Threat Intelligence queries, all orchestrated by a secure REST API. 

## 2. Problem Statement
Phishing attacks are constantly evolving, evading purely heuristic filters and basic blocklists. A static, un-versioned machine learning model quickly degrades against adversarial obfuscation (e.g., "l33t" speak, hidden elements, nested iframes). A resilient system requires a hybrid architecture capable of fusing live reputation scoring, offline ML inference, static HTML structural analysis, and explainability to empower end-users.

## 3. Major Project Objectives
- Build a robust ML pipeline capable of accurately classifying URLs and unstructured email text.
- Create a Hybrid Risk Engine that gracefully merges ML scores with live Threat Intelligence (VirusTotal/URLHaus) without network-blocking vulnerabilities.
- Provide true Explainable AI (XAI) transparently exposing precisely why a domain or email was flagged.
- Deliver a secure, RBAC-protected REST API and Admin Dashboard for telemetry.
- Provide real-time endpoint protection via a Chromium Browser Extension.
- Deploy a Vercel-ready, serverless environment running on PostgreSQL.

## 4. Architecture
The architecture comprises several core modules:
- **ML Subsystem (`app/ml/`)**: Handles versioned dataset preprocessing, TF-IDF vectorization, feature extraction, and offline adversarial robustness testing.
- **Service Layer (`app/services/`)**: Orchestrates the Hybrid Risk Engine, Threat Intelligence polling, Website HTML analysis, and SQLite/Postgres persistence.
- **API/Routes (`app/api.py`, `app/routes.py`)**: Secured Flask endpoints utilizing JWT-style stateless authorization.
- **Extension (`extension/`)**: A Chromium Manifest V3 browser extension querying the backend natively.

## 5. URL Detection Pipeline
The URL engine parses string lexics (entropy, special characters, suspicious token extraction like "login", "verify") and extracts structural metadata (path depth, subdomains). It evaluates this numerical matrix against a tuned `RandomForestClassifier`.

## 6. Email Detection Pipeline
The Email engine normalizes unstructured `sender`, `subject`, and `body` fields, stripping HTML/scripts safely. It extracts TF-IDF n-grams (up to 25,000 features) and evaluates them against a highly accurate `LinearSVC` model, reinforced by regex heuristics (urgency/payment keywords, sender-mismatch).

## 7. Kaggle Dataset Usage
The Email pipeline was trained against a consolidated, large-scale dataset spanning 82,486 records (merged from Enron, SpamAssassin, Nigerian Fraud, Nazario, Ling, and CEAS_08 datasets). The URL model was tested on a small synthetic stub for pipeline verification. The raw `.csv` datasets are strictly utilized offline during model versioning and are excluded from production deployment footprints.

## 8. ML/NLP Models
- **URL**: `RandomForestClassifier` (150 estimators, max depth 10, min samples split 2)
- **Email**: `LinearSVC` + `TfidfVectorizer` (Word n-grams (1,2), english stopwords)

## 9. Model Evaluation (Actual Metrics)
**Email Model (`LinearSVC`)**
- Dataset Size: 82,486 
- Accuracy: 99.15%
- Precision: 99.00%
- Recall: 99.38%
- F1 Score: 99.19%
- False Positive Rate: 1.08%

**URL Model (`Random Forest`)**
- Accuracy / F1: 100% (Evaluated on a 24-sample pipeline validation stub)

## 10. Hybrid Risk Engine
Instead of blindly trusting the ML, the `HybridRiskEngine` weighs multiple discrete signals:
- Base ML Probability Output.
- Threat Intelligence overrides (If explicitly flagged Malicious, risk goes to 100).
- Local Blacklist / Whitelist conflicts (Whitelist drops risk to 0 safely).
- Web Parsing signals (e.g., Hidden passwords push risk +20).

## 11. Explainable AI
The ML engine extracts exactly which feature triggered the score. It outputs an array of `contributing_signals` (e.g., "Path is unusually long", "Contains hidden password field", "TF-IDF triggered on urgent terminology") providing human-readable explanations in the UI.

## 12. Threat Intelligence
Integrated `VirusTotal` and `URLHaus` API adapters using native Python `urllib`. They run synchronously with strict timeout ceilings (`THREAT_INTEL_TIMEOUT_SECONDS = 3`) to ensure third-party API latency or downtime does not degrade core inference speed.

## 13. Website Analysis
Implemented a safe, static HTML scanner (`app/services/website_analysis.py`). It analyzes target domains for:
- Hidden elements.
- Embedded external `<form>` login actions.
- Cross-origin `<iframe>` usage.
*Crucially, it utilizes strict IP screening to reject internal/AWS Loopback metadata addresses (SSRF protection) and caps downloads at 2MB to prevent memory exhaustion.*

## 14. REST API
Fully versioned API located under `/api/v1/`:
- `POST /api/v1/analyze/url`
- `POST /api/v1/analyze/email`
- `GET /api/v1/scan/<id>`
- `GET /api/v1/history`

## 15. Authentication and Roles
Role-Based Access Control (RBAC) supporting `Admin`, `Analyst`, and `User`. Passwords utilize `pbkdf2:sha256` hashing (`werkzeug.security`). API endpoints utilize static Bearer tokens generated via `secrets.token_urlsafe(32)`.

## 16. Database
The system dynamically scales:
- **Local:** `sqlite3` filesystem DB natively mapped to `sqlite3.Row`.
- **Production:** Dynamic transpilation to PostgreSQL (`psycopg2`) if `DATABASE_URL` is detected, converting schemas and variables dynamically.

## 17. Admin Dashboard
A glassmorphic UI providing:
- Real-time Chart.js metrics for Scan distributions.
- Paginated scan history logs.
- Role management.
- CSV / JSON export streaming.

## 18. Browser Extension
A standalone Chromium Manifest V3 extension operating in "Audit Mode". It silently grabs the active tab URL, securely hits the REST API via JWT, and dynamically renders the Threat Intel indicators without executing local ML inference or injecting DOM scripts.

## 19. Model Versioning
A dedicated CLI (`app/ml/manage_models.py`) enforcing reproducibility. 
- Automatically hashes datasets via SHA256.
- Prevents auto-promotions; requires explicit CLI validation (e.g., `python -m app.ml.manage_models promote --type url --version v1727...`).
- Stores historical metrics in `models/registry.json`.

## 20. Robustness Testing
`test_adversarial.py` challenges the trained models entirely offline using techniques like URL encoding (`%6C%6F%67%69%6E`), subdomain spoofing, and Email L33t Speak substitution (`acc0unt`, `r3stricted`) to guarantee the feature extraction holds its confidence scores.

## 21. Security
- **Path Traversal Protection:** ML pickling is strictly bounded; attempts to load `../../../malicious.pkl` are forcefully aborted.
- **Session Security:** Cookies configured with `HttpOnly`, `Secure`, and `SameSite=Lax`.
- **XSS & Headers:** `@app.after_request` globally injects `Content-Security-Policy`, `X-Frame-Options`, and `HSTS`.
- **DDoS Protection:** `MAX_CONTENT_LENGTH` explicitly capped to 10MB globally.
- **Verbose Error Masking:** 500-level tracebacks are swallowed from JSON responses and safely logged internally.

## 22. Local Installation
1. Clone the repository.
2. `python3 -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`

## 23. Dataset Location
Raw datasets should be placed in `data/raw/` (e.g., `Enron.csv`, `phishing_urls.csv`). They are only utilized during offline CLI training and must not be pushed to Vercel production.

## 24. Model Training Commands
```bash
# Train models
python -m app.ml.manage_models train --type url
python -m app.ml.manage_models train --type email

# Promote models to production
python -m app.ml.manage_models promote --type url --version <timestamp>
```

## 25. Running the Application
```bash
python run.py
```
Server boots at `http://127.0.0.1:5000`.

## 26. API Usage
```bash
curl -X POST http://127.0.0.1:5000/api/v1/analyze/url \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <TOKEN>" \
     -d '{"url": "http://evil.com"}'
```

## 27. Browser Extension Setup
1. Open Chrome/Edge extensions page (`chrome://extensions/`).
2. Enable "Developer mode".
3. Click "Load unpacked" and select the `extension/` directory.

## 28. Environment Variables
- `FLASK_ENV`: `development` | `production`
- `SECRET_KEY`: Security token for sessions.
- `DATABASE_URL`: (Optional) PostgreSQL connection URI.
- `THREAT_INTEL_VIRUSTOTAL_API_KEY`: (Optional) VT Key.
- `THREAT_INTEL_VIRUSTOTAL_ENABLED`: `True` | `False`

## 29. PostgreSQL/Vercel Deployment
The repository is Vercel-ready with zero configuration needed via `vercel.json` and `api/index.py`. 
- Vercel automatically deploys the serverless edge functions.
- Set `DATABASE_URL` in Vercel to a Neon or Supabase PostgreSQL instance.
- Ensure only `models/` (containing `.pkl`) is uploaded, skipping `data/raw/`.

## 30. Testing
The system utilizes Pytest.
- Executed `69 passed in 8.18s`.
- Covers URL detection, auth, APIs, HTML parsing SSRF limits, ML extraction, and adversarial robustness.
```bash
pytest tests/
```

## 31. Limitations
- **Pickle Deserialization**: The system relies on `joblib`. While path-bounded, a compromised OS allows arbitrary code execution via forged pickle payloads.
- **DNS Rebinding**: While strict IP checks occur, a highly advanced DNS-rebinding SSRF vector might still resolve dynamically during HTTP streaming.
- **Serverless Constraints**: Vercel limits Serverless Functions to 250MB. If ML models grow significantly larger, Docker/Container orchestration will be required.

## 32. Future Work
- Migration to ONNX formatting for ML artifacts to eliminate Pickle RCE vectors.
- Automated API blocking native to the Browser Extension.
- Migration to Redis for aggressive API Rate Limiting.
