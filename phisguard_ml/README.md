# PhishGuard //\\//\\//\\//\\
> ML-Powered Phishing URL Detection System with Cyber Threat Intelligence Integration

**Prateek Dixit  ·  BS-MS Economics, Year 3  ·  IIT Roorkee**

Even Semester Projects — Coding Club IIT Guwahati 2026

---

## Project Structure

```
phisguard/
├── phisguard_ml/                 ← ML model + API
│   ├── feature_extractor.py      ← 33 URL features
│   ├── dataset_loader.py         ← Dataset preprocessing
│   ├── train.py                  ← Model training + evaluation
│   ├── api.py                    ← FastAPI backend
│   ├── data/
│   │   └── phishing_urls.csv     ← Training dataset (from Kaggle)
│   ├── processed/
│   │   └── features_urldata.csv  ← Auto-generated feature matrix
│   └── models/
│       ├── xgb_model.joblib      ← Trained XGBoost model
│       ├── scaler.joblib         ← StandardScaler
│       ├── tfidf.joblib          ← TF-IDF vectorizer
│       └── meta.json             ← Model metadata + metrics
│
├── phishguard_extension/         ← Chrome extension
│   ├── manifest.json
│   ├── popup.html / popup.js
│   ├── background.js
│   ├── content.js
│   ├── generate_icons.py
│   └── icons/
│
└── phishguard_dashboard/
    └── dashboard.html            ← React analyst dashboard
```

---

#### Demo Video Link :- https://drive.google.com/file/d/1E6p0UDsFbrgSaslSe41CNRwGISipzAYh/view?usp=sharing

## Results

| Metric | Value |
|---|---|
| Accuracy | **96.47%** ✓ (target: ≥95%) |
| ROC-AUC | **99.44%** |
| Phishing Precision | 97% |
| Phishing Recall | 95% |
| Training URLs | 100,000 |
| Features | 3,033 (33 handcrafted + 3,000 TF-IDF) |

---

## Setup & Run

### 1. Install dependencies

```bash
pip install pandas scikit-learn xgboost scipy fastapi uvicorn[standard] joblib tqdm matplotlib seaborn Pillow
```

### 2. Get the dataset

Download from Kaggle:
`https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls`

Rename to `phishing_urls.csv` and place in `phisguard_ml/data/`

### 3. Train the model

```bash
cd phisguard_ml
python dataset_loader.py --source urldata
python train.py --source urldata
```

Expected output:
```
Accuracy : 0.9647  ✓ TARGET MET
ROC-AUC  : 0.9944
```

### 4. Start the API

```bash
cd phisguard_ml
python -m uvicorn api:app --reload --port 8000
```

API is live at `http://localhost:8000`
Interactive docs at `http://localhost:8000/docs`

### 5. Load the Chrome Extension

```bash
cd phishguard_extension
python generate_icons.py     # generates icons/
```

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `phishguard_extension/` folder

### 6. Open the Dashboard

Just open `phishguard_dashboard/dashboard.html` in your browser. No build step needed.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/stats` | Model accuracy + scan counts |
| `POST` | `/scan` | Scan a single URL |
| `POST` | `/scan/batch` | Scan up to 100 URLs |
| `GET` | `/history` | Recent scan history |

**Example:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-secure-login.com/verify"}'
```

```json
{
  "scan_id": "04e12e54",
  "label": "phishing",
  "confidence": 0.9998,
  "risk_level": "HIGH",
  "scanned_at": "2026-05-18T06:35:58Z"
}
```

---

## How It Works

### Two-stage classification

```
URL → Trusted domain whitelist? → YES → SAFE (no model call)
                                ↓ NO
                     Feature extraction (33 features)
                     + TF-IDF char n-grams (3,000 features)
                                ↓
                     XGBoost (500 trees) → P(phishing)
                                ↓
                     VirusTotal CTI lookup
                                ↓
                     Final verdict + confidence score
```

### Feature groups

| Group | Features |
|---|---|
| Length | url_length, domain_length, path_length, query_length |
| Counts | dots, hyphens, digits, subdomains, path depth, params |
| Boolean | IP address, HTTPS, port, shortener, phish keywords, suspicious TLD |
| Entropy | Shannon entropy of hostname and domain core |
| Typosquatting | Levenshtein distance to top 24 brand names |
| Whitelist | Trusted domain flag |
| TF-IDF | 3,000 character bigram–4gram features from raw URL |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Machine Learning | Python, XGBoost, scikit-learn, scipy, Pandas |
| Backend | FastAPI, Uvicorn, Pydantic v2 |
| Threat Intel | VirusTotal API v3 |
| Extension | JavaScript, Chrome Manifest V3 |
| Dashboard | React 18, Recharts |

---

## Author

Prateek Dixit 
BS-MS Economics
IIT Roorkee