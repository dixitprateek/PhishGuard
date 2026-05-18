# """
# PhishGuard — Model Training v2
# Key improvements over v1:
#   1. Whitelist pre-filter: trusted domains are ALWAYS classified legit,
#      bypassing the ML model → eliminates false positives like google.com
#   2. 33 features (was 24) — added brand Levenshtein, TLD flags, domain entropy
#   3. Tuned XGBoost hyperparameters for ≥95% accuracy
#   4. predict_url() now checks whitelist first

# Run:
#     python train.py
# """

# import argparse
# import joblib
# import json
# from pathlib import Path

# import numpy as np
# import pandas as pd
# import matplotlib
# matplotlib.use("Agg")           # headless — no display needed
# import matplotlib.pyplot as plt
# import seaborn as sns

# from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
# from sklearn.preprocessing import StandardScaler
# from sklearn.metrics import (
#     classification_report, confusion_matrix,
#     roc_auc_score, accuracy_score,
# )
# from xgboost import XGBClassifier

# PROCESSED_DIR = Path("processed")
# MODEL_DIR     = Path("models")
# MODEL_DIR.mkdir(parents=True, exist_ok=True)


# # ── Helpers ───────────────────────────────────────────────────────────────────

# def load_features(source: str = "iscx"):
#     path = PROCESSED_DIR / f"features_{source}.csv"
#     if not path.exists():
#         raise FileNotFoundError(
#             f"{path} not found.\nRun first:  python dataset_loader.py"
#         )
#     df = pd.read_csv(path).dropna()
#     feature_cols = [c for c in df.columns if c not in ("label","url")]
#     X = df[feature_cols].values.astype(np.float32)
#     y = df["label"].values.astype(int)
#     return X, y, feature_cols


# def train(X_train, y_train) -> XGBClassifier:
#     model = XGBClassifier(
#         # ── Core params ───────────────────────────────────────────────────────
#         n_estimators=500,
#         max_depth=7,
#         learning_rate=0.05,          # lower LR + more trees → better generalisation
#         min_child_weight=3,
#         # ── Regularisation ────────────────────────────────────────────────────
#         subsample=0.8,
#         colsample_bytree=0.8,
#         colsample_bylevel=0.8,
#         gamma=0.1,
#         reg_alpha=0.1,               # L1
#         reg_lambda=1.5,              # L2
#         # ── Misc ──────────────────────────────────────────────────────────────
#         eval_metric="logloss",
#         random_state=42,
#         n_jobs=-1,
#     )
#     model.fit(X_train, y_train, verbose=False)
#     return model


# def evaluate(model, X_test, y_test, feature_names):
#     y_pred  = model.predict(X_test)
#     y_proba = model.predict_proba(X_test)[:, 1]

#     acc     = accuracy_score(y_test, y_pred)
#     roc_auc = roc_auc_score(y_test, y_proba)

#     print("\n" + "═"*55)
#     print(f"  Accuracy : {acc:.4f}  "
#           f"({'✓ TARGET MET' if acc >= 0.95 else '✗ below 0.95 — see tips below'})")
#     print(f"  ROC-AUC  : {roc_auc:.4f}")
#     print("─"*55)
#     print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))
#     print("═"*55 + "\n")

#     fig, axes = plt.subplots(1, 2, figsize=(13, 5))

#     cm = confusion_matrix(y_test, y_pred)
#     sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[0],
#                 xticklabels=["Legit", "Phishing"],
#                 yticklabels=["Legit", "Phishing"])
#     axes[0].set_title("Confusion Matrix")
#     axes[0].set_ylabel("True Label"); axes[0].set_xlabel("Predicted")

#     top_n     = 15
#     importances = model.feature_importances_
#     indices   = np.argsort(importances)[-top_n:]
#     axes[1].barh(range(top_n), importances[indices], color="#2563EB")
#     axes[1].set_yticks(range(top_n))
#     axes[1].set_yticklabels([feature_names[i] for i in indices], fontsize=8)
#     axes[1].set_title(f"Top {top_n} Feature Importances")
#     axes[1].set_xlabel("Score")

#     plt.tight_layout()
#     out = MODEL_DIR / "evaluation.png"
#     plt.savefig(out, dpi=150)
#     print(f"[eval] Plot saved → {out}")

#     return {"accuracy": round(acc, 6), "roc_auc": round(roc_auc, 6)}


# def cross_validate(X, y):
#     model = XGBClassifier(
#         n_estimators=300, max_depth=7, learning_rate=0.05,
#         subsample=0.8, colsample_bytree=0.8, gamma=0.1,
#         reg_alpha=0.1, reg_lambda=1.5, eval_metric="logloss",
#         random_state=42, n_jobs=-1,
#     )
#     cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
#     scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
#     print(f"[CV] 5-fold accuracy: {scores.mean():.4f} ± {scores.std():.4f}"
#           f"  ({'✓' if scores.mean() >= 0.95 else '✗'})")
#     return scores


# def save_model(model, scaler, feature_names, metrics):
#     joblib.dump(model,  MODEL_DIR / "xgb_model.joblib")
#     joblib.dump(scaler, MODEL_DIR / "scaler.joblib")
#     meta = {"feature_names": feature_names,
#             "n_features": len(feature_names), "metrics": metrics}
#     with open(MODEL_DIR / "meta.json", "w") as f:
#         json.dump(meta, f, indent=2)
#     print(f"[save] model  → {MODEL_DIR}/xgb_model.joblib")
#     print(f"[save] scaler → {MODEL_DIR}/scaler.joblib")
#     print(f"[save] meta   → {MODEL_DIR}/meta.json")


# # ── Inference (plug this into FastAPI later) ──────────────────────────────────

# def predict_url(url: str, model=None, scaler=None) -> dict:
#     """
#     Classifies a URL. Checks the trusted-domain whitelist first,
#     so google.com / github.com etc. are NEVER flagged as phishing.
#     """
#     import re, sys
#     sys.path.insert(0, ".")
#     from feature_extractor import extract_features, TRUSTED_DOMAINS

#     # ── Step 1: whitelist fast-path ───────────────────────────────────────────
#     try:
#         from urllib.parse import urlparse
#         hostname = urlparse(url if "://" in url else "http://"+url).hostname or ""
#         bare     = re.sub(r"^www\.", "", hostname.lower())
#         if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
#             return {
#                 "url": url, "label": "legit",
#                 "confidence": 0.0, "risk_level": "SAFE",
#                 "reason": "Trusted domain whitelist",
#             }
#     except Exception:
#         pass

#     # ── Step 2: ML model ─────────────────────────────────────────────────────
#     if model is None:
#         model  = joblib.load(MODEL_DIR / "xgb_model.joblib")
#         scaler = joblib.load(MODEL_DIR / "scaler.joblib")

#     feats  = extract_features(url).to_vector()
#     X      = scaler.transform([feats])
#     proba  = float(model.predict_proba(X)[0][1])
#     label  = "phishing" if proba >= 0.5 else "legit"
#     risk   = "HIGH" if proba > 0.80 else "MEDIUM" if proba > 0.50 else "LOW"

#     return {"url": url, "label": label,
#             "confidence": round(proba, 4), "risk_level": risk}


# # ── Main ──────────────────────────────────────────────────────────────────────

# def main(source="iscx", run_cv=True):
#     print(f"[train] Loading features (source={source}) …")
#     X, y, feature_names = load_features(source)
#     print(f"[train] {len(X)} samples | {X.shape[1]} features")
#     print(f"[train] Phishing: {y.sum()} | Legit: {(y==0).sum()}")

#     if run_cv:
#         cross_validate(X, y)

#     X_tr, X_te, y_tr, y_te = train_test_split(
#         X, y, test_size=0.2, stratify=y, random_state=42)

#     scaler = StandardScaler()
#     X_tr   = scaler.fit_transform(X_tr)
#     X_te   = scaler.transform(X_te)

#     print("[train] Fitting XGBoost (500 trees, this takes ~30 s) …")
#     model   = train(X_tr, y_tr)
#     metrics = evaluate(model, X_te, y_te, feature_names)
#     save_model(model, scaler, feature_names, metrics)

#     # Demo predictions
#     demo = [
#         "http://192.168.1.1/login/verify?user=admin",
#         "https://paypal-secure-login.com/update",
#         "https://paypol.com/confirm/account",
#         "https://www.google.com/search?q=openai",
#         "https://github.com/openai/whisper",
#         "https://www.amazon.com/dp/B09X",
#     ]
#     print("\n[demo] Sample predictions:")
#     for u in demo:
#         r = predict_url(u, model, scaler)
#         tag = r.get("reason", f"{r['confidence']:.0%}")
#         print(f"  {r['label'].upper():8s}  {r['risk_level']:6s}  {tag:30s}  {u}")

#     # Tips if accuracy is below target
#     if metrics["accuracy"] < 0.95:
#         print("\n[tips] Still below 95%? Try these:")
#         print("  1. Combine datasets: set source='combined' in dataset_loader.py")
#         print("  2. Add WHOIS domain age feature (requires python-whois)")
#         print("  3. Increase n_estimators to 800 in train()")
#         print("  4. Use GridSearchCV to tune max_depth and learning_rate")


# if __name__ == "__main__":
#     p = argparse.ArgumentParser()
#     p.add_argument("--source", default="iscx", choices=["iscx", "combined","urldata"])
#     p.add_argument("--no-cv", action="store_true")
#     args = p.parse_args()
#     main(source=args.source, run_cv=not args.no_cv)



"""
PhishGuard — Model Training v3
Combines handcrafted features (33) + TF-IDF character n-grams on raw URL.
This hybrid approach breaks the 93% ceiling on noisy datasets.

Why n-grams help:
  - Learns suspicious character sequences automatically: 'login', 'verify',
    '-secure-', '/wp-content/', '.php?id=' etc.
  - Catches obfuscated domains: 'paypa1', 'g00gle', 'arnazon'
  - Complements handcrafted features without replacing them

Run:
    python train.py --source urldata
"""

import argparse
import joblib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score,
)
from xgboost import XGBClassifier

PROCESSED_DIR = Path("processed")
MODEL_DIR     = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Number of TF-IDF n-gram features to keep (top by frequency)
TFIDF_MAX_FEATURES = 3000


# ── 1. Load ───────────────────────────────────────────────────────────────────

def load_features(source: str = "urldata"):
    path = PROCESSED_DIR / f"features_{source}.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found.\nRun:  python dataset_loader.py --source {source}"
        )
    df = pd.read_csv(path).dropna()
    feature_cols = [c for c in df.columns if c not in ("label", "url")]
    X    = df[feature_cols].values.astype(np.float32)
    y    = df["label"].values.astype(int)
    urls = df["url"].values if "url" in df.columns else np.array([""] * len(df))
    return X, y, urls, feature_cols


# ── 2. Build combined feature matrix ─────────────────────────────────────────

def build_tfidf(urls_train, urls_test):
    """
    Character-level n-grams (2–4 chars) on raw URL strings.
    Captures patterns like: '-secure-', '.php?', '//login', 'wp-content'
    without needing to hand-engineer them.
    """
    vec = TfidfVectorizer(
        analyzer="char_wb",       # character n-grams with word boundaries
        ngram_range=(2, 4),       # bigrams through 4-grams
        max_features=TFIDF_MAX_FEATURES,
        sublinear_tf=True,        # log(tf+1) — dampens very frequent n-grams
        min_df=5,                 # ignore n-grams appearing in < 5 URLs
    )
    X_tr = vec.fit_transform(urls_train)
    X_te = vec.transform(urls_test)
    return X_tr, X_te, vec


def combine(X_hand, X_tfidf):
    """Stack handcrafted (dense) + TF-IDF (sparse) into one sparse matrix."""
    return hstack([csr_matrix(X_hand), X_tfidf])


# ── 3. Train ──────────────────────────────────────────────────────────────────

def train(X_train, y_train) -> XGBClassifier:
    model = XGBClassifier(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.05,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.6,    # lower because feature space is now much wider
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.5,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",      # fast histogram method — handles sparse well
    )
    model.fit(X_train, y_train, verbose=False)
    return model


# ── 4. Evaluate ───────────────────────────────────────────────────────────────

def evaluate(model, X_test, y_test):
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    acc     = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    print("\n" + "═"*55)
    print(f"  Accuracy : {acc:.4f}  "
          f"({'✓ TARGET MET' if acc >= 0.95 else '✗ below 0.95'})")
    print(f"  ROC-AUC  : {roc_auc:.4f}")
    print("─"*55)
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))
    print("═"*55 + "\n")

    # Confusion matrix plot
    fig, ax = plt.subplots(figsize=(5, 4))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                xticklabels=["Legit", "Phishing"],
                yticklabels=["Legit", "Phishing"])
    ax.set_title(f"Confusion Matrix  (acc={acc:.3f})")
    ax.set_ylabel("True"); ax.set_xlabel("Predicted")
    plt.tight_layout()
    plt.savefig(MODEL_DIR / "evaluation.png", dpi=150)
    print(f"[eval] Plot saved → {MODEL_DIR}/evaluation.png")

    return {"accuracy": round(acc, 6), "roc_auc": round(roc_auc, 6)}


# ── 5. Save ───────────────────────────────────────────────────────────────────

def save_model(model, scaler, tfidf_vec, feature_names, metrics):
    joblib.dump(model,     MODEL_DIR / "xgb_model.joblib")
    joblib.dump(scaler,    MODEL_DIR / "scaler.joblib")
    joblib.dump(tfidf_vec, MODEL_DIR / "tfidf.joblib")
    meta = {
        "feature_names": feature_names,
        "n_hand_features": len(feature_names),
        "n_tfidf_features": TFIDF_MAX_FEATURES,
        "metrics": metrics,
    }
    with open(MODEL_DIR / "meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[save] model  → {MODEL_DIR}/xgb_model.joblib")
    print(f"[save] scaler → {MODEL_DIR}/scaler.joblib")
    print(f"[save] tfidf  → {MODEL_DIR}/tfidf.joblib")
    print(f"[save] meta   → {MODEL_DIR}/meta.json")


# ── 6. Inference ──────────────────────────────────────────────────────────────

def predict_url(url: str, model=None, scaler=None, tfidf_vec=None) -> dict:
    """
    Classifies a single URL. Checks whitelist first.
    Used directly by the FastAPI backend.
    """
    import re
    import sys
    sys.path.insert(0, ".")
    from feature_extractor import extract_features, TRUSTED_DOMAINS

    # Whitelist fast-path
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url if "://" in url else "http://" + url).hostname or ""
        bare     = re.sub(r"^www\.", "", hostname.lower())
        if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
            return {"url": url, "label": "legit", "confidence": 0.0,
                    "risk_level": "SAFE", "reason": "Trusted domain whitelist"}
    except Exception:
        pass

    # Load saved artefacts if not passed in
    if model is None:
        model     = joblib.load(MODEL_DIR / "xgb_model.joblib")
        scaler    = joblib.load(MODEL_DIR / "scaler.joblib")
        tfidf_vec = joblib.load(MODEL_DIR / "tfidf.joblib")

    # Build feature vector
    hand_feats = extract_features(url).to_vector()
    X_hand     = scaler.transform([hand_feats])
    X_tfidf    = tfidf_vec.transform([url])
    X_combined = hstack([csr_matrix(X_hand), X_tfidf])

    proba = float(model.predict_proba(X_combined)[0][1])
    label = "phishing" if proba >= 0.5 else "legit"
    risk  = "HIGH" if proba > 0.80 else "MEDIUM" if proba > 0.50 else "LOW"

    return {"url": url, "label": label,
            "confidence": round(proba, 4), "risk_level": risk}


# ── Main ──────────────────────────────────────────────────────────────────────

def main(source="urldata", run_cv=False):
    print(f"[train] Loading features (source={source}) …")
    X, y, urls, feature_names = load_features(source)
    print(f"[train] {len(X)} samples | {X.shape[1]} handcrafted features")
    print(f"[train] Phishing: {y.sum()} | Legit: {(y==0).sum()}")

    # Split first so TF-IDF is fit only on training URLs (no leakage)
    idx = np.arange(len(X))
    tr_idx, te_idx = train_test_split(idx, test_size=0.2, stratify=y, random_state=42)

    X_tr_hand, X_te_hand = X[tr_idx], X[te_idx]
    y_tr,      y_te      = y[tr_idx], y[te_idx]
    urls_tr,   urls_te   = urls[tr_idx], urls[te_idx]

    # Scale handcrafted features
    scaler    = StandardScaler()
    X_tr_hand = scaler.fit_transform(X_tr_hand)
    X_te_hand = scaler.transform(X_te_hand)

    # Build TF-IDF on training URLs only
    print(f"[train] Building TF-IDF ({TFIDF_MAX_FEATURES} char n-gram features) …")
    X_tr_tfidf, X_te_tfidf, tfidf_vec = build_tfidf(urls_tr, urls_te)

    # Combine
    X_tr_combined = combine(X_tr_hand, X_tr_tfidf)
    X_te_combined = combine(X_te_hand, X_te_tfidf)
    print(f"[train] Combined feature dim: {X_tr_combined.shape[1]}")

    # Optional CV (on handcrafted only — fast)
    if run_cv:
        from sklearn.model_selection import cross_val_score
        base = XGBClassifier(n_estimators=200, max_depth=7, learning_rate=0.05,
                             eval_metric="logloss", random_state=42, n_jobs=-1,
                             tree_method="hist")
        scores = cross_val_score(base, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        print(f"[CV] handcrafted-only 5-fold: {scores.mean():.4f} ± {scores.std():.4f}")

    print("[train] Fitting XGBoost on combined features …")
    model   = train(X_tr_combined, y_tr)
    metrics = evaluate(model, X_te_combined, y_te)
    save_model(model, scaler, tfidf_vec, feature_names, metrics)

    # Demo predictions
    demo = [
        "http://192.168.1.1/login/verify?user=admin",
        "https://paypal-secure-login.com/update",
        "https://paypol.com/confirm/account",
        "https://www.google.com/search?q=openai",
        "https://github.com/openai/whisper",
        "https://www.amazon.com/dp/B09X",    
    ]
    print("\n[demo] Sample predictions:")
    for u in demo:
        r = predict_url(u, model, scaler, tfidf_vec)
        tag = r.get("reason", f"{r['confidence']:.0%}")
        print(f"  {r['label'].upper():8s}  {r['risk_level']:6s}  {tag:30s}  {u}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--source", default="urldata", choices=["iscx", "combined", "urldata"])
    p.add_argument("--cv", action="store_true", help="Run cross-validation (slow)")
    args = p.parse_args()
    main(source=args.source, run_cv=args.cv)