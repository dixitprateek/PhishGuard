# """
# PhishGuard — Dataset Loader
# Loads phishing + legitimate URLs from standard sources and
# builds a balanced, feature-extracted DataFrame ready for training.

# Supported sources
# -----------------
# 1. ISCX URL 2016 (Kaggle CSV)          — recommended starting point
# 2. PhishTank CSV export                — phishing URLs
# 3. Tranco top-1M CSV                   — legitimate URLs

# Install deps first:
#     pip install pandas scikit-learn tqdm requests
# """

# import os
# import re
# import json
# import urllib.request
# from pathlib import Path

# import pandas as pd
# from tqdm import tqdm

# from feature_extractor import extract_features, URLFeatures

# # ── Paths — adjust to where you store the raw CSVs ───────────────────────────
# DATA_DIR   = Path("data")
# OUTPUT_DIR = Path("processed")
# OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ISCX_PATH      = DATA_DIR / "iscx.csv"
# PHISHTANK_PATH = DATA_DIR / "phishtank.csv"
# TRANCO_PATH    = DATA_DIR / "tranco.csv"


# # ── 1. ISCX URL 2016 (easiest to use — already labelled) ─────────────────────
# def load_iscx(path: Path = ISCX_PATH, n: int = 50_000) -> pd.DataFrame:
#     """
#     ISCX CSV has columns:  url, type
#     type values:  benign / defacement / phishing / malware
#     We keep only 'benign' (label=0) and 'phishing' (label=1).
#     """
#     df = pd.read_csv(path, usecols=["url", "type"])
#     df = df[df["type"].isin(["benign", "phishing"])].copy()
#     df["label"] = (df["type"] == "phishing").astype(int)
#     df = df.drop(columns=["type"]).dropna().drop_duplicates(subset="url")

#     # Balance classes
#     pos = df[df["label"] == 1].sample(min(n // 2, len(df[df["label"] == 1])), random_state=42)
#     neg = df[df["label"] == 0].sample(min(n // 2, len(df[df["label"] == 0])), random_state=42)
#     return pd.concat([pos, neg]).reset_index(drop=True)


# # ── 2. PhishTank CSV ──────────────────────────────────────────────────────────
# def load_phishtank(path: Path = PHISHTANK_PATH, n: int = 25_000) -> pd.DataFrame:
#     """
#     PhishTank export columns include: url, verified, valid
#     We use only verified=yes, valid=yes rows.
#     Download: https://www.phishtank.com/developer_info.php  (free account)
#     """
#     df = pd.read_csv(path)
#     # Column names vary slightly across exports — normalise
#     df.columns = [c.strip().lower() for c in df.columns]
#     url_col = next(c for c in df.columns if "url" in c)
#     df = df.rename(columns={url_col: "url"})
#     if "verified" in df.columns:
#         df = df[df["verified"] == "yes"]
#     df = df[["url"]].dropna().drop_duplicates()
#     df["label"] = 1
#     return df.sample(min(n, len(df)), random_state=42).reset_index(drop=True)


# # ── 3. Tranco (legitimate URLs) ───────────────────────────────────────────────
# def load_tranco(path: Path = TRANCO_PATH, n: int = 25_000) -> pd.DataFrame:
#     """
#     Tranco CSV: rank, domain  (no header)
#     We prepend https:// to make them full URLs.
#     Download: https://tranco-list.eu/
#     """
#     df = pd.read_csv(path, names=["rank", "domain"])
#     df["url"] = "https://" + df["domain"].str.strip()
#     df["label"] = 0
#     return df.sample(min(n, len(df)), random_state=42)[["url", "label"]].reset_index(drop=True)


# # ── Feature extraction helper ─────────────────────────────────────────────────
# def build_feature_matrix(df: pd.DataFrame, chunk_size: int = 5000) -> pd.DataFrame:
#     """
#     Runs extract_features() on every URL and returns a DataFrame
#     where each column is one feature + the 'label' column at the end.
#     """
#     records = []
#     for url in tqdm(df["url"], desc="Extracting features"):
#         try:
#             feats = extract_features(str(url))
#             records.append(feats.to_vector())
#         except Exception:
#             records.append([0] * len(URLFeatures.feature_names()))

#     feat_df = pd.DataFrame(records, columns=URLFeatures.feature_names())
#     feat_df["label"] = df["label"].values
#     feat_df["url"]   = df["url"].values   # kept for WHOIS enrichment
#     return feat_df


# # ── Main ──────────────────────────────────────────────────────────────────────
# def prepare_dataset(source: str = "iscx") -> pd.DataFrame:
#     """
#     source: 'iscx' | 'combined'
#       - 'iscx'     → use only ISCX (simplest, good for first run)
#       - 'combined' → merge PhishTank + Tranco (more diverse)
#     """
#     print(f"[dataset] Loading source='{source}' …")

#     if source == "iscx":
#         raw = load_iscx()
#     elif source == "combined":
#         phish = load_phishtank()
#         legit = load_tranco()
#         raw = pd.concat([phish, legit]).sample(frac=1, random_state=42).reset_index(drop=True)
#     else:
#         raise ValueError(f"Unknown source: {source}")

#     print(f"[dataset] Raw URLs: {len(raw)} | Phishing: {raw['label'].sum()} | Legit: {(raw['label']==0).sum()}")

#     feat_df = build_feature_matrix(raw)
#     out_path = OUTPUT_DIR / f"features_{source}.csv"
#     feat_df.to_csv(out_path, index=False)
#     print(f"[dataset] Saved → {out_path}")
#     return feat_df


# if __name__ == "__main__":
#     df = prepare_dataset(source="iscx")   # Change to 'combined' when you have both CSVs
#     print(df.head())
#     print(df["label"].value_counts())

"""
PhishGuard — Domain Age Enrichment
Adds a `domain_age_days` feature to the existing features CSV.

Why domain age?
  - Phishing domains are almost always < 30 days old (registered just before attack)
  - Legitimate domains are typically years old
  - This single feature can push accuracy from ~91% → ~96%+

Install:
    pip install python-whois tqdm

Usage:
    python add_domain_age.py                     # enriches processed/features_iscx.csv
    python add_domain_age.py --source combined
    python add_domain_age.py --limit 5000        # quick test on first 5000 rows
"""

"""
PhishGuard — Dataset Loader
Loads phishing + legitimate URLs and builds a feature CSV for training.

Sources
-------
urldata  → Kaggle "Phishing and Legitimate URLs" (RECOMMENDED — gets 96%+)
           https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls
           Download CSV → rename to phishing_urls.csv → put in data/

iscx     → ISCX URL 2016 (older, harder — lexical features cap at ~91%)
           https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

combined → PhishTank + Tranco (requires two separate CSVs)

Install:
    pip install pandas scikit-learn tqdm
"""
"""
PhishGuard — Dataset Loader
Loads phishing + legitimate URLs and builds a feature CSV for training.

Sources
-------
urldata  → Kaggle "Phishing and Legitimate URLs" (RECOMMENDED — gets 96%+)
           https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls
           Download CSV → rename to phishing_urls.csv → put in data/

iscx     → ISCX URL 2016 (older, harder — lexical features cap at ~91%)
           https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

combined → PhishTank + Tranco (requires two separate CSVs)

Install:
    pip install pandas scikit-learn tqdm
"""

"""
PhishGuard — Dataset Loader
Loads phishing + legitimate URLs and builds a feature CSV for training.

Sources
-------
urldata  → Kaggle "Phishing and Legitimate URLs" (RECOMMENDED — gets 96%+)
           https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls
           Download CSV → rename to phishing_urls.csv → put in data/

iscx     → ISCX URL 2016 (older, harder — lexical features cap at ~91%)
           https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

combined → PhishTank + Tranco (requires two separate CSVs)

Install:
    pip install pandas scikit-learn tqdm
"""

from pathlib import Path
import pandas as pd
from tqdm import tqdm
from feature_extractor import extract_features, URLFeatures

DATA_DIR   = Path("data")
OUTPUT_DIR = Path("processed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_urldata(n: int = 100_000) -> pd.DataFrame:
    """
    Kaggle 'Phishing and Legitimate URLs' dataset.
    Columns vary by version — we auto-detect url + label columns.
    """
    path = DATA_DIR / "phishing_urls.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found.\n"
            "Download from: https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls\n"
            "Rename the CSV to 'phishing_urls.csv' and put it in the data/ folder."
        )
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]

    # Auto-detect URL column
    url_col = next((c for c in df.columns if "url" in c), None)
    if url_col is None:
        raise ValueError(f"No URL column found. Columns are: {list(df.columns)}")

    # Auto-detect label column
    label_col = next(
        (c for c in df.columns if c in ("label", "type", "status", "class", "target")),
        None
    )
    if label_col is None:
        raise ValueError(f"No label column found. Columns are: {list(df.columns)}")

    df = df.rename(columns={url_col: "url", label_col: "label"})

    # In the harisudhan411 dataset: status=0=phishing, status=1=legit
    # We invert so our convention is always 1=phishing, 0=legit
    print("[dataset] Inverting labels: status 0→phishing(1), 1→legit(0)")
    df["label"] = 1 - df["label"].astype(int)

    # Add scheme if missing (some datasets store bare domains)
    df["url"] = df["url"].apply(
        lambda u: u if str(u).startswith("http") else "http://" + str(u)
    )

    df = df[["url", "label"]].dropna().drop_duplicates(subset="url")

    # Balance classes
    pos = df[df["label"] == 1]
    neg = df[df["label"] == 0]
    k   = min(n // 2, len(pos), len(neg))
    return (pd.concat([pos.sample(k, random_state=42),
                       neg.sample(k, random_state=42)])
              .sample(frac=1, random_state=42)
              .reset_index(drop=True))


def load_iscx(n: int = 50_000) -> pd.DataFrame:
    path = DATA_DIR / "ISCX_URL_2016.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found.\n"
            "Download from: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset"
        )
    df = pd.read_csv(path, usecols=["url", "type"])
    df = df[df["type"].isin(["benign", "phishing"])].copy()
    df["label"] = (df["type"] == "phishing").astype(int)
    df = df[["url", "label"]].dropna().drop_duplicates(subset="url")
    pos = df[df["label"] == 1].sample(min(n//2, len(df[df["label"]==1])), random_state=42)
    neg = df[df["label"] == 0].sample(min(n//2, len(df[df["label"]==0])), random_state=42)
    return pd.concat([pos, neg]).sample(frac=1, random_state=42).reset_index(drop=True)


# ── Feature extraction ────────────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    records = []
    for url in tqdm(df["url"], desc="Extracting features"):
        try:
            records.append(extract_features(str(url)).to_vector())
        except Exception:
            records.append([0] * len(URLFeatures.feature_names()))

    feat_df = pd.DataFrame(records, columns=URLFeatures.feature_names())
    feat_df["label"] = df["label"].values
    feat_df["url"]   = df["url"].values
    return feat_df


# ── Main ──────────────────────────────────────────────────────────────────────

def prepare_dataset(source: str = "urldata") -> pd.DataFrame:
    print(f"[dataset] Loading source='{source}' …")

    if source == "urldata":
        raw = load_urldata()
    elif source == "iscx":
        raw = load_iscx()
    else:
        raise ValueError(f"Unknown source '{source}'. Choose: urldata, iscx")

    print(f"[dataset] {len(raw)} URLs | Phishing: {raw['label'].sum()} | Legit: {(raw['label']==0).sum()}")

    feat_df  = build_feature_matrix(raw)
    out_path = OUTPUT_DIR / f"features_{source}.csv"
    feat_df.to_csv(out_path, index=False)
    print(f"[dataset] Saved → {out_path}")
    return feat_df


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--source", default="urldata", choices=["urldata", "iscx"])
    args = p.parse_args()

    df = prepare_dataset(source=args.source)
    print(df.head())
    print(df["label"].value_counts())