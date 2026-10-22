"""
Dataset acquisition script for TrustLens AI.
Downloads the SMS Spam Collection dataset from the UCI Machine Learning Repository / reliable mirror.
Saves the cleaned dataset into data/raw/sms_spam_collection.csv with full provenance documentation.
"""

import os
import sys
import zipfile
import io
import requests
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw")
OUTPUT_PATH = os.path.join(DATA_DIR, "sms_spam_collection.csv")
README_PATH = os.path.join(os.path.dirname(DATA_DIR), "README.md")

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
GITHUB_MIRROR_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"

README_CONTENT = """# TrustLens AI Dataset Documentation

## Dataset: SMS Spam Collection
- **Source**: UCI Machine Learning Repository (Dataset ID: 228)
- **Creators**: Tiago A. Almeida (Federal University of Sao Carlos) and Jose Maria Gomez Hidalgo (R&D Department of Optenet)
- **License**: Creative Commons Attribution 4.0 International (CC BY 4.0) / Open Access
- **Primary Domain**: Mobile fraud, phishing, and SMS deception detection

## Schema
- `label`: Binary classification target (`ham` = legitimate message, `spam` = fraudulent/unsolicited/phishing)
- `message`: Raw text of the communication
- `label_num`: Numeric encoding (0 = ham, 1 = spam)

## Class Distribution & Characteristics
- Total samples: ~5,572 rows
- Imbalance: ~86.6% legitimate (ham), ~13.4% fraudulent/unwanted (spam)
- Characteristics: Short-form communications, SMS shorthand, urgency cues, masked URLs, prize claims, service fees.

## Preprocessing & Data Leakage Prevention
1. Duplicates are audited and handled.
2. Train-test split is stratified (80% train, 20% test) before any vectorization or feature learning.
3. Preprocessing preserves critical security tokens (URLs, phone numbers, currency symbols, urgent punctuation).
4. No synthetic labels or test samples are leaked into the training pipeline.
"""

def fetch_dataset() -> pd.DataFrame:
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 1. Try UCI direct ZIP download
    print(f"Attempting download from UCI: {UCI_ZIP_URL}")
    try:
        resp = requests.get(UCI_ZIP_URL, timeout=15)
        if resp.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                # File is usually named 'SMSSpamCollection'
                for name in z.namelist():
                    if "SMSSpamCollection" in name:
                        with z.open(name) as f:
                            df = pd.read_csv(f, sep='\t', names=['label', 'message'], quoting=3, encoding='utf-8', on_bad_lines='skip')
                            print(f"Successfully loaded {len(df)} samples from UCI ZIP.")
                            return df
    except Exception as e:
        print(f"UCI download failed ({e}), trying GitHub mirror...")

    # 2. Try GitHub mirror
    print(f"Attempting download from GitHub mirror: {GITHUB_MIRROR_URL}")
    try:
        resp = requests.get(GITHUB_MIRROR_URL, timeout=15)
        if resp.status_code == 200:
            df = pd.read_csv(io.StringIO(resp.text), sep='\t', names=['label', 'message'], quoting=3, encoding='utf-8')
            print(f"Successfully loaded {len(df)} samples from GitHub mirror.")
            return df
    except Exception as e:
        print(f"GitHub mirror failed ({e}).")

    raise RuntimeError("Could not download SMS Spam Collection dataset from any upstream source.")

def main():
    df = fetch_dataset()
    # Normalize labels
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df = df[df['label'].isin(['ham', 'spam'])].dropna(subset=['message'])
    df['label_num'] = (df['label'] == 'spam').astype(int)
    
    # Save CSV
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved dataset to {OUTPUT_PATH}")
    print(f"Total rows: {len(df)}")
    print(df['label'].value_counts())
    
    # Save README
    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(README_CONTENT)
    print(f"Saved dataset documentation to {README_PATH}")

if __name__ == "__main__":
    main()
