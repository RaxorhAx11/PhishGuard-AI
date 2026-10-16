"""
Dataset acquisition and verification script for PhishGuard AI.
Fetches real benchmark datasets (UCI SMS Spam Collection & Enron Spam Corpus)
and formats them into data/dataset.csv.
"""

import os
import sys
import pandas as pd

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
OUTPUT_PATH = os.path.join(DATA_DIR, "dataset.csv")

SMS_DATASET_URL = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
EMAIL_DATASET_URL = "https://raw.githubusercontent.com/thehananbhat/spam-vs-ham/refs/heads/main/spam_ham_dataset.csv"


def download_and_prepare_dataset(force_redownload: bool = False) -> str:
    """
    Downloads and prepares real labeled datasets for training.
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(OUTPUT_PATH) and not force_redownload:
        print(f"[+] Dataset already exists at {OUTPUT_PATH}")
        df = pd.read_csv(OUTPUT_PATH)
        print(f"    - Total instances: {len(df)}")
        print(f"    - Legitimate (0): {(df['label'] == 0).sum()}")
        print(f"    - Phishing/Spam (1): {(df['label'] == 1).sum()}")
        return OUTPUT_PATH

    print("[*] Downloading real benchmark SMS and Email datasets...")

    # 1. Download UCI SMS Spam Collection
    print(f"[*] Fetching SMS collection from {SMS_DATASET_URL}...")
    df_sms = pd.read_csv(SMS_DATASET_URL, sep="\t", names=["label_str", "text"])
    df_sms["label"] = df_sms["label_str"].map({"ham": 0, "spam": 1}).astype(int)
    df_sms["source"] = "sms"
    df_sms = df_sms[["text", "label", "source"]].dropna()

    # 2. Download Enron Spam Corpus subset
    print(f"[*] Fetching Email corpus from {EMAIL_DATASET_URL}...")
    df_email = pd.read_csv(EMAIL_DATASET_URL)
    df_email = df_email[["text", "label_num"]].copy()
    df_email.rename(columns={"label_num": "label"}, inplace=True)
    df_email["label"] = df_email["label"].astype(int)
    df_email["source"] = "email"
    df_email = df_email[["text", "label", "source"]].dropna()

    # Combine datasets
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from src.preprocessing import clean_text

    df_combined = pd.concat([df_sms, df_email], axis=0, ignore_index=True)
    df_combined["text"] = df_combined["text"].astype(str).str.strip()
    df_combined = df_combined[df_combined["text"].str.len() > 10]
    clean_keys = df_combined["text"].apply(clean_text)
    df_combined = df_combined.loc[~clean_keys.duplicated()].reset_index(drop=True)

    df_combined.to_csv(OUTPUT_PATH, index=False)
    print(f"[+] Successfully saved {len(df_combined)} samples to {OUTPUT_PATH}")
    print(f"    - Legitimate: {(df_combined['label'] == 0).sum()}")
    print(f"    - Phishing/Spam: {(df_combined['label'] == 1).sum()}")
    print(f"    - SMS samples: {(df_combined['source'] == 'sms').sum()}")
    print(f"    - Email samples: {(df_combined['source'] == 'email').sum()}")

    return OUTPUT_PATH


if __name__ == "__main__":
    force = "--force" in sys.argv
    download_and_prepare_dataset(force_redownload=force)
