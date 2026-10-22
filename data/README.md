# TrustLens AI Dataset Documentation

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
