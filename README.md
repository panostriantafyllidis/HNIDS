# Hybrid Intrusion Detection System (HIDS) Project

## Overview
This project aims to develop a Hybrid Intrusion Detection System (HIDS) that combines the strengths of Signature-based IDS (SIDS) and Anomaly-based IDS (AIDS) to provide robust security for cloud computing environments. The system is designed to detect and respond to both known and novel threats with high accuracy and minimal false positives.

## Features
- **Signature-based IDS (SIDS)**: Utilizes the C5.0 decision tree algorithm for fast and efficient detection of known threats.
- **Anomaly-based IDS (AIDS)**: Employs a single-class Support Vector Machine (SVM) to identify unknown attacks through anomaly detection.
- **Hybrid Approach**: Integrates SIDS and AIDS for comprehensive threat detection and mitigation.
- **Resource Optimization**: Focuses on optimizing computational and memory requirements for efficient operation in resource-constrained environments.
- **High Accuracy**: Aims to minimize false positives and false negatives while maintaining high detection accuracy.

## Installation
To get started with the project, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/panostriantafyllidis/MSc-Hybrid-IDS.git
cd MSc-Hybrid-IDS
pip install -r requirements.txt
```

## Usage
Run the main script to start the Hybrid IDS system:

```bash
python src/main.py
```

## Data
- **Raw Data**: Store raw datasets in `data/raw/`.
- **Processed Data**: Store processed datasets in `data/processed/`.

## Documentation
- **Project Proposal**: `docs/project_proposal.pdf`
- **Literature Review**: `docs/literature_review.pdf`
- **User Manual**: `docs/user_manual.md`
- **API Documentation**: `docs/API_documentation.md`

## Testing
Run the test cases to ensure everything is working correctly:

```bash
pytest tests/
```
