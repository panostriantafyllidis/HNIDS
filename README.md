# Hybrid Intrusion Detection System (HIDS) Project

## Overview

This project aims to develop a Hybrid Intrusion Detection System (HIDS) that combines the strengths of Signature-based IDS (SIDS) and Anomaly-based IDS (AIDS) to provide robust security for cloud computing environments. The system is designed to detect and respond to both known and novel threats with high accuracy and minimal false positives.

## Features

- **Signature-based IDS (SIDS)**: Utilizes the C5.0 decision tree algorithm for fast and efficient detection of known threats.
- **Anomaly-based IDS (AIDS)**: Employs a single-class Support Vector Machine (SVM) to identify unknown attacks through anomaly detection.
- **Hybrid Approach**: Integrates SIDS and AIDS for comprehensive threat detection and mitigation.
- **Resource Optimization**: Focuses on optimizing computational and memory requirements for efficient operation in resource-constrained environments.
- **High Accuracy**: Aims to minimize false positives and false negatives while maintaining high detection accuracy.

## Setup Instructions

1. Clone the repository:

```sh
git clone https://github.com/panostriantafyllidis/MSc-Hybrid-IDS.git
cd MSc-Hybrid-IDS
```

2. Create a virtual environment:

```sh
python -m venv venv
```

3. Activate the virtual environment:

- **Windows**:

```sh
.\venv\Scripts\activate
```

- **macOS/Linux**:

```sh
source venv/bin/activate
```

4. Install the required packages:

```sh
pip install -r requirements.txt
```

5. Run the project:

```sh
python -m src.sids.sids_main
```

## Usage

SIDS and AIDS are executed separately in different ways.

### AIDS

```bash
python -m src.aids.train_aids
```

```bash
python -m src.aids.test_aids
```

### SIDS

(For Attacker)

```bash
python sender.py
```

or

```bash
python -m src.sids.sender.py
```

(For Receiver)

```bash
python sids_main.py
```

or

```bash
python -m src.sids.sids_main.py
```
