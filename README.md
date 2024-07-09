# Hybrid Intrusion Detection System (HIDS) Project

<div style="overflow-x: auto;">
  <pre>
    ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗██████╗     ███╗   ██╗██╗██████╗ ███████╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗    ████╗  ██║██║██╔══██╗██╔════╝
    ███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║    ██╔██╗ ██║██║██║  ██║███████╗
    ██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║    ██║╚██╗██║██║██║  ██║╚════██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝    ██║ ╚████║██║██████╔╝███████║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝     ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝                                                              
  </pre>
</div>

(made using https://www.patorjk.com/software/taag/)

## Overview

This project aims to develop a Hybrid Intrusion Detection System (HIDS) that combines the strengths of Signature-based IDS (SIDS) and Anomaly-based IDS (AIDS) to provide robust security for cloud computing environments. The system is designed to detect and respond to both known and novel threats with high accuracy and minimal false positives.

## Features

- **Signature-based IDS (SIDS)**: Utilizes the C5.0 decision tree algorithm for fast and efficient detection of known threats.
- **Anomaly-based IDS (AIDS)**: Employs a single-class Support Vector Machine (SVM) to identify unknown attacks through anomaly detection.
- **Hybrid Approach**: Integrates SIDS and AIDS for comprehensive threat detection and mitigation.
- **Resource Optimization**: Focuses on optimizing computational and memory requirements for efficient operation in resource-constrained environments.
- **High Accuracy**: Aims to minimize false positives and false negatives while maintaining high detection accuracy.

## Versioning notes

### example

- 1.2.3
  > 1 expresses version of the Hybrid connection/ensemble of the SIDS+AIDS modules
  > 2 expresses version of the AIDS module
  > 3 expresses version of the SIDS module

Thus : "this is the 1 iteration of the Hybrid System, using the 2nd AIDS and 3rd SIDS module versions"

This format helped me process multiple approaches during Net-HIDS development , while incorporating different code and features from various sources.

## Setup Instructions

1. Clone the repository:

```sh
git clone https://github.com/panostriantafyllidis/MSc-Hybrid-IDS.git
cd MSc-Hybrid-IDS
```

2. Create a virtual environment (Optional):

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
python -m src.sids.main.py
```

## Independent Module Usage

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

- Use the Packet Sender tool, linked here -> https://packetsender.com/download

- To view my attempt in making a (non-working) packet creation/sending script, look at the "..src/attacker" folder

(For Receiver)

- Start scanning...

```bash
python -m src.sids.sids_main
```

- Next step : Send some packets from a different device , using the ruleset in "src/sids/rules" as guidelines for known/unknown packet-creation variation limits
