# A Hybrid Network Intrusion Detection System (NIDS) Project

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

- **Signature-based IDS (SIDS)**: Defines a Rule object , reads and parses rules, reads and dissects captured traffic to find a match. Forwards unmatched packets to the AIDS.
- **Anomaly-based IDS (AIDS)**: Trains and utilised 12 Machine Learning models to classify captured packets. Creates new rules based on newly classified attacks, using the Rule Object definition.
- **Hybrid Approach**: Integrates SIDS and AIDS for comprehensive threat detection and mitigation.
- **High Accuracy**: 95+% Accuracy during train-validate conditions. 85+% Accuracy on testing environment conditions.

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
python -m src.main
```

6. For SIDS, when promped, type 'default' for default ruleset path located in src/sids/rules , otherwise path a desired path like :

```
(no brackets)
c:\Users\takis\OneDrive - The University of Manchester\MSc-Hybrid-IDS\src\sids\rules\exampleRules.txt
```

## Independent Module Usage

SIDS and AIDS are executed independently in different ways.

The main method is to use the Hybrid UI (main.py)

If for some reason you would like to test/work them as a standalone package then use:

```
python -m src.<path-to-file-name>
```

### AIDS

```bash
python -m src.aids.train_aids
```

```bash
python -m src.aids.aids_main
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
