# Signature-Based Intrusion Detection System with Python

This project aims to develop a Signature-Based Intrusion Detection System (IDS) tailored for Internet of Things (IoT) environments using Python. The IDS detects malicious activities in IoT networks by comparing network traffic patterns against known attack signatures.

## Overview

In IoT environments, ensuring the security of connected devices and networks is crucial to prevent unauthorized access and data breaches. Signature-based IDSs are effective in identifying known attacks by matching patterns in network traffic with pre-defined attack signatures.

## Features

- Signature-based detection of known attacks in IoT network traffic.
- Preprocessing of IoT network data for effective intrusion detection.
- Training and evaluation scripts to assess the performance of the IDS.
- Visualization of detection results and performance metrics.

## Installation

1. Clone this repository to your local machine:

```
git clone https://github.com/panostriantafyllidis/PySignatureIDS.git
```

2. Navigate to the project directory:

```
cd PySignatureIDS
```

3. Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

1. Prepare your IoT network traffic dataset in CSV format and place it in the `data/` directory.

2. Train the intrusion detection model using the provided dataset:

```
python train.py --dataset data/dataset.csv
```

3. Test the trained model on a separate test dataset:

```
python test.py --model trained_model.pth --test_dataset data/test_dataset.csv
```

4. Visualize the detection results and performance metrics:

```
python visualization.py --results results.csv
```

## License

This project is licensed under the [MIT License](LICENSE).

## Overview

# Background

Cloud computingis an emerging computing paradigm aimed at providing IT (information technology) services in a similar manner as the electricity grid. In Cloud computing, computing resources, data and software are managed by service providers on the Internet, and are provided to users and their devices in an on-demand manner. This new paradigm offers a number of advantages including on-demand self-service, ubiquitous and broad network access, resource pooling, rapid resource elasticity and usage-based pricing, etc [1]. While this paradigmis attractive to users in many aspects, it also introduces some serious concerns. One of these concerns is how to preserve data integrity in cloud computing.

# Description

In this project, you have an opportunity to research and design an intrusion detection system to detect security violations in a Cloud computing environment. The project tasks include:
· Investigate/identify methods appropriate for detecting security violations in foreign domains.
· Design a new method, or modify an existing one, to facilitate such intrusion detections.
· Implement and evaluate the method.

# Deliverables

1.      Report your literature survey.
2.      The design and implementation of a method for intrusion detections.
3.      Insights to the design based upon the evaluation of your implementation.

# References

1. Sana Ullah Jan, et al, "Toward a Lightweight Intrusion Detection System for the Internet of Things", IEEE Access, Year: 2019, Volume: 7.

2. P. Mell and T. Grance, "The NIST Definition of Cloud Computing," Referenced on 26, Oct 2010, Online at http://csrc.nist.gov/groups/SNS/cloud-computing/.

3. NIST SP 800-94, Guide to Intrusion Detection and Prevention Systems, http://csrc.nist.gov/publications/nistpubs/800-94/SP800-94.pdf.
