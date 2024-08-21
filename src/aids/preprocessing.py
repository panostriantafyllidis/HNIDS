# TODO
# Code for giving the testing df, packet data from the dataset, rundom row
# row of Label = 1 if packet payload contains "Attack"
# row of Label = 0 if packet payload contains "Normal"

import os
import pickle

import joblib
import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether
from sklearn.svm import SVC, OneClassSVM

# ============== Global variables to store the dataset and models ==============
df = None
# Load the models globally to ensure they are loaded only once
svc_model = joblib.load("src/aids/models/svc_svm_model.joblib")
ocsvm_model = joblib.load("src/aids/models/one_class_svm_model.joblib")
ensemble_model = joblib.load("src/aids/models/classifier_ensemble_model.joblib")
# These are the feature that that data needs to be gathered.
# There are two approaches to this.
# For testing and research purposes, the applied method is to get data for those features, out of the dataset and act as if its an actual captured packet's.
# The second method is to actually code the data extraction for these respective features, add them in a dataframe and test them
# The first method is used here for testing purposes. The second method is too complex for the current scope of the project.
# Additionally the features here are hardcoded as "selected" since there is no current implementation of updating the dataset with new entries, thus the importance and relevance stays the same.
selected_features = [
    "dsport",
    "state",
    "dur",
    "sbytes",
    "sttl",
    "dttl",
    "Dload",
    "Dpkts",
    "smeansz",
    "dmeansz",
    "Sjit",
    "Dintpkt",
    "ct_state_ttl",
    "ct_srv_dst",
    "ct_src_ltm",
    "byte_ratio",
    "pkt_ratio",
    "load_ratio",
    "jit_ratio",
    "tcp_setup_ratio",
]

# ========================End of Global Variables==========================


# Ensuring the Dataset is loaded ONCE , at the start of the system's execution
# to avoid redundant loading delay per packet
def load_dataset():
    """
    Load the dataset if it's not already loaded.
    """
    global df
    if df is None:
        logging.info("[*] Loading dataset for the first time...")
        df = pd.read_csv("datasets/UNSW-NB15/sample_dataset.csv")
        logging.info("[*] Dataset loaded successfully.")


def predict_with_voting(input_data):
    """
    Perform predictions using SVC, One-Class SVM, and Ensemble models.
    Return the majority voting result and individual predictions.
    """
    input_data = np.array(input_data).reshape(1, -1)

    # Generate predictions
    svc_prediction = svc_model.predict(input_data)[0]
    ocsvm_prediction = ocsvm_model.predict(input_data)[0]
    ensemble_prediction = ensemble_model.predict(input_data)[0]

    # Majority voting
    predictions = [svc_prediction, ocsvm_prediction, ensemble_prediction]
    final_prediction = 1 if predictions.count(1) > predictions.count(0) else 0

    return final_prediction, predictions


def prepare_input(user_input):
    """
    Prepares the input data for the model by converting the given input into the expected format.
    """

    state_mapping = {"INT": 0, "FIN": 1, "CON": 2, "REQ": 3, "RST": 4, "CLO": 5}

    input_data = []
    for feature in selected_features:
        if feature in user_input:
            if feature == "state":
                value = state_mapping.get(user_input[feature], 0)
            else:
                try:
                    # value = (
                    #     float(user_input[feature])
                    #     if "." in user_input[feature]
                    #     else int(user_input[feature])
                    # )
                    if (
                        isinstance(user_input[feature], str)
                        and "." in user_input[feature]
                    ):
                        value = float(user_input[feature])
                    else:
                        value = (
                            float(user_input[feature])
                            if isinstance(user_input[feature], (int, float))
                            else int(user_input[feature])
                        )
                except ValueError:
                    value = user_input[feature]
            input_data.append(value)

    # Ensure all features are present
    if len(input_data) < len(selected_features):
        input_data += [0] * (len(selected_features) - len(input_data))

    return input_data


# ============== Choice 1 ==============
def handle_user_input(user_input):
    """
    Handles the user input and performs the model prediction.
    """
    input_data = prepare_input(user_input)

    # Use the voting function
    final_prediction, predictions = predict_with_voting(input_data)

    # Output the results
    model_names = ["SVC", "One-Class SVM", "Ensemble"]
    prediction_results = {name: pred for name, pred in zip(model_names, predictions)}

    logging.info(
        f"User input predictions: {prediction_results}, final decision: {'Attack' if final_prediction == 1 else 'Normal'}"
    )

    return final_prediction


def get_user_input():
    """
    Prompts the user to enter values for the selected features.
    """
    feature_descriptions = {
        "dsport": "Destination port number (integer)",
        "state": "Indicates the state and its dependent protocol (nominal, e.g., ACC, CLO, etc.)",
        "dur": "Record total duration (float)",
        "sbytes": "Source to destination transaction bytes (integer)",
        "sttl": "Source to destination time to live value (integer)",
        "dttl": "Destination to source time to live value (integer)",
        "Dload": "Destination load (float)",
        "Dpkts": "Destination to source packet count (integer)",
        "smeansz": "Mean of the flow packet size transmitted by the source (integer)",
        "dmeansz": "Mean of the flow packet size transmitted by the destination (integer)",
        "Sjit": "Source jitter (mSec) (float)",
        "Dintpkt": "Destination interpacket arrival time (mSec) (float)",
        "ct_state_ttl": "Number of connections with the same state according to specific TTL range (integer)",
        "ct_srv_dst": "Number of connections that contain the same service and destination address in 100 connections (integer)",
        "ct_src_ltm": "Number of connections of the same source address in 100 connections (integer)",
        "byte_ratio": "Ratio of source to destination bytes (calculated feature)",
        "pkt_ratio": "Ratio of source to destination packets (calculated feature)",
        "load_ratio": "Ratio of source to destination load (calculated feature)",
        "jit_ratio": "Ratio of source to destination jitter (calculated feature)",
        "tcp_setup_ratio": "Ratio of TCP setup times (calculated feature)",
    }

    user_input = {}
    for feature in selected_features:
        if feature in feature_descriptions:
            while True:
                value = input(
                    f"Enter value for {feature} ({feature_descriptions[feature]}): "
                )
                if value:
                    user_input[feature] = value
                    break
                else:
                    logging.info(
                        f"Value for {feature} cannot be empty. Please enter a valid value."
                    )
    return user_input


# ============== Choice 2 ==============
def random_testing():
    """
    Randomly selects a row from the dataset and performs the model prediction.
    """
    # Randomly pick Label 1 or 0
    label = np.random.choice([0, 1])
    df_filtered = df[df["Label"] == label][selected_features]
    selected_row = df_filtered.sample(n=1)  # Random row with the selected label

    # Prepare the input data for the model
    randinput = prepare_input(selected_row.iloc[0].to_dict())

    final_prediction, predictions = predict_with_voting(randinput)

    # Output the results
    model_names = ["SVC", "One-Class SVM", "Ensemble"]
    prediction_results = {name: pred for name, pred in zip(model_names, predictions)}

    logging.info(
        f"Random row with Label = {label}, individual predictions: {prediction_results}, final decision: {'Attack' if final_prediction == 1 else 'Normal'}"
    )


# ============== Choice 3 =================
def extract_features(packet):
    """
    Extracts the necessary features from the raw packet data.
    """
    # Extract features from the raw packet data
    # This function should convert the raw packet into the format expected by the model
    # Placeholder for feature extraction logic based on raw packet data
    features = {
        "srcip": packet[IP].src,  # Source IP address
        "sport": (
            packet[UDP].sport if UDP in packet else packet[TCP].sport
        ),  # Source port number
        "dstip": packet[IP].dst,  # Destination IP address
        "dsport": (
            packet[UDP].dport if UDP in packet else packet[TCP].dport
        ),  # Destination port number
    }
    return features


def extract_name_from_packet(packet):
    """
    Extracts the packet name from the raw packet data (payload).
    """
    payload = None
    # Attempt to extract the payload from the Raw layer
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode("utf-8")
        except UnicodeDecodeError:
            payload = packet[Raw].load.decode("latin1")
    else:
        logging.info("[*] No Raw layer found in packet.")

    if payload:
        logging.info(f"[*] Extracted payload: {payload}")

        # Search for 'Attack' or 'Normal' directly in the payload
        if "Attack" in payload:
            name = "Attack"
            logging.info(f"[*] Identified packet as: {name}")
        elif "Normal" in payload:
            name = "Normal"
            logging.info(f"[*] Identified packet as: {name}")
        else:
            logging.info("[*] Neither 'Attack' nor 'Normal' found in payload.")
            name = None
    else:
        logging.info("[*] No payload found in packet.")
        name = None

    return name


# scaler_path = "src/aids/models/scaler.joblib"
# scaler = joblib.load(scaler_path)


def process_packets(packets):
    """
    Processes the packets received by the SIDS.
    """
    # Ensure the dataset is loaded (only happens once)
    load_dataset()

    # Convert raw packets to DataFrame
    packet_features = []
    for packet in packets:

        logging.info(
            f"[*] Processing packet from {packet[IP].src} to {packet[IP].dst}."
        )

        packet_data = extract_features(packet)  # Function to extract necessary features
        packet_features.append(packet_data)

        # Extract the packet name
        name = extract_name_from_packet(packet)
        logging.info(f"[*] Packet name extracted: {name}")

        # Only process if the name is 'Attack' or 'Normal'
        if name == "Attack" or name == "Normal":
            label = 1 if name == "Attack" else 0
            logging.info(f"[*] Packet labeled as: {name} ({label}).")

            # Filter the DataFrame and drop the 'Label' column
            df_filtered = df[df["Label"] == label][selected_features]
            df_filtered = df_filtered.drop(columns=["Label"], errors="ignore")
            selected_row = df_filtered.sample(
                n=1
            )  # Random row with the corresponding label
            logging.info(f"[*] Selected random row from dataset for label {label}.")

            # Validate that all selected features are present in the selected row
            missing_features = [
                feature
                for feature in selected_features
                if feature not in selected_row.columns
            ]
            if missing_features:
                logging.warning(
                    f"[*] Missing features in selected row: {missing_features}"
                )
                continue  # Skip this packet if required features are missing

            input_data = prepare_input(selected_row.iloc[0].to_dict())
            # input_data_scaled = scaler.transform([input_data])
            logging.info(f"[*] Input data prepared for model prediction.")

            # Use the voting function
            final_prediction, predictions = predict_with_voting(input_data)

            model_names = ["SVC", "One-Class SVM", "Ensemble"]
            prediction_results = {
                name: pred for name, pred in zip(model_names, predictions)
            }

            logging.info(f"Packet predictions: {prediction_results}, final decision:")

            if final_prediction == 1:
                logging.info(f"ALERT: Attack detected for packet from {packet[IP].src}")
            else:
                logging.info(f"False alarm for packet from {packet[IP].src}")
        else:
            logging.info(
                f"[*] Unknown Packet's name is not 'Attack' or 'Normal'. Skipping packet."
            )
