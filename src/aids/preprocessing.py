import os
import pickle
import signal
import time
from concurrent.futures import ThreadPoolExecutor

import joblib
import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether
from sklearn.svm import SVC, OneClassSVM

from src.packet_sniffer.rule_creator import handle_attack_detection
from src.sids.sids_main import max_sids_workers

# ============== Global variables to store the dataset and models ==============

df = pd.read_csv("datasets/UNSW-NB15/test_df.csv")
# logging.info("[*] Dataset loaded successfully.")

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
    "Djit",
    "Dintpkt",
    "ct_state_ttl",
    "ct_srv_dst",
    "ct_src_ltm",
    "byte_ratio",
    "load_ratio",
    "jit_ratio",
    "tcp_setup_ratio",
]


# ========================End of Global Variables==========================


# # Ensuring the Dataset is loaded ONCE , at the start of the system's execution
# # to avoid redundant loading delay per packet
# def load_dataset():
#     """
#     Load the dataset if it's not already loaded.
#     """
#     global df
#     if df is None:
#         logging.info("[*] Loading dataset for the first time...")
#         df = pd.read_csv("datasets/UNSW-NB15/sample_dataset.csv")
#         logging.info("[*] Dataset loaded successfully.")


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

    # Adjust OCSVM prediction: Map 1 -> 0 (Normal), -1 -> 1 (Attack)
    ocsvm_adjusted = 0 if ocsvm_prediction == 1 else 1

    # Majority voting
    predictions = [svc_prediction, ocsvm_adjusted, ensemble_prediction]
    final_prediction = 1 if predictions.count(1) > predictions.count(0) else 0
    # Percentage of agreement: 74.92% using test_df with over 100k entries

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


# ==============================================================================
# Choice 1: User Input Testing
# ==============================================================================
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
        "Dload": "Destination bits per second (float)",
        "Dpkts": "Destination to source packet count (integer)",
        "smeansz": "Mean of the flow packet size transmitted by the source (integer)",
        "dmeansz": "Mean of the flow packet size transmitted by the destination (integer)",
        "Sjit": "Source jitter (mSec) (float)",
        "Djit": "Destination jitter (mSec) (float)",
        "Dintpkt": "Destination interpacket arrival time (mSec) (float)",
        "ct_state_ttl": "Number of connections with the same state according to specific TTL range (integer)",
        "ct_srv_dst": "Number of connections that contain the same service and destination address in 100 connections (integer)",
        "ct_src_ltm": "Number of connections of the same source address in 100 connections (integer)",
        "byte_ratio": "Ratio of source to destination bytes (calculated feature)",
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


# ==============================================================================
# Choice 2: Random Testing
# ==============================================================================
def random_testing(used_indices=None):
    """
    Randomly selects a row from the dataset and performs the model prediction.
    Ensures that the same row is not selected more than once.
    """
    if used_indices is None:
        used_indices = set()

    # Randomly pick Label 1 or 0
    label = np.random.choice([0, 1])
    df_filtered = df[df["Label"] == label][selected_features]

    # Find unused indices
    available_indices = df_filtered.index.difference(used_indices)

    if available_indices.empty:
        logging.info("No more unique rows available for the selected label.")
        return None, None  # or handle as needed

    # Random row with the selected label
    selected_row_index = np.random.choice(available_indices)
    selected_row = df_filtered.loc[selected_row_index]

    # Prepare the input data for the model
    randinput = prepare_input(selected_row.to_dict())

    final_prediction, predictions = predict_with_voting(randinput)

    # Output the results
    model_names = ["SVC", "One-Class SVM", "Ensemble"]
    prediction_results = {name: pred for name, pred in zip(model_names, predictions)}

    logging.info(
        f"Random row with Label = {label}, individual predictions: {prediction_results}, final decision: {'Attack' if final_prediction == 1 else 'Normal'}"
    )

    return final_prediction, predictions, selected_row_index


# ==============================================================================
# Choice 3: Extracting Features from Raw Packet Data
# ==============================================================================
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
    # Set to keep track of used indices for each label
    used_attack_indices = set()
    used_normal_indices = set()

    # Convert raw packets to DataFrame
    packet_features = []
    for packet in packets:
        start_time = time.time()

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

            # Filter the DataFrame based on the label
            df_filtered = df[df["Label"] == label][selected_features]
            df_filtered = df_filtered.drop(columns=["Label"], errors="ignore")

            # Choose the set of used indices based on label
            used_indices = used_attack_indices if label == 1 else used_normal_indices

            # Find available indices
            available_indices = df_filtered.index.difference(used_indices)

            if available_indices.empty:
                logging.info(
                    f"No more unique rows available for label {label}. Resetting used indices."
                )
                used_indices.clear()  # Reset used indices to start over
                available_indices = df_filtered.index

            # Select a random row from available indices
            selected_row_index = np.random.choice(available_indices)
            selected_row = df_filtered.loc[[selected_row_index]]

            # Add the selected index to the set of used indices
            used_indices.add(selected_row_index)

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
                handle_attack_detection(packet)
            else:
                logging.info(f"False alarm for packet from {packet[IP].src}")
        else:
            logging.info(
                f"[*] Unknown Packet's name is not 'Attack' or 'Normal'. Skipping packet."
            )
        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_time  # Calculate elapsed time
        logging.info(f"[*] Time taken to process packet: {elapsed_time:.4f} seconds")


# ==============================================================================
# Choice 4: Testing Live Packet Capture with AIDS
# ==============================================================================

packet_queue = Queue()
stop_event = threading.Event()


def live_traffic():
    """
    Process live traffic by capturing packets directly using Scapy's sniff.
    Packets are queued and processed by a separate thread.
    """

    def packet_capture():
        """
        Function to capture packets and put them into the queue.
        This function will periodically check if it should stop based on the stop_event.
        """
        logging.info("[*] Starting packet capture...")

        def enqueue_packet(pkt):
            if IP in pkt and UDP in pkt and pkt[IP].src == "192.168.2.12":
                packet_queue.put(pkt)
                logging.info(f"[*] Packet from {pkt[IP].src} captured and queued.")

        # Loop to continuously capture packets, checking the stop_event regularly
        while not stop_event.is_set():
            sniff(prn=enqueue_packet, filter="ip", store=0, timeout=1)

    def process_single_packet(packet, used_attack_indices2, used_normal_indices2):
        """
        Function to process a single packet.
        """
        logging.info(
            f"[*] Processing live traffic packet from {packet[IP].src} to {packet[IP].dst}."
        )

        # Extract the packet name using the extraction logic from Choice 3
        name = extract_name_from_packet(packet)
        logging.info(f"[*] Packet name extracted: {name}")

        if name == "Attack":
            label = 1
        elif name == "Normal":
            label = 0
        else:
            logging.info("[*] Unknown packet name; skipping packet.")
            return

        df_filtered = df[df["Label"] == label][selected_features]
        df_filtered = df_filtered.drop(columns=["Label"], errors="ignore")

        # Choose the set of used indices based on label
        used_indices = used_attack_indices2 if label == 1 else used_normal_indices2

        # Find available indices
        available_indices = df_filtered.index.difference(used_indices)

        if available_indices.empty:
            logging.info("No more unique rows available for the selected label.")
            return

        # Random row with the selected label
        selected_row_index = np.random.choice(available_indices)
        selected_row = df_filtered.loc[selected_row_index]

        randinput = prepare_input(selected_row.to_dict())

        final_prediction, predictions = predict_with_voting(randinput)

        model_names = ["SVC", "One-Class SVM", "Ensemble"]
        prediction_results = {
            name: pred for name, pred in zip(model_names, predictions)
        }

        logging.info(
            f"Live traffic predictions: {prediction_results}, final decision: {'Attack' if final_prediction == 1 else 'Normal'}"
        )

    def process_queue_packets():
        """
        Function to process packets from the queue using a thread pool.
        """
        used_attack_indices2 = set()
        used_normal_indices2 = set()
        max_aids_workers = 3  # Limit to 4 threads
        with ThreadPoolExecutor(max_workers=max_aids_workers) as executor:
            while not stop_event.is_set():
                try:
                    packet = packet_queue.get(
                        timeout=0.6
                    )  # Use timeout to check stop_event
                    if packet is None:
                        break

                    # Submit packet processing to the executor
                    executor.submit(
                        process_single_packet,
                        packet,
                        used_attack_indices2,
                        used_normal_indices2,
                    )
                    packet_queue.task_done()
                except queue.Empty:
                    continue  # Timeout occurred, loop to check stop_event

    def signal_handler(sig, frame):
        """
        Handle keyboard interrupt and stop packet capture and processing gracefully.
        """
        logging.info("[*] Live traffic IDS stopping...")
        stop_event.set()  # Signal to stop threads
        packet_queue.put(None)  # Stop the packet processing thread
        sys.exit(0)

    # Set up signal handling for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Start the packet capture in a separate thread
    capture_thread = threading.Thread(target=packet_capture)
    capture_thread.daemon = True
    capture_thread.start()

    # Start the packet processing in the main thread
    process_thread = threading.Thread(target=process_queue_packets)
    process_thread.daemon = True
    process_thread.start()

    try:
        # Keep the main thread running to handle signals
        while True:
            capture_thread.join(1)
            process_thread.join(1)
            if not capture_thread.is_alive() or not process_thread.is_alive():
                break
    except KeyboardInterrupt:
        signal_handler(None, None)
