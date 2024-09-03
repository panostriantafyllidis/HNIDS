# aids_main.py

import logging
import os
import pickle

import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether
from sklearn.svm import SVC, OneClassSVM

from src.aids.preprocessing import (
    get_user_input,
    handle_user_input,
    live_traffic,
    process_packets,
    random_testing,
)
from src.aids.train_aids import train_aids


def main(funnel_packets, packets, log_path):

    # ===========================================================================
    # LOG SETUP
    if log_path:
        # Use the hybrid log path provided by main.py
        log_file_path = log_path
    else:
        log_directory = "logs/aids"
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)

        # Generate a unique log file name with the current date and time
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file_name = f"anomaly_run_{current_time}.log"
        log_file_path = os.path.join(log_directory, log_file_name)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file_path, mode="w"),  # Log to file
                logging.StreamHandler(),  # Log to console
            ],
        )
    # ===========================================================================
    if funnel_packets and packets is not None:
        logging.info("[*] Anomaly Subsystem processing unknown packet...")
        process_packets(packets)
    else:
        logging.info("*" * 40)
        logging.info("AIDS Initiated:")
        logging.info("*" * 40)
        while True:
            logging.info("Select an option:")
            logging.info("1. Testing - Manual User Input")
            logging.info("2. Testing - Random Testing")
            logging.info("3. Train AIDS")
            logging.info("4. Test Live Traffic")
            logging.info("5. Exit")

            choice = input("Enter choice: ")

            if choice == "1":
                user_input = get_user_input()
                handle_user_input(user_input)
            elif choice == "2":
                random_testing()
            elif choice == "3":
                train_aids()
            elif choice == "4":
                live_traffic()
            elif choice == "5":
                logging.info("Exiting the program.")
                sys.exit(0)
            else:
                logging.info("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main(funnel_packets=False, packets=None, log_path=None)
