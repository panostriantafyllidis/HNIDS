import concurrent.futures
import datetime
import logging
import os
import queue
import signal
import sys
import threading

from scapy.all import datetime

from src.aids import aids_main
from src.packet_sniffer.packet_sniffer import Sniffer
from src.packet_sniffer.packet_sniffer_manager import set_sniffer
from src.sids.rule_file_reader import read

RED = "\033[91m"
BLUE = "\033[34m"
GREEN = "\033[32m"
ENDC = "\033[0m"

packet_queue = queue.Queue()

DEFAULT_RULESET_PATH = "rules/rule_set.txt"


def retrieve_unknown_packets(sniffer):
    """Retrieve raw unknown packets from the sniffer."""
    with sniffer.lock:
        packets = list(sniffer.unknownPackets)
        sniffer.unknownPackets.clear()
    return packets


# def process_unknown_packets(log_path):
#     """Process unknown packets as they arrive."""
#     while True:
#         packet = packet_queue.get()
#         if packet is None:
#             break
#         else:
#             logging.info("[*] Unknown packet forwarded to Anomaly subsystem...")
#             aids_main.main(funnel_packets=True, packets=[packet], log_path=log_path)
#             packet_queue.task_done()

max_sids_workers = 3


def process_unknown_packets(log_path):
    """Process unknown packets as they arrive using a thread pool."""
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_sids_workers
    ) as executor:
        while True:
            packet = packet_queue.get()
            if packet is None:
                break
            else:
                logging.info("[*] Unknown packet forwarded to Anomaly subsystem...")
                # Submit a task to the thread pool executor
                executor.submit(
                    aids_main.main,
                    funnel_packets=True,
                    packets=[packet],
                    log_path=log_path,
                )
                packet_queue.task_done()


def main(handle_unknown_packets, funnel_packets, mode, log_path):
    """Read the rule file and start listening."""

    # ====================================================================================================
    # LOG SETUP
    if log_path:
        # Use the hybrid log path provided by main.py
        log_file_path = log_path
    else:
        log_directory = "logs/sids"
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)

        # Generate a unique log file name with the current date and time
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file_name = f"signature_run_{current_time}.log"
        log_file_path = os.path.join(log_directory, log_file_name)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file_path, mode="w"),  # Log to file
                logging.StreamHandler(),  # Log to console
            ],
        )
    # ====================================================================================================

    while True:
        logging.info("*" * 40)
        if mode == "Hybrid":
            logging.info("\tHybrid Network IDS Initiated:")
        else:
            logging.info("\tSignature IDS Initiated:")
        logging.info("*" * 40)
        filename = input(
            "[*] Please provide the path to the Ruleset (type 'default' for the predefined path, 'new' to specify a new path, or 'exit' to quit): "
        )

        if filename.lower() == "exit":
            logging.info("[*] Exiting the program.")
            sys.exit(0)

        if filename.lower() == "default":
            filename = DEFAULT_RULESET_PATH
            logging.info(f"[*] Using default ruleset path: {filename}")
            break

        if filename.lower() == "new":
            filename = input("[*] Please provide the new path to the Ruleset: ")

        if os.path.isfile(filename):
            break
        else:
            logging.info(
                f"[*] Error: The file '{filename}' does not exist. Please try again."
            )

    # Read the rule file
    logging.info("[*] Reading rule file...")
    global ruleList
    ruleList, errorCount = read(filename)
    logging.info("[*] Finished reading rule file.")

    if errorCount == 0:
        logging.info(f"[*] All ({len(ruleList)}) rules have been correctly read.")
    else:
        logging.info(f"[*] {len(ruleList)} rules have been correctly read.")
        logging.info(f"[*] {errorCount} rules have errors and could not be read.")

    # Begin sniffing
    logging.info("[*] Commencing packet sniffing...")
    sniffer = Sniffer(ruleList, handle_unknown_packets)
    set_sniffer(sniffer)
    sniffer.start()

    # Retrieve unknown packets - setting funnel infrastructure for AIDS
    if handle_unknown_packets and funnel_packets:
        threading.Thread(
            target=process_unknown_packets, args=(log_path,), daemon=True
        ).start()

    def signal_handler(sig, frame):
        logging.info("[*] Signature IDS stopping...")
        sniffer.stop()
        sniffer.join()
        packet_queue.put(None)  # Stop the packet processing thread
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Keep the main thread running, otherwise signals are ignored.
    try:
        while True:
            # Dynamically add unknown packets to the queue
            unknown_packets = retrieve_unknown_packets(sniffer)
            for packet in unknown_packets:
                packet_queue.put(packet)
    except KeyboardInterrupt:
        signal_handler(None, None)


# Global variables and setup
ruleList = list()

if __name__ == "__main__":
    main(
        handle_unknown_packets=False,
        funnel_packets=False,
        mode="Signature",
        log_path=None,
    )  # default value for testing purposes
