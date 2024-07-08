import datetime
import logging
import os
import signal
import sys
from sys import argv

from scapy.all import datetime

from src.sids.RuleFileReader import read
from src.sids.Sniffer import Sniffer

RED = "\033[91m"
BLUE = "\033[34m"
GREEN = "\033[32m"
ENDC = "\033[0m"


def main(filename):
    """Read the rule file and start listening."""

    # Create log directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(__file__), "log")
    os.makedirs(log_dir, exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(log_dir, f"Simple-NIDS_{now}.log")
    logging.basicConfig(filename=log_file, level=logging.INFO)

    print("Simple-NIDS started.\n")
    # Read the rule file
    print("Reading rule file...")
    global ruleList
    # ruleList, errorCount = RuleFileReader.read(filename)
    ruleList, errorCount = read(filename)
    print("Finished reading rule file.")

    if errorCount == 0:
        print(f"All ({len(ruleList)}) rules have been correctly read.")
    else:
        print(f"{len(ruleList)} rules have been correctly read.")
        print(f"{errorCount} rules have errors and could not be read.")

    # Begin sniffing
    sniffer = Sniffer(ruleList)
    sniffer.start()

    def signal_handler(sig, frame):
        print("\nSimple-NIDS stopping...")
        sniffer.stop()
        sniffer.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Keep the main thread running, otherwise signals are ignored.
    try:
        while True:
            pass
    except KeyboardInterrupt:
        signal_handler(None, None)


# Global variables and setup
ruleList = list()
script, filename = argv
main(filename)
