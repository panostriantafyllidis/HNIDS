# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from multiprocessing import Queue
from os import makedirs, path
from sys import argv
from sys import exit as sys_exit
from time import sleep, time
from typing import Optional

from .analyzer import Analyzer
from .sniffer import Sniffer

"""
Intrusion Detection System (IDS) implemented in Python.
"""


def print_banner() -> None:
    banner = """
     █████╗  ██████╗███████╗██╗         ██╗██████╗ ███████╗
    ██╔══██╗██╔════╝██╔════╝██║         ██║██╔══██╗██╔════╝
    ███████║██║     ███████╗██║         ██║██║  ██║███████╗
    ██╔══██║██║     ╚════██║██║         ██║██║  ██║╚════██║
    ██║  ██║╚██████╗███████║███████╗    ██║██████╔╝███████║
    ╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝    ╚═╝╚═════╝ ╚══════╝
    """
    print(banner)


def main() -> None:
    print_banner()

    if len(argv) < 2:
        sys_exit("[@] No interface was passed. Usage: main.py <INTERFACE> [RULE_PATH]")

    interface = argv[1]
    rule_path = argv[2] if len(argv) > 2 else "sids_rules/default.rules"

    if not path.exists("logs"):
        makedirs("logs")

    print(f"[*] Loading {rule_path}")

    queue = Queue()
    timestamp = str(int(time()))
    log_file_path = path.join("logs", f"{timestamp}.log")

    with open(log_file_path, "w") as log_file:
        sniffer = Sniffer(interface, queue, timestamp)
        show_summary = False
        analyzer = Analyzer(queue, log_file, rule_path, show_summary)

        try:
            print("[*] Start sniffing")
            sniffer.start()
            print("[*] Start analyzing")
            analyzer.start()

            while True:
                sleep(100)

        except KeyboardInterrupt:
            print("[*] Stopping IDS")
            sys_exit()
            analyzer.join()
            sleep(0.1)
            sniffer.join()
            print("[*] Bye")


if __name__ == "__main__":
    main()
