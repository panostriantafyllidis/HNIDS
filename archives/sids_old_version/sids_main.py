# -*- coding: utf-8 -*-
#! /usr/bin/env python3

"""
A Network Signature Intrusion Detection System (IDS) implemented in Python.
"""

from multiprocessing import Queue
from os import makedirs, path
from sys import argv
from sys import exit as sys_exit
from time import time

import ifaddr
from scapy.all import conf, get_if_list

from .analyzer import Analyzer
from .sniffer import Sniffer

# TO-DO : Tranfer Banner and MANUF_PATH seting confirmation (from sniffer),
# to the main.py file of the Hybrid system

# def print_banner() -> None:
#     banner = """
#     ███╗   ██╗ ██████╗███████╗██╗         ██╗██████╗ ███████╗
#     ████╗  ██║██╔════╝██╔════╝██║         ██║██╔══██╗██╔════╝
#     ██╔██╗ ██║██║     ███████╗██║         ██║██║  ██║███████╗
#     ██║╚██╗██║██║     ╚════██║██║         ██║██║  ██║╚════██║
#     ██║ ╚████║╚██████╗███████║███████╗    ██║██████╔╝███████║
#     ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝    ╚═╝╚═════╝ ╚══════╝
#     """
#     print(banner)


def get_interfaces():
    adapters = ifaddr.get_adapters()
    interfaces = {}
    for adapter in adapters:
        for ip in adapter.ips:
            if isinstance(ip.ip, str):  # IPv4 address
                interfaces[adapter.nice_name] = ip.ip
    return interfaces


def select_interface(interface_details):
    print("Available interfaces:")
    for i, (name, ip) in enumerate(interface_details.items()):
        print(f"{i}: {name} (IP: {ip})")
    choice = int(input("Select an interface by number: "))
    selected_name = list(interface_details.keys())[choice]
    return selected_name, interface_details[selected_name]


def main() -> None:
    # print_banner()

    interface_details = get_interfaces()

    if len(argv) < 2 or argv[1] not in interface_details:
        interface, ip = select_interface(interface_details)
    else:
        interface = argv[1]

    rule_path = argv[2] if len(argv) > 2 else "src/sids/rules/default.rules"

    if not path.exists("logs"):
        makedirs("logs")

    print(f"[*] Loading {rule_path}")

    queue = Queue()
    timestamp = str(int(time()))
    log_file_path = path.join("logs", f"{timestamp}.log")

    sniffer = Sniffer(interface, queue, timestamp)
    show_summary = False
    analyzer = Analyzer(queue, log_file_path, rule_path, show_summary)

    try:
        print("[*] Start sniffing")
        sniffer.start()
        print("[*] Start analyzing")
        analyzer.start()

        sniffer.join()
        analyzer.join()

    except KeyboardInterrupt:
        print("[*] Stopping IDS")
        sniffer.terminate()
        analyzer.terminate()
        sniffer.join()
        analyzer.join()
        print("[*] Bye")
        sys_exit()


if __name__ == "__main__":
    main()
