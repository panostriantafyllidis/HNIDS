# -*- coding: utf-8 -*-
# ! /usr/bin/env python3
import logging
import os
from random import choice, randint
from sys import argv
from time import sleep, time

import ifaddr
import netifaces
import scapy.all as scapy
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether
from scapy.layers.l2 import get_if_hwaddr, getmacbyip
from snortparser import Parser, SerializeRule

AF_INET = netifaces.AF_INET
ifaddresses = netifaces.ifaddresses


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
    interface_choice = int(input("Select an interface by number: "))
    selected_name = list(interface_details.keys())[interface_choice]
    return selected_name, interface_details[selected_name]


interface_details = get_interfaces()
INTERFACE, ip = argv[1:3] if len(argv) == 3 else select_interface(interface_details)

print(f"Using IP: {ip} on interface: {INTERFACE}")

SOCKET = scapy.conf.L2socket(iface=INTERFACE)
DEFAULT_PORT = 80
MAX_PORT = 65535
timestamp = str(int(time()))
log_dir = "logs"
log_file_path = os.path.join(log_dir, f"{timestamp}.log")
os.makedirs(log_dir, exist_ok=True)
log_file = open(log_file_path, "w", encoding="utf-8")


def get_ports_from_range(ports):
    sport = ports
    sport = sport[1 : len(sport) - 1].split("-")
    ports = range(int(sport[0]), int(sport[1]) + 1)
    return ports


def create_packet(proto, src_port, dst_ip, dst_port):
    packet = Ether() / IP(src=ip, dst=dst_ip)
    if proto == "ICMP":
        packet = packet / ICMP()
    elif proto == "TCP":
        packet = packet / TCP(sport=src_port, dport=dst_port)
    elif proto == "UDP":
        packet = packet / UDP(sport=src_port, dport=dst_port)
    return packet


def send_unknown(rules, count=10):
    """
    Analyze given signatures and collect necessary information:
      - all used destination IPs
      - all used source and destination ports
      - ignore the key words "any", "none" and negated IPs and ports
    NOTE: the created unknown is only a possible unknown due to ignored negations of IPs and ports
    create lists of source/destination ports and destination IPs
    """
    print("\n\nSending Unknown...")
    src_ports = []
    dst_ips = []
    dst_ports = []
    for rule in rules:
        header = rule["header"]
        src_ip = header["source"][1]
        dst_ip = header["destination"][1]
        src_port = header["src_port"][1]
        dst_port = header["dst_port"][1]

        if not src_ip.startswith("!") and src_ip not in ["any", "none"]:
            if src_ip not in src_ports:
                src_ports.append(src_ip)
        if not dst_ip.startswith("!") and dst_ip not in ["any", "none"]:
            if dst_ip not in dst_ips:
                dst_ips.append(dst_ip)
        if not src_port.startswith("!") and src_port not in ["any", "none"]:
            if src_port.startswith("["):
                ports = get_ports_from_range(src_port)
                for i in ports:
                    if i not in src_ports:
                        src_ports.append(i)
            else:
                if src_port not in src_ports:
                    src_ports.append(int(src_port))
        if not dst_port.startswith("!") and dst_port not in ["any", "none"]:
            if dst_port.startswith("["):
                ports = get_ports_from_range(dst_port)
                for i in ports:
                    if i not in dst_ports:
                        dst_ports.append(i)
            else:
                if dst_port not in dst_ports:
                    dst_ports.append(int(dst_port))

    # all allowed protocols
    protocols = ["IP", "ICMP", "TCP", "UDP"]
    #
    ips = [
        "192.168.56.1",
        "192.168.56.2",
        "192.168.56.104",
        "192.168.56.105",
    ]
    sent = 0
    # create count "possible" unknowns
    for i in range(1, count + 1):
        # choose protocol pseudo randomly
        proto = choice(protocols)
        dst_ip = choice(ips)
        src_port = randint(1, MAX_PORT + 1)
        dst_port = randint(1, MAX_PORT + 1)
        # ensure that dest IP is not equal source IP
        while dst_ip == ip or dst_ip in dst_ips:
            dst_ip = choice(ips)
        # ensure that source port is not in given source ports
        while src_port in src_ports:
            src_port = randint(1, MAX_PORT + 1)
        # ensure that destination port is not in given destination ports
        while dst_port in dst_ports:
            dst_port = randint(1, MAX_PORT + 1)
        packet = create_packet(proto, src_port, dst_ip, dst_port)
        SOCKET.send(packet)
        sleep(0.5)
        print(f"\tSent packet: {packet.summary()}.\n\n")
        sent = i

    print(f"{sent} Unknown packets sent.\n\n")


def create_known_packet(header):
    try:
        # Get the MAC address of the selected network interface
        src_mac = get_if_hwaddr(INTERFACE)
        dst_ip = header["destination"][1]

        # Efficiently retrieve the destination MAC address
        dst_mac = getmacbyip(dst_ip)
        if dst_mac is None:
            logging.warning(
                f"Failed to get MAC address for IP {dst_ip}, using broadcast address"
            )
            dst_mac = "ff:ff:ff:ff:ff:ff"  # Default to broadcast MAC if not found

        # Log the retrieved MAC addresses
        logging.info(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")

        # Set up the Ethernet and IP layers
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=header["source"][1], dst=dst_ip)
        proto = header["proto"].lower()  # Ensure protocol is in lowercase
        src_port = header["src_port"][1]
        dst_port = header["dst_port"][1]

        # Error out if ports are specified as "any" or "none"
        if src_port in ["any", "none"] or dst_port in ["any", "none"]:
            raise ValueError("Ports cannot be 'any' or 'none' for packet creation.")

        # Convert ports to integers
        try:
            sport = int(src_port)
            dport = int(dst_port)
        except ValueError:
            raise ValueError("Ports must be valid integers.")

        # Construct the appropriate transport layer packet
        if proto == "tcp":
            pkt = pkt / TCP(sport=sport, dport=dport, flags="S")
        elif proto == "udp":
            pkt = pkt / UDP(sport=sport, dport=dport)
        elif proto == "icmp":
            pkt = pkt / ICMP()
        else:
            raise ValueError(f"Unknown protocol: {proto}")

        # Override Scapy's default port name resolution
        if TCP in pkt:
            pkt[TCP].sport = sport
            pkt[TCP].dport = dport
        if UDP in pkt:
            pkt[UDP].sport = sport
            pkt[UDP].dport = dport

        return pkt
    except KeyError as e:
        logging.error(f"Missing key in header: {e}")
        raise
    except ValueError as ve:
        logging.error(f"Error: {ve}")
        raise
    except Exception as e:
        logging.error(f"Error creating packet: {e}")
        raise


def send_known(rules):
    known_choice = input("Do you want to send (1) Attack or (2) Normal packets? ")
    selected_signatures = []

    try:
        if known_choice == "1":
            selected_signatures = [
                sig
                for sig in rules
                if "options" in sig
                and list(sig["options"].values())[0][0] == "msg"
                and "attack" in list(sig["options"].values())[0][1][0].lower()
            ]
        elif known_choice == "2":
            selected_signatures = [
                sig
                for sig in rules
                if "options" in sig
                and list(sig["options"].values())[0][0] == "msg"
                and "normal" in list(sig["options"].values())[0][1][0].lower()
            ]

        print(f"Found {len(selected_signatures)} matching signatures")

        count = input("How many packets do you want to send? (default = 10) ")
        count = int(count) if count.isdigit() else 10

        print("\n\nSending Known Packets...")
        created_packets = 0
        sent_packets = 0
        for i in range(min(count, len(selected_signatures))):
            signature = selected_signatures[i % len(selected_signatures)]
            try:
                packet = create_known_packet(signature["header"])
                created_packets += 1
                message = (
                    SerializeRule(signature).serialize_header()
                    + " ~> "
                    + packet.summary()
                    + "\n"
                )
                print(
                    f"Created packet: {packet.show(dump=True)}"
                )  # Print packet details
                try:
                    SOCKET.send(packet)
                    sent_packets += 1
                    print(f"\tSent packet: {packet.summary()}.\n\n")
                    log_file.write(message)
                    log_file.flush()
                except Exception as send_error:
                    print(f"Error sending packet: {send_error}")
                sleep(0.5)
            except Exception as e:
                print(f"Error creating or sending packet for rule {signature}: {e}")

        print(f"\n\n{created_packets} packets created.")
        print(f"{sent_packets} packets sent.")
    except Exception as e:
        print(f"Error processing rules: {e}")


def print_menu():
    print("*" * 40)
    print("\t\tMain Menu:")
    print("*" * 40)
    print("\t(1) Send Known Packets")
    print("\t(2) Send Unknown Packets")
    print("\t(3) Send Manually Created Packet")
    print("\t(4) Exit")
    return int(input("What do you want to do: "))


def main():
    with open("ammo/eval.rules", "r", encoding="utf-8") as f:
        rules = f.readlines()

    rules = [
        Parser(rule.strip()).data
        for rule in rules
        if rule.strip() and not rule.startswith("#")
    ]

    print("[*] parsed rules")

    running = True
    while running:
        selection = print_menu()
        while selection not in [1, 2, 3, 4]:
            selection = print_menu()
        if selection == 1:
            if len(rules) == 0:
                print("Error: No rules loaded.")
            else:
                send_known(rules)
        elif selection == 2:
            selection = input(
                "How many Unknown packets do you want to send (default = 10)? "
            )
            if len(selection) == 0:
                send_unknown(rules)
            else:
                send_unknown(rules, int(selection))
        elif selection == 3:
            print(
                "Insert following format [protocol] [source port] [destination IP] [destination port]"
            )
            selection = input("")
            selection = selection.split(" ")
            packet = create_packet(
                selection[0], int(selection[1]), selection[2], int(selection[3])
            )
            SOCKET.send(packet)
            print(f"Sent packet: {packet.summary()}\n\n")
        elif selection == 4:
            running = False


if __name__ == "__main__":
    main()
