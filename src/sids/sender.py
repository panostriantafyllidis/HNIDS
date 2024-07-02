# -*- coding: utf-8 -*-
# ! /usr/bin/env python3
import os
from random import choice, randint
from sys import argv
from time import sleep, time

import ifaddr
import netifaces

AF_INET = netifaces.AF_INET
ifaddresses = netifaces.ifaddresses
import scapy.all as scapy
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether

from .importer import RULES


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
log_file = open(log_file_path, "w")


def getPortsFromRange(ports):
    sport = ports
    sport = sport[1 : len(sport) - 1].split("-")
    ports = range(int(sport[0]), int(sport[1]) + 1)
    return ports


def create_package(proto, src_port, dst_ip, dst_port):
    # package = Ether() / IP(src=ip, dst=dst_ip)
    # package = Ether() / IP(src=ip, dst="192.168.56.104")
    package = Ether() / IP(src=ip, dst="192.168.56.1")

    if proto == "ICMP":
        package = package / ICMP()
    elif proto == "TCP":
        package = package / TCP(sport=src_port, dport=dst_port)
    elif proto == "UDP":
        package = package / UDP(sport=src_port, dport=dst_port)
    print(f"Creating packet: {package.summary()}")
    return package


def send_negatives(count=10):
    """
    analyse given signatures and collect necessary information:
      - all used destination IPs
      - all used source and destination ports
      - ignore the key words "any", "none" and negated IPs and ports
    NOTE: the created negative is only a possible negative due to ignored negations of IPs and ports
    create lists of source/destination ports and destination IPs
    """
    print("\n\nSending Negatives...")
    src_ports = []
    dst_ips = []
    dst_ports = []
    for signature in RULES:
        if not (
            signature.dst_ip.startswith("!") or signature.dst_ip in ["any", "none"]
        ):
            if signature.dst_ip not in dst_ips:
                dst_ips.append(signature.dst_ip)
        if not (
            signature.src_port.startswith("!") or signature.src_port in ["any", "none"]
        ):
            if signature.src_port.startswith("["):
                ports = getPortsFromRange(signature.src_port)
                for i in ports:
                    if i not in src_ports:
                        src_ports.append(i)
            else:
                if signature.src_port not in src_ports:
                    src_ports.append(int(signature.src_port))
        if not (
            signature.dst_port.startswith("!") or signature.dst_port in ["any", "none"]
        ):
            if signature.dst_port.startswith("["):
                ports = getPortsFromRange(signature.dst_port)
                for i in ports:
                    if i not in dst_ports:
                        dst_ports.append(i)
            else:
                if signature.dst_port not in dst_ports:
                    dst_ports.append(int(signature.dst_port))

    # all allowed protocols
    protocols = ["IP", "ICMP", "TCP", "UDP"]
    #
    ips = [
        "10.0.2.6",
        "192.168.56.1",
        "192.168.0.5",
        "192.168.0.3",
        "192.168.1.4",
        "192.169.0.4",
        "192.167.0.4",
        "193.168.0.4",
        "191.168.0.4",
        "192.168.0.1",
        "192.168.0.2",
        "192.168.0.3",
        "192.168.0.4",
    ]
    sent = 0
    # create count "possible" negatives
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
        package = create_package(proto, src_port, dst_ip, dst_port)
        SOCKET.send(package)
        sleep(0.5)
        print("\tSend package: {}".format(package.summary()))
        sent = i

    print("{} Negatives sent.\n\n".format(sent))


# This function creates for every signature a package, which results in an alarm for the corresponding signature.
def create_positives(signature):
    # TODO: special case: negation
    # special case: bidirectional and dest IP equals own ip
    bidirect = False
    if signature.dir == "<>" and signature.dst_ip == ip:
        pkg = Ether() / IP(src=ip, dst=signature.src_ip)
        bidirect = True
    else:
        pkg = Ether() / IP(src=ip, dst=signature.dst_ip)
    if signature.proto == "IP":
        # if protocol is IP, choose randomly a transport protocol
        signature.proto = choice(["TCP", "UDP"])
    # check if ports are defined as "any" or "none"
    if signature.src_port in ["any", "none"]:
        sport = DEFAULT_PORT
    elif signature.src_port.startswith("["):
        # if there is a list of ports, just pick up one port of them randomly
        ports = getPortsFromRange(signature.src_port)
        sport = choice(ports)
    elif not signature.src_port.startswith("!"):
        sport = int(signature.src_port)
    if signature.dst_port in ["any", "none"]:
        dport = DEFAULT_PORT
    elif signature.dst_port.startswith("["):
        # if there is a list of ports, just pick up one port of them randomly
        ports = getPortsFromRange(signature.dst_port)
        dport = choice(ports)
    elif not signature.src_port.startswith("!"):
        dport = int(signature.dst_port)
    if signature.proto == "TCP":
        if bidirect:
            return pkg / TCP(sport=dport, dport=sport)
        else:
            return pkg / TCP(sport=sport, dport=dport)
    elif signature.proto == "UDP":
        if bidirect:
            return pkg / UDP(sport=dport, dport=sport)
        else:
            return pkg / UDP(sport=sport, dport=dport)
    elif signature.proto == "ICMP":
        # no ports for protocol ICMP?
        return pkg / ICMP()
    else:
        print(
            "Unknown protocol of signature: {} with proto: {}".format(
                signature.sID, signature.proto
            )
        )


def send_positives():
    print("\n\nSending Positives...")
    for signature in RULES:
        if (
            signature.src_ip == ip or (signature.dir == "<>" and signature.dst_ip == ip)
        ) and not (
            signature.dst_ip.startswith("!")
            or signature.src_port.startswith("!")
            or signature.dst_port.startswith("!")
        ):
            package = create_positives(signature)
            message = (
                signature.sID
                + ": "
                + signature.__str__()
                + " ~> "
                + package.summary()
                + "\n"
            )
            print("\t{}".format(message.replace("\n", "", 1)))
            SOCKET.send(package)
            sleep(0.5)
            log_file.write(message)
            log_file.flush()
    print("\n\nPositives sent.")


def print_menu():
    print("*" * 40)
    print("\t\tMain Menu:")
    print("*" * 40)
    print("\t(1) send Positives")
    print("\t(2) send Negatives")
    print("\t(3) send manually created package")
    print("\t(4) exit")
    return int(input("What do you want to do: "))


def main():
    running = True
    while running:
        selection = print_menu()
        while selection not in [1, 2, 3, 4]:
            selection = print_menu()
        if selection == 1:
            if len(RULES) == 0:
                print("Error: No rules loaded.")
            else:
                send_positives()
        elif selection == 2:
            selection = input("How many Negatives do you want to send (default = 10)? ")
            if len(selection) == 0:
                send_negatives()
            else:
                send_negatives(int(selection))
        elif selection == 3:
            print(
                "Insert following format [protocol] [source port] [destination IP] [destination port]"
            )
            selection = input("")
            selection = selection.split(" ")
            package = create_package(
                selection[0], int(selection[1]), selection[2], int(selection[3])
            )
            SOCKET.send(package)
            print("Sent package: {}\n\n".format(package.summary()))
        elif selection == 4:
            running = False


if __name__ == "__main__":
    main()
