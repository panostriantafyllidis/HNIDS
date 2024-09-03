# ==============================================================================
# CREATING A NEW RULE , IF VERDICT = 1, ALONG WITH AN ALERT
# ==============================================================================
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP, Ether

from src.packet_sniffer.packet_sniffer import *
from src.packet_sniffer.packet_sniffer_manager import update_sniffer_ruleset
from src.sids.sids_main import *


def create_rule(action, protocol, src_ip, src_port, dst_ip, dst_port, msg):
    """
    Create a rule string based on the provided parameters.

    Args:
        action (str): Action to be taken (e.g., "alert").
        protocol (str): Protocol to be matched (e.g., "tcp").
        src_ip (str): Source IP address.
        src_port (str): Source port (e.g., "any").
        dst_ip (str): Destination IP address.
        dst_port (str): Destination port (e.g., "any").
        msg (str): Message to be included in the rule.

    Returns:
        str: The constructed rule string.
    """
    rule = (
        f'{action} {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} (msg: "{msg}")'
    )
    return rule


def add_rule_to_file(rule_string, ruleset_path=DEFAULT_RULESET_PATH):
    """
    Append a new rule to the specified ruleset file.

    Args:
        rule_string (str): The rule to be added.
        ruleset_path (str): The path to the ruleset file.
    """
    try:
        with open(ruleset_path, "a") as file:
            file.write(f"{rule_string}\n")
        logging.info(f"[*] New rule added to {ruleset_path}: {rule_string}")
        update_sniffer_ruleset()
    except IOError as e:
        logging.error(f"Error writing to ruleset file: {e}")


def handle_attack_detection(packet, ruleset_path=DEFAULT_RULESET_PATH):
    """
    Handle attack detection by creating and appending a new rule based on the packet details.

    Args:
        packet: The packet that triggered the alert.
        ruleset_path (str): The path to the ruleset file to which the new rule will be added.
    """
    # Determine the protocol
    if TCP in packet:
        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        protocol = "ip"
        src_port = "any"
        dst_port = "any"

    # Extract IP addresses
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Create the rule
    new_rule = create_rule(
        action="alert",
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        msg="Possible Attack",
    )

    # Add the rule to the ruleset file
    add_rule_to_file(new_rule, ruleset_path)
