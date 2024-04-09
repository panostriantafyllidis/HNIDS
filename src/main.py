from scapy.all import sniff
from config import load_config

config = load_config()


def packet_analysis(packet):
    """
    Analyze each packet against known signatures.
    For simplicity, this function just prints packet summary.
    Expand this function to analyze packet contents against signatures.
    """
    print(packet.summary())


def start_capture(interface):
    """
    Start capturing packets on the specified interface.
    """
    print(f"Starting packet capture on interface {interface}")
    sniff(iface=interface, prn=packet_analysis)


if __name__ == "__main__":
    try:
        start_capture(config["network_interface"])
    except Exception as e:
        print(f"Error: {e}")
