import logging
import threading
from threading import Thread

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# import src.sids.RuleFileReader
from src.sids.Rule import *


class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList, handle_unknown_packets):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList
        self.handle_unknown_packets = handle_unknown_packets
        self.unknownPackets = []
        self.processed_sequences = set()  # To track processed sequence numbers
        self.lock = threading.Lock()

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def handleUnknownPacket(self, pkt):
        """Handling unknown packets - from specific IP - If the goal is to handle any and all unknwons, edit bellow"""
        # if IP in pkt and pkt[IP].src == "192.168.2.10":
        with self.lock:
            # Acquiring the lock to ensure thread-safe access to unknownPackets
            self.unknownPackets.append(pkt)  # Store the raw packet data

    def inPacket(self, pkt):
        """Directive for each received packet."""

        # # Check if this packet is a retransmission (for TCP packets)
        # if TCP in pkt:
        #     seq_number = pkt[TCP].seq
        #     ack_number = pkt[TCP].ack
        #     # Create a unique key for this TCP connection
        #     tcp_key = (
        #         pkt[IP].src,
        #         pkt[IP].dst,
        #         pkt[TCP].sport,
        #         pkt[TCP].dport,
        #         seq_number,
        #         ack_number,
        #     )
        #     if tcp_key in self.processed_sequences:
        #         return  # Ignore this packet as it's a retransmission
        #     self.processed_sequences.add(tcp_key)  # Mark this packet as processed

        # Check for IP packets
        if IP in pkt:
            # Check for UDP packets
            if UDP in pkt:
                # Check for matching rules
                for rule in self.ruleList:
                    if rule.match(pkt):
                        matched = True  # packet matched a rule - Known traffic
                        logging.info(rule.getMatchedPrintMessage(pkt))
                        return

                if pkt[IP].src == "192.168.2.33" and pkt[UDP].dport == 5000:
                    if self.handle_unknown_packets:
                        logging.info(
                            f"[*] Processing unknown packet from IP: {pkt[IP].src} ..."
                        )
                        self.handleUnknownPacket(pkt)
            # Check for TCP packets
            elif TCP in pkt:
                if pkt[TCP].dport == 5000:
                    logging.info(
                        f"[*] Sorry, TCP packets not implemented thanks to Windows Firewall issues..."
                    )

    def run(self):
        logging.info("[*] Sniffing started.")
        sniff(
            prn=self.inPacket, filter="ip", store=0, stop_filter=self.stopfilter
        )  # ensuring only packets with an IP are captured
        # logMessage = rule.getMatchedMessage(pkt)
        # logging.warning(logMessage)
