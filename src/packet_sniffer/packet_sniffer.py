import logging
import threading
from threading import Thread

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

from src.sids.rule import *


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
        """Handling unknown packets"""
        with self.lock:
            # Acquiring the lock to ensure thread-safe access to unknownPackets
            self.unknownPackets.append(pkt)  # Store the raw packet data

    def update_ruleset(self):

        from src.sids.rule_file_reader import read
        from src.sids.sids_main import DEFAULT_RULESET_PATH

        logging.info("[*] Reloading rules due to new rule addition...")
        self.ruleList, errorCount = read(DEFAULT_RULESET_PATH)
        if errorCount == 0:
            logging.info(
                f"[*] All ({len(self.ruleList)}) rules have been correctly read."
            )
        else:
            logging.info(f"[*] {len(self.ruleList)} rules have been correctly read.")
            logging.info(f"[*] {errorCount} rules have errors and could not be read.")

    def inPacket(self, pkt):
        """Directive for each received packet."""

        # Uncomment for TCP implementation
        # Check if this packet is a retransmission (for TCP packets)
        if TCP in pkt:
            seq_number = pkt[TCP].seq
            ack_number = pkt[TCP].ack
            # Create a unique key for this TCP connection
            tcp_key = (
                pkt[IP].src,
                pkt[IP].dst,
                pkt[TCP].sport,
                pkt[TCP].dport,
                seq_number,
                ack_number,
            )
            if tcp_key in self.processed_sequences:
                return  # Ignore this packet as it's a retransmission
            self.processed_sequences.add(tcp_key)  # Mark this packet as processed

        # Check for IP packets
        if IP in pkt:
            # Check for UDP packets
            if UDP in pkt:
                # Check for matching rules
                for rule in self.ruleList:
                    if rule.match(pkt):
                        # matched = True  # packet matched a rule - Known traffic
                        logging.info(rule.getMatchedPrintMessage(pkt))
                        return

                if pkt[IP].src == "192.168.2.12":
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
        ####### Uncomment and replace the above with the bellow if you want TCP processing.
        ####### It works when tested in a secondary machine, but my system had issues and I couldn't keep.
        # # Check for IP packets
        # if IP in pkt:
        #     logging.info(f"[*] Processing IP packet from {pkt[IP].src} to {pkt[IP].dst}.")
        #     # Check for UDP packets
        #     if UDP in pkt:
        #         logging.info(f"[*] Detected UDP packet from {pkt[IP].src} to {pkt[IP].dst}.")
        #         # Check for matching rules
        #         for rule in self.ruleList:
        #             if rule.match(pkt):
        #                 logging.info(rule.getMatchedPrintMessage(pkt))
        #                 return
        #         # Handle unknown UDP packet if unmatched
        #         if pkt[IP].src == "192.168.2.12" and self.handle_unknown_packets:
        #             logging.info(
        #                 f"[*] Processing unknown UDP packet from IP: {pkt[IP].src} ..."
        #             )
        #             self.handleUnknownPacket(pkt)
        #     # Check for TCP packets
        #     elif TCP in pkt:
        #         logging.info(f"[*] Detected TCP packet from {pkt[IP].src} to {pkt[IP].dst}.")
        #         # Create a unique key for this TCP connection to check for retransmissions
        #         seq_number = pkt[TCP].seq
        #         ack_number = pkt[TCP].ack
        #         tcp_key = (
        #             pkt[IP].src,
        #             pkt[IP].dst,
        #             pkt[TCP].sport,
        #             pkt[TCP].dport,
        #             seq_number,
        #             ack_number,
        #         )
        #         # Check if the TCP packet is already processed
        #         if tcp_key in self.processed_sequences:
        #             logging.info(f"[*] TCP packet {tcp_key} is a retransmission. Ignoring.")
        #             return  # Ignore this packet as it's a retransmission
        #         # Mark this TCP packet as processed
        #         self.processed_sequences.add(tcp_key)
        #         # After confirming it's not a retransmission, process like UDP
        #         for rule in self.ruleList:
        #             if rule.match(pkt):
        #                 logging.info(rule.getMatchedPrintMessage(pkt))
        #                 return
        #         # Handle unknown TCP packet if unmatched
        #         if pkt[IP].src == "192.168.2.12" and self.handle_unknown_packets:
        #             logging.info(
        #                 f"[*] Processing unknown TCP packet from IP: {pkt[IP].src} ..."
        #             )
        #             self.handleUnknownPacket(pkt)

    def run(self):
        logging.info("[*] Sniffing started.")
        sniff(
            prn=self.inPacket, filter="ip", store=0, stop_filter=self.stopfilter
        )  # ensuring only packets with an IP are captured
