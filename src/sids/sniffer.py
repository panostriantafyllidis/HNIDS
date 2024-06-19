# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from multiprocessing import Process, Event, Queue
from typing import Optional, Any
from scapy.all import conf, sniff, wrpcap, ETH_P_ALL
from scapy.packet import Packet

"""
This module defines a packet Sniffer class using multiprocessing to capture network packets 
on a specified network interface and save them to a pcap file. It uses Scapy for packet sniffing 
and analysis.
"""


class Sniffer(Process):
    """
    A class used to represent a Network Packet Sniffer.

    This class inherits from multiprocessing.Process and captures network packets
    on a specified interface using Scapy, analyzing and saving the packets to a queue
    and a pcap file.

    Attributes
    ----------
    interface : str
        The network interface to sniff packets on.
    queue : multiprocessing.Queue
        The queue to store analyzed packets.
    log_name : str
        The name used for the log file.

    Methods
    -------
    run(self) -> None:
        Starts the packet sniffing process.
    analyze_packet(self, packet: Packet) -> None:
        Analyzes a single packet and puts its byte representation into the queue.
    stop_sniffing(self, _: Any) -> bool:
        Checks if the sniffer should stop running.
    join(self, timeout: Optional[int] = None) -> None:
        Stops the sniffer and waits for the process to terminate.
    """

    def __init__(self, interface: str, queue: Queue, log_name: str):
        super().__init__()
        self.daemon = True
        self.socket = None
        self.interface = interface
        self.stop_event = Event()
        self.queue = queue
        self.log_name = log_name

    def run(self) -> None:
        try:
            self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.interface)
        except PermissionError:
            exit(f"[@] No permissions to listen on {self.interface}")

        packets = sniff(
            opened_socket=self.socket,
            prn=self.analyze_packet,
            stop_filter=self.stop_sniffing,
        )
        wrpcap(f"logs/{self.log_name}.pcap", packets)

    def analyze_packet(self, packet: Packet) -> None:
        self.queue.put(bytes(packet))

    def stop_sniffing(self, _: Any) -> bool:
        return self.stop_event.is_set()

    def join(self, timeout: Optional[int] = None) -> None:
        self.stop_event.set()
        super().join(timeout)
