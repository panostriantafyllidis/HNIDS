# signature.py
# -*- coding: utf-8 -*-
#! /usr/bin/env python3
from copy import deepcopy
from typing import Tuple

from scapy.layers.inet import ICMP, IP, Ether


def switch_directions(signatur: "Signature") -> Tuple["Signature", "Signature"]:
    """
    Switches the source and destination directions of a given signature.

    Parameters
    ----------
    signatur : Signature
        The signature to switch directions for.

    Returns
    -------
    Tuple[Signature, Signature]
        A tuple containing the original signature with its direction set to '->'
        and the switched signature with its source and destination swapped.
    """
    srcdst = deepcopy(signatur)
    srcdst.dir = "->"
    dstsrc = deepcopy(signatur)
    dstsrc.dir = "->"
    dstsrc.src_ip = dstsrc.dst_ip
    dstsrc.src_port = dstsrc.dst_port
    dstsrc.dst_ip = srcdst.src_ip
    dstsrc.dst_port = srcdst.src_port

    return srcdst, dstsrc


def not_eq(other_: str, self_: str, normal: bool = True) -> bool:
    """
    Checks inequality between two values with special handling for 'any', '!', and ranges.

    Parameters
    ----------
    other_ : str
        The value to compare against.
    self_ : str
        The value to be compared.
    normal : bool, optional
        Whether to perform a normal comparison (default is True).

    Returns
    -------
    bool
        True if the values are not equal based on the rules, False otherwise.
    """
    if normal:
        if other_ == "IP" and self_ in ["TCP", "UDP"]:
            return False
        else:
            return self_ == other_[1:] if other_[0] == "!" else self_ != other_
    else:
        if self_ == "any":
            return False
        split = other_.split("!")
        if "-" in other_:
            split_split = split[-1].split("-")
            min_ = split_split[0][1:]
            max_ = split_split[1][:-1]
        else:
            min_ = split[-1]
            max_ = split[-1]

        other_ = range(int(min_), int(max_) + 1)
        try:
            self_ = int(self_)
        except ValueError:
            print(f"no meaning full compare/TODO: {self_}")
            return True
        else:
            return (len(split) == 1 and self_ not in other_) or (
                len(split) == 2 and self_ in other_
            )


class Signature(object):
    """
    A class used to represent a network packet signature.

    This class can be initialized with either a scapy packet or a string, and it
    extracts or parses the relevant information to create a signature for comparison.

    Attributes
    ----------
    sID : str
        The ID of the signature.
    proto : str
        The protocol of the packet.
    src_ip : str
        The source IP address.
    src_port : str
        The source port.
    dir : str
        The direction of the packet ('->', '<>', etc.).
    dst_ip : str
        The destination IP address.
    dst_port : str
        The destination port.
    payload : str
        The payload of the packet.

    Methods
    -------
    __str__():
        Returns the string representation of the signature.

    __repr__():
        Returns the representation of the rule ID.

    __eq__(other):
        Checks if the signature is equal to another signature.
    """

    def __init__(self, obj):
        super(Signature, self).__init__()
        if isinstance(obj, Ether):
            direction = "->"
            sID = "-1"
            if IP in obj:
                proto = obj[2].name
                src_ip = str(obj[1].src)
                dst_ip = str(obj[1].dst)
                payload = "*"
                try:
                    src_port = str(obj[1].sport)
                    dst_port = str(obj[1].dport)
                except AttributeError as exc:
                    if ICMP in obj:
                        src_port = "any"
                        dst_port = "any"
                    else:
                        raise ValueError() from exc
                except IndexError as exc:
                    raise ValueError() from exc
            else:
                raise ValueError()
        elif isinstance(obj, str):
            string = obj.split(" ")
            if len(string) == 5:
                src_split = string[1].split(":")
                dst_split = string[3].split(":")

                sID = ""
                proto = string[0]
                src_ip = src_split[0]
                src_port = src_split[1]
                direction = string[2]
                dst_ip = dst_split[0]
                dst_port = dst_split[1]
                payload = string[4]

            elif len(string) == 6:
                src_split = string[2].split(":")
                dst_split = string[4].split(":")

                sID = string[0].split(":")[0]
                proto = string[1]
                src_ip = src_split[0]
                src_port = src_split[1]
                direction = string[3]
                dst_ip = dst_split[0]
                dst_port = dst_split[1]
                payload = string[5]
        else:
            raise ValueError(obj, "cant be initialized")
        del obj
        self.sID = sID
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dir = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.payload = payload

    def __str__(self):
        return f"{self.proto} {self.src_ip}:{self.src_port} {self.dir} {self.dst_ip}:{self.dst_port} {self.payload}"

    def __repr__(self):
        return f"ruleID {self.sID}"

    def __eq__(self, other):
        """
        not commutative
        self always without !/any/<>/portRange
        """
        if isinstance(self, other.__class__):
            if other.dir == "<>":
                dir_a, dir_b = switch_directions(other)
                return self.__eq__(dir_a) or self.__eq__(dir_b)
            if other.proto != "any":
                if not_eq(other.proto, self.proto):
                    return False
            if other.src_ip != "any":
                if not_eq(other.src_ip, self.src_ip):
                    return False
            if other.src_port != "any":
                if not_eq(other.src_port, self.src_port, 0):
                    return False
            if other.dst_ip != "any":
                if not_eq(other.dst_ip, self.dst_ip):
                    return False
            if other.dst_port != "any":
                if not_eq(other.dst_port, self.dst_port, 0):
                    return False
            if other.payload != "any":
                if self.payload != other.payload:
                    return False
            return True
        else:
            return False
