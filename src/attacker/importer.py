# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from re import VERBOSE
from re import compile as reg_comp
from sys import argv

from signature import Signature

REGEX = reg_comp(
    r""" ^
    #sID
    (\d{1,5}:\s)?
    #PROTO
    ([A-Z]{2,4}\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|any):)
    #PORT
    (!?\d{1,6}|any|\[!\d{1,6}-\d{1,6}\]):\s
    #DIR
    (<>\s|->\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|any):)
    #PORT
    (!?\d{1,6}|any|\[!\d{1,6}-\d{1,6}\])\s
    #OPTIONS
    \(([^()]*)\)
    $ """,
    VERBOSE,
)


RULEPATH = ""
try:
    RULEPATH = argv[2]
except IndexError:
    RULEPATH = "ammo/eval.rules"
finally:
    print(f"[*] loading {RULEPATH}")


def verify_rules(ruleset):
    signatures = []
    for rule in ruleset:
        if rule[0] != "#":
            if REGEX.match(rule):
                sig = Signature(rule)
                if sig.sID == "":
                    sig.sID = str(len(signatures) + 1)
                if sig.sID in [s.sID for s in signatures]:
                    raise ValueError(" ID in use for %s" % (rule))
                signatures.append(sig)
            else:
                raise ValueError(f"{rule} does not match the syntax")
    try:
        signatures[0]
    except IndexError as exc:
        raise ValueError("empty signature set") from exc
    else:
        return signatures


def load_rules(path):
    try:
        with open(path, encoding="utf-8") as new_file:
            rules = new_file.readlines()
    except FileNotFoundError as file_err:
        raise ValueError(file_err) from file_err
    else:
        try:
            vrules = verify_rules([x.strip() for x in rules if len(x) > 1])
        except ValueError as file_err:
            raise file_err
        else:
            return vrules


try:
    RULES = load_rules(RULEPATH)
    print("[*] parsed rules")
except ValueError as err:
    exit(f"[@] {err}")
