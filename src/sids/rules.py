# -*- coding: utf-8 -*-
#! /usr/bin/env python3

"""
This module provides utilities for loading and verifying network packet rules.
"""

from re import VERBOSE
from re import compile as reg_comp
from typing import List

from .signature import Signature

RULE_REGEX = reg_comp(
    r""" ^
    #sID
    (\d{,99999}:\s)?
    #PROTO
    ([A-Z]{,4}\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #DIR
    (<>\s|->\s)
    #IP
    (!?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)|any:)
    #PORT
    (!?[0-9]{,6}\s|(any)\s|!?\[[0-9]{,6}-[0-9]{,6}\]\s)
    #PAYLOAD
    (\*)
        $ """,
    VERBOSE,
)


def verify_rules(ruleset: List[str]) -> List[Signature]:
    """
    Verifies a list of rules and converts them into Signature objects.

    Parameters
    ----------
    ruleset : List[str]
        A list of rules in string format.

    Returns
    -------
    List[Signature]
        A list of valid Signature objects.

    Raises
    ------
    ValueError
        If a rule does not match the syntax or if there are duplicate IDs.
    """
    signatures = []
    for rule in ruleset:
        if not rule.startswith("#"):
            if RULE_REGEX.match(rule):
                signature = Signature(rule)
                if not signature.sID:
                    signature.sID = str(len(signatures) + 1)
                if signature.sID in {s.sID for s in signatures}:
                    raise ValueError(f"ID in use for {rule}")
                signatures.append(signature)
            else:
                raise ValueError(f"{rule} does not match the syntax")

    if not signatures:
        raise ValueError("Empty signature set")

    return signatures


def load_rules(path: str) -> List[Signature]:
    """
    Loads rules from a file and verifies them.

    Parameters
    ----------
    path : str
        The file path to load the rules from.

    Returns
    -------
    List[Signature]
        A list of valid Signature objects.

    Raises
    ------
    ValueError
        If the file is not found or if the rules are invalid.
    """
    try:
        with open(path) as file:
            rules = file.readlines()
    except FileNotFoundError as e:
        raise ValueError(f"File not found: {path}") from e

    try:
        verified_rules = verify_rules([rule.strip() for rule in rules if rule.strip()])
    except ValueError as e:
        raise ValueError(f"Error verifying rules in {path}: {e}") from e

    return verified_rules
