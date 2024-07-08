"""Functions for reading a file of rules."""

from sids.Action import *
from sids.IPNetwork import *
from sids.Ports import *
from sids.Protocol import *
from sids.Rule import *


def read(filename):
    """Read the input file for rules and return the list of rules and the number of line errors."""

    l = list()
    with open(filename, "r") as f:
        ruleErrorCount = 0
        for line in f:
            # rule = parseRule(line)

            try:
                rule = Rule(line)
                l.append(rule)
            except ValueError as err:
                ruleErrorCount += 1
                print(err)

    return l, ruleErrorCount
