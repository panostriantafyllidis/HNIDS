# sniffer_manager.py

from src.packet_sniffer.packet_sniffer import Sniffer

_sniffer_instance = None


def get_sniffer():
    global _sniffer_instance
    return _sniffer_instance


def set_sniffer(sniffer_instance):
    global _sniffer_instance
    _sniffer_instance = sniffer_instance


def update_sniffer_ruleset():
    global _sniffer_instance
    if _sniffer_instance is not None:
        _sniffer_instance.update_ruleset()
    else:
        print.error("No running Sniffer instance found to update rules.")
