# # Get all network interfaces
# interfaces = netifaces.interfaces()
# print("Available network interfaces:")
# for idx, interface in enumerate(interfaces):
#     print(f"{idx}: {interface}")

import platform

# # Allow the user to select an interface
# selected_idx = int(input("\nSelect the interface index to use: "))
# selected_interface = interfaces[selected_idx]
# print(f"Selected interface: {selected_interface}")
import netifaces
from scapy.all import get_if_list

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None


def get_interface_details():
    details = []
    system = platform.system()

    if system == "Windows" and get_windows_if_list:
        intf_list = get_if_list()
        for name in intf_list:
            try:
                addrs = netifaces.ifaddresses(name)
                details.append((name, addrs))
            except ValueError:
                details.append((name, "Cannot get addresses for this interface"))
    else:
        for name in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(name)
                details.append((name, addrs))
            except ValueError:
                details.append((name, "Cannot get addresses for this interface"))
    return details


def print_interface_information():
    interface_details = get_interface_details()
    for idx, (name, addrs) in enumerate(interface_details):
        print(f"{idx + 1}: {name}\nDetails for interface {name}: {addrs}\n{'-'*40}")


if __name__ == "__main__":
    print_interface_information()
