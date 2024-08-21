import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import time


def calculate_features(packets):
    # Initialize a DataFrame to store packet information
    df = pd.DataFrame(
        columns=[
            "sbytes",
            "dbytes",
            "Spkts",
            "Dpkts",
            "Sload",
            "Dload",
            "Sjit",
            "Djit",
            "Sintpkt",
            "Dintpkt",
            "tcprtt",
            "synack",
            "ackdat",
            "stcpb",
            "dtcpb",
            "Stime",
            "Ltime",
        ]
    )

    # Variables to store previous packet times and sequences for jitter and inter-packet interval calculations
    prev_src_time = {}
    prev_dst_time = {}
    prev_src_seq = {}
    prev_dst_seq = {}

    # Variables to store the first and last packet times for calculating Stime and Ltime
    first_packet_time = None
    last_packet_time = None

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_time = time.time()

            # Set the first and last packet times
            if first_packet_time is None:
                first_packet_time = packet_time
            last_packet_time = packet_time

            row = {
                "sbytes": len(packet[IP]),
                "dbytes": len(packet[IP].payload),
                "Spkts": 1 if src_ip else 0,
                "Dpkts": 1 if dst_ip else 0,
                "Sload": (
                    len(packet[IP].payload) if TCP in packet or UDP in packet else 0
                ),
                "Dload": (
                    len(packet[IP].payload) if TCP in packet or UDP in packet else 0
                ),
                "Sjit": 0,
                "Djit": 0,
                "Sintpkt": 0,
                "Dintpkt": 0,
                "tcprtt": 0,
                "synack": 1 if TCP in packet and packet[TCP].flags == "SA" else 0,
                "ackdat": 1 if TCP in packet and packet[TCP].flags == "A" else 0,
                "stcpb": packet[TCP].seq if TCP in packet else 0,
                "dtcpb": packet[TCP].ack if TCP in packet else 0,
                "Stime": first_packet_time,
                "Ltime": last_packet_time,
            }

            # Calculate jitter and inter-packet interval
            if src_ip in prev_src_time:
                row["Sintpkt"] = packet_time - prev_src_time[src_ip]
                row["Sjit"] = abs(row["Sintpkt"] - prev_src_time[src_ip])
            if dst_ip in prev_dst_time:
                row["Dintpkt"] = packet_time - prev_dst_time[dst_ip]
                row["Djit"] = abs(row["Dintpkt"] - prev_dst_time[dst_ip])

            prev_src_time[src_ip] = packet_time
            prev_dst_time[dst_ip] = packet_time

            # Calculate TCP RTT
            if TCP in packet:
                if packet[TCP].flags == "S":
                    prev_src_seq[src_ip] = packet_time
                elif packet[TCP].flags == "A" and src_ip in prev_src_seq:
                    row["tcprtt"] = packet_time - prev_src_seq[src_ip]

            df = df.append(row, ignore_index=True)

    # Calculate aggregate and interaction features
    df["duration"] = df["Ltime"] - df["Stime"]
    df["byte_ratio"] = df["sbytes"] / (df["dbytes"] + 1)
    df["pkt_ratio"] = df["Spkts"] / (df["Dpkts"] + 1)
    df["load_ratio"] = df["Sload"] / (df["Dload"] + 1)
    df["jit_ratio"] = df["Sjit"] / (df["Djit"] + 1)
    df["inter_pkt_ratio"] = df["Sintpkt"] / (df["Dintpkt"] + 1)
    df["tcp_setup_ratio"] = df["tcprtt"] / (df["synack"] + df["ackdat"] + 1)
    df["total_bytes"] = df["sbytes"] + df["dbytes"]
    df["total_pkts"] = df["Spkts"] + df["Dpkts"]
    df["total_load"] = df["Sload"] + df["Dload"]
    df["total_jitter"] = df["Sjit"] + df["Djit"]
    df["total_inter_pkt"] = df["Sintpkt"] + df["Dintpkt"]
    df["total_tcp_setup"] = df["tcprtt"] + df["synack"] + df["ackdat"]
    df["byte_pkt_interaction_src"] = df["sbytes"] * df["Spkts"]
    df["byte_pkt_interaction_dst"] = df["dbytes"] * df["Dpkts"]
    df["load_jit_interaction_src"] = df["Sload"] * df["Sjit"]
    df["load_jit_interaction_dst"] = df["Dload"] * df["Djit"]
    df["pkt_jit_interaction_src"] = df["Spkts"] * df["Sjit"]
    df["pkt_jit_interaction_dst"] = df["Dpkts"] * df["Djit"]
    df["mean_pkt_size"] = df["smeansz"] + df["dmeansz"]
    df["tcp_seq_diff"] = df["stcpb"] - df["dtcpb"]

    return df


# Capture packets (e.g., from a pcap file or live capture)
packets = sniff(count=100)  # Live capture

# Calculate features
df_features = calculate_features(packets)
print(df_features.head())
