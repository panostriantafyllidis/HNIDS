#!/bin/bash

# Define the destination IP
DEST_IP="192.168.2.20"

# Path to PacketSender executable
PACKET_SENDER_PATH="packetsender"

# Define the limit for the number of packets to send
LIMIT=3

# Loop to send packets up to the specified limit
for i in $(seq 1 $LIMIT); do
    # Randomly choose between "Attack" and "Normal" payload
    PAYLOAD=$((RANDOM % 2)) # Generates either 0 or 1
    if [ $PAYLOAD -eq 0 ]; then
        ASCII_PAYLOAD="Attack"
    else
        ASCII_PAYLOAD="Normal"
    fi

    # Randomly select a port between 5000 and 5050
    DEST_PORT=$((5000 + RANDOM % 51))

    # Send the packet using PacketSender's CLI with --ASCII flag
    "$PACKET_SENDER_PATH" --udp "$DEST_IP" "$DEST_PORT" --ASCII "$ASCII_PAYLOAD"

    # Wait before sending the next packet
    sleep 0.5 # Adjust delay as needed
done

# Output the number of packets sent using the limit variable
echo "$LIMIT packets sent successfully."
