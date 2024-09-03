#!/bin/bash

# Define the destination IP
DEST_IP="192.168.2.20"

# Path to PacketSender executable
PACKET_SENDER_PATH="packetsender"

# Define the duration for which to send packets (in seconds)
DURATION=120  # 2 minutes

# Define the source port to use
SOURCE_PORT=12345  # Replace this with your desired source port

# Get the start time
START_TIME=$(date +%s)

# Loop to send packets for the specified duration
while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    # Randomly choose between "Attack" and "Normal" payload
    PAYLOAD=$((RANDOM % 2)) # Generates either 0 or 1
    if [ $PAYLOAD -eq 0 ]; then
        ASCII_PAYLOAD="Attack"
    else
        ASCII_PAYLOAD="Normal"
    fi

    # Randomly select a port between 5000 and 5050
    DEST_PORT=$((5000 + RANDOM % 51))

    # Send the packet using PacketSender's CLI with --ASCII flag and bind to source port
    "$PACKET_SENDER_PATH" --udp "$DEST_IP" "$DEST_PORT" --ASCII "$ASCII_PAYLOAD" --bind "$SOURCE_PORT"

    # Wait before sending the next packet
    sleep 0.5 # Adjust delay as needed
done

# Output that the duration has elapsed
echo "Packets sent for $((DURATION / 60)) minutes successfully."
