# µIDS

A simple Python-based network signature intrusion detection system.

## Required Packages

- `scapy`
- `netifaces`

## Installation and Testing

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/dreizehnutters/-IDS.git
cd '-IDS'
pipx install -r requirements.txt
sudo python3 main.py <INTERFACE> default.rules
```

Replace `<INTERFACE>` with your network interface, e.g., `wlp4s0`.

## Rules

Rules are defined in default.rules and eval.rules.

### Rule Structure

```python
PROTO [!]IP|any:[!]PORT(RANGE)|any <>|-> [!]IP|any:[!]PORT(RANGE)|any *PAYLOAD
```

### Example

```python
ICMP 192.168.178.22:any -> 1.1.1.1:[500-510] * # -IDS
```

### Explanation

- `PROTO`: The protocol (e.g., ICMP, TCP, UDP).
- `[!]IP|any`: Source IP address (use ! for negation, any for any IP).
- `[!]PORT(RANGE)|any`: Source port (use ! for negation, specify range with [min-max], any for any port).
- `<>|->`: Direction of traffic (<> for bidirectional, -> for unidirectional).
- `[!]IP|any`: Destination IP address.
- `[!]PORT(RANGE)|any`: Destination port.
- `*PAYLOAD`: Payload pattern.
- Comments in rules are indicated with #.

### Guide

To run the provided network packet sniffer system effectively, follow this detailed guide step-by-step. Ensure you meet all the prerequisites and carefully execute each step as described.

### Prerequisites

1. **Operating System**: Linux or macOS is recommended, as the code uses Scapy, which has better support on Unix-like systems.
2. **Python**: Ensure Python 3 is installed on your system. You can check this by running `python3 --version`.
3. **Dependencies**: Install required Python packages. The main packages needed are Scapy and netifaces.

### Steps to Run the System

#### 1. Set Up Your Environment

1. **Install Python Dependencies**:

   - Install Scapy and netifaces using pip:
     ```bash
     pip3 install scapy netifaces
     ```

2. **Create a Directory for Logs**:
   - Create a directory where logs and pcap files will be stored:
     ```bash
     mkdir logs
     ```

#### 2. Prepare the Code

1. **Ensure the Code is Available**:
   - Save the provided code snippets into appropriately named Python files in a single directory.
   - For instance:
     - `signature.py` for the code defining the `Signature` class and related functions.
     - `sniffer.py` for the code defining the `Sniffer` class.
     - `main.py` for the main execution script (the first script you provided).

#### 3. Run the Code

1. **Execute the Main Script**:
   - Navigate to the directory where your scripts are saved:
     ```bash
     cd /path/to/your/scripts
     ```
   - Run the main script. If `main.py` is the main script, execute:
     ```bash
     sudo python3 main.py <network_interface>
     ```
     - Replace `<network_interface>` with your actual network interface name, e.g., `eth0`, `en0`, or similar.
     - Note: You might need `sudo` to grant the necessary permissions to capture network packets.

#### 4. Interact with the Program

1. **Main Menu**:

   - After running the script, you should see a menu with options to send positives, send negatives, send manually created packages, or exit.
   - Enter the appropriate number corresponding to your choice.

2. **Send Positives**:

   - Choose option 1 to send positive packets based on the defined rules.

3. **Send Negatives**:

   - Choose option 2 to send negative packets.
   - You will be prompted to enter the number of negative packets to send. Press Enter to use the default (10), or specify a different number.

4. **Send Manually Created Package**:

   - Choose option 3 to send a custom packet.
   - Enter the details in the format: `[protocol] [source port] [destination IP] [destination port]`.

5. **Exit**:
   - Choose option 4 to exit the program.

### Tips and Troubleshooting

- **Permissions**:

  - Capturing network packets usually requires elevated permissions. If you encounter permission errors, ensure you are running the script with `sudo`.

- **Network Interface**:

  - Ensure you are using the correct network interface. You can list available interfaces using:
    ```bash
    ifconfig -a
    ```
  - Choose an active network interface to capture live traffic.

- **Log Files**:

  - Check the `logs` directory for log files and pcap files generated during the execution. The logs can help you understand what packets were captured and sent.

- **Error Handling**:

  - If you encounter errors related to missing attributes or modules, double-check your code to ensure all snippets are correctly saved and imported.

- **Dependencies**:
  - Ensure all dependencies (`scapy`, `netifaces`, `multiprocessing`) are properly installed and compatible with your Python version.

By following these steps meticulously, you can run the network packet sniffer system successfully without making any assumptions or overlooking critical details.
