# Simple-NIDS

Simple Network Intrusion Detection System (signature based).  
Written in Python with Scapy.

# Install

Install [python 2.7](https://www.python.org/downloads/) and [scapy](http://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x).

Clone this project :

> git clone https://github.com/pthevenet/Simple-NIDS.git

# Run (Linux)

> cd Simple-NIDS
> and
> sudo python -B src/Simple-NIDS.py rules/exampleRules.txt
> or
> sudo python -B src/Simple-NIDS.py \<rule file\>

# Stop (Linux)

> ctrl + Z

# Run (Windows)

cd <path/to/Simple-NIDS.py

> python Simple-NIDS.py ..\rules\exampleRules.txt

# Stop (windows)

> ctrl + C
