\# Intrusion Detection System (IDS) — Packet Sniffer



Author: Maitri Rohit \& Dhairya Pandya \& Brinda Patel

**Course:** B.Tech Computer science \& engineering Semester 5

Date: 30/10/2025



\## Project summary

This repository contains a lightweight IDS that captures packets and detects suspicious network behaviors (port scans, SYN floods, ARP spoofing) using Python.



\## Files

* `sniffer.py`- main sniffer \& alerting program
* `flow\_aggregator\_online.py`- flow aggregation and detection logic
* `test\_tcp\_clients.py`- test traffic generator
* `requirements.txt` - Python dependencies
* `README.md` - this file





\## Requirements

\- Python 3.9+

\- On Windows: Npcap (WinPcap-compatible)

\- On Linux: run with sudo for packet capture



Install dependencies:

```bash

pip install -r requirements.txt



