# 🔐 Python-Based Intrusion Detection System (IDS) Using Scapy

A lightweight, Python-powered Intrusion Detection System (IDS) that captures network packets, applies basic detection rules, and logs alerts in real-time. Includes both a CLI version and a GUI (Tkinter) version for live monitoring.

## ✨ Features

- 🔎 Real-time packet sniffing using Scapy
- 🧠 Simple rule engine for detecting:
  - SSH brute-force attempts
  - SQL injection attempts via HTTP
- 📜 Logs alerts to `.txt` and `.csv` files
- 💻 GUI version with:
  - Start/Stop buttons
  - Live alert feed
  - Scrollable log window

## 🛠️ Requirements

- Python 3.x
- [Scapy](https://scapy.net/) (`pip install scapy`)
- Tkinter (included with Python by default on most systems)

## 📁 Files

| File               | Description                            |
|--------------------|----------------------------------------|
| `GUI_IDS.py`       | Tkinter GUI-based IDS interface        |
| `ids_output.txt`   | Plain text alert log                   |


