# PROBE – Network Forensics & Intrusion Prevention System

![PROBE Banner](https://img.shields.io/badge/Security-Network%20Forensics-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Built%20With-Python-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

## Overview

**PROBE** is an **agentless network monitoring and forensics solution** designed to detect, analyze, and mitigate malicious network activity in real time.

The tool focuses on:
- Detecting **IP spoofing**
- Identifying **MAC spoofing**
- Monitoring **packet anomalies**
- Tracing hidden/internal devices behind public IPs
- Terminating malicious requests automatically
- Providing integrated **IDS/IPS capabilities**

PROBE enables organizations to monitor suspicious traffic patterns without requiring endpoint agents, making deployment lightweight and scalable.

---

# Features

## 🔍 Network Forensics
- Deep packet inspection
- Traffic pattern analysis
- Session tracking
- Suspicious behavior correlation

## 🛡️ IDS/IPS Engine
- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- Real-time malicious packet blocking
- Threat signature detection

## 🧠 Spoofing Detection
- IP spoofing detection
- MAC spoofing identification
- ARP anomaly monitoring
- Rogue device discovery

## 🌐 Connection Tracing
- Maps hidden/internal hosts behind NAT/Public IPs
- Tracks suspicious outbound communications
- Detects unauthorized external connections

## ⚡ Automated Threat Response
- Terminates malicious requests
- Auto-block suspicious endpoints
- Real-time alert generation

## 📊 Monitoring Dashboard
- Live traffic monitoring
- Packet statistics
- Threat logs
- Connection analytics

---

# Architecture

```text
                +-------------------+
                | Network Traffic   |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Packet Sniffer    |
                +---------+---------+
                          |
          +---------------+---------------+
          |                               |
          v                               v
+-------------------+        +----------------------+
| Spoof Detection   |        | Anomaly Detection    |
| IP/MAC Analysis   |        | IDS/IPS Engine       |
+---------+---------+        +----------+-----------+
          |                               |
          +---------------+---------------+
                          |
                          v
                +-------------------+
                | Threat Response   |
                | Block / Terminate |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Logs & Dashboard  |
                +-------------------+
```

---

# Tech Stack

- Python
- Scapy
- Socket Programming
- Packet Sniffing APIs
- IDS/IPS Detection Modules
- Network Traffic Analysis Tools

---

# Installation

```bash
# Clone repository
git clone https://github.com/yourusername/probe-network-forensics.git

# Navigate into project
cd probe-network-forensics

# Install dependencies
pip install -r requirements.txt
```

---

# Usage

```bash
python main.py
```

### Example Functionalities
- Start live packet capture
- Monitor spoofed devices
- Detect abnormal packet flow
- Auto-block malicious traffic

---

# Sample Detection Output

```bash
[ALERT] IP Spoofing Detected
Source IP: 192.168.1.20
MAC Mismatch Found

[WARNING] Suspicious Packet Burst
Possible DoS Attempt Detected

[ACTION] Malicious Request Terminated
Blocked Endpoint: 45.xxx.xxx.xxx
```

---

# Project Objectives

- Improve network visibility
- Detect hidden malicious activities
- Prevent spoofing attacks
- Enable proactive threat mitigation
- Simplify enterprise network forensics

---

# Future Enhancements

- Machine Learning based anomaly detection
- Web-based monitoring dashboard
- SIEM integration
- Distributed sensor support
- Threat intelligence feeds
- Real-time alert notifications

---

# Security Use Cases

- Enterprise network monitoring
- SOC environments
- Threat hunting
- Incident response
- Internal traffic investigation
- Rogue device detection

---

# Contributing

Contributions are welcome.

```bash
# Fork the repository
# Create feature branch
git checkout -b feature-name

# Commit changes
git commit -m "Added new feature"

# Push changes
git push origin feature-name
```

---

# License

This project is licensed under the **Apache License, Version 2.0**.

See [LICENSE.txt](LICENSE.txt) for the full license text.

**Copyright 2026 ByteNinja**

---

# Author

**PROBE – Network Forensics & IDS/IPS Solution**  
Developed for cybersecurity and network defense research by Byteninja.
