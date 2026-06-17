# Task 1: Basic Network Sniffer

A real-time network packet analyzer built as part of the **CodeAlpha Cyber Security Internship**.

## Overview

This tool captures every packet traveling through your network and displays it live on a dashboard without any page refresh. It gives visibility into what's actually happening on your network at any given moment.

## Features

- Live packet capture using Scapy
- Displays source IP, destination IP, protocol type (TCP, UDP, ICMP, ARP), port info, and packet size
- Real-time dashboard with no page refresh using Flask-SocketIO
- Protocol distribution chart
- Packets per second live graph

## Tech Stack

- Python
- Scapy (packet capturing)
- Flask (backend server)
- Flask-SocketIO (real-time communication)
- Chart.js (live visualizations)

## How to Run

1. Install dependencies:
 pip install scapy flask flask-socketio
2. Run the app with admin/root privileges:
 python app.py
3. Open your browser and go to:
 http://localhost:5000

## What I Learned

- How data travels across networks at the packet level
- What protocols like TCP, UDP, ICMP, and ARP mean in practice
- Why network monitoring is a critical part of cybersecurity
- How to build real-time web applications using Flask-SocketIO
