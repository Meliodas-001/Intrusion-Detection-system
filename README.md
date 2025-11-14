# 🛡️ Snort-NIDS-Virtual-Detection-Lab

This project details the creation of a hands-on virtual lab designed to demonstrate the setup, configuration, and operation of a **Network Intrusion Detection System (NIDS)** using **Snort**.

The lab simulates a common network reconnaissance scenario (ICMP Ping Sweep) from an attacker machine (Kali Linux). It successfully detects the activity in real-time on a sensor (Ubuntu Server running Snort).

---

## 📖 Table of Contents
* [Objective](#-objective)
* [Skills Demonstrated](#-skills-demonstrated)
* [Tools & Technologies](#-tools--technologies-used)
* [Network Architecture](#-network-architecture)
* [Lab Walkthrough](#-lab-walkthrough)
    * [1. Environment Setup](#1-environment-setup)
    * [2. Snort Configuration](#2-snort-configuration)
    * [3. Attack Simulation](#3-attack-simulation)
    * [4. Detection & Analysis](#4-detection--analysis)
* [Example Snort Rule](#-example-snort-rule)
* [Repository Structure](#-repository-structure)
* [Conclusion & Key Takeaways](#-conclusion--key-takeaways)
* [Author](#-author)

---

## 🔍 Objective

The primary objective of this project was to build and configure a virtualized detection lab from scratch. The goal was to inspect live network traffic, generate telemetry, and analyze how an IDS like **Snort** identifies and flags malicious or suspicious behavior.

This hands-on approach provides a deep, practical understanding of:
* Real-time packet inspection and analysis.
* Reconnaissance patterns used by attackers.
* The foundational role of an IDS in a modern defensive security stack.

---

## 🧠 Skills Demonstrated

* **IDS Deployment:** Deployed and configured Snort 3 on a Linux server (Ubuntu).
* **Network Analysis:** Analyzed live network traffic to identify attack patterns.
* **Rule Management:** Tuned and applied Snort rules to detect specific ICMP traffic.
* **Attack Simulation:** Executed reconnaissance techniques using Kali Linux.
* **Virtualization:** Built and managed a multi-VM virtual lab environment using VirtualBox.
* **SOC Workflow:** Replicated the core "detection-alerting-analysis" workflow used in a Security Operations Center (SOC).

---

## 🛠️ Tools & Technologies Used

* **NIDS:** **Snort 3**
* **Sensor Host:** **Ubuntu Server 22.04**
* **Attacker VM:** **Kali Linux**
* **Virtualization:** **Oracle VirtualBox**
* **Network Protocols:** **ICMP**, **TCP/IP**

---

## 📡 Network Architecture

The lab operates on a simple, isolated virtual network. The Attacker and Sensor VMs are on the same subnet, allowing the Snort sensor (in promiscuous mode) to monitor all traffic.

       ┌─────────────────┐
       │   Kali Linux    │
       │   (Attacker)    │
       └───────┬────────┘
               │ ICMP / Scan Traffic
       ┌───────▼────────┐
       │   VirtualBox    │
       │   Virtual LAN   │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │  Ubuntu Server  │
       │  Snort IDS Host │
       └───────┬────────┘
               │ Logs / Alerts
       ┌───────▼────────┐
       │   (Optional)    │
       │     SIEM        │
       └─────────────────┘


   ---

## 📝 Lab Walkthrough

### 1. Environment Setup
1.  **VirtualBox:** Two VMs were created: one for the Ubuntu Server and one for Kali Linux.
2.  **Networking:** Both VMs were configured to use the same VirtualBox **Internal Network** (e.g., `vboxnet0`) to ensure they could communicate and that all traffic would pass within a monitorable segment.

### 2. Snort Configuration
1.  **Installation:** Snort 3 was installed on the Ubuntu Server using `apt`.
    ```bash
    sudo apt update
    sudo apt install snort -y
    ```
2.  **Configuration:** The `$HOME_NET` variable in `/etc/snort/snort.conf` was set to the server's IP address to define the "protected" network.
    ```ini
    # Set up the network(s) you are protecting
    ipvar HOME_NET [192.168.0.194]
    ```
3.  **Run Snort:** Snort was launched in console mode to display alerts in real-time.
    * `-A console`: Print alerts to the console.
    * `-q`: Quiet mode (suppress non-alert output).
    * `-c ...`: Specify the configuration file.
    * `-i ...`: Specify the interface to listen on (e.g., `enp0s3`).

    ```bash
    sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
    ```

### 3. Attack Simulation
On the **Kali Linux** attacker VM (`192.168.0.116`), a standard `ping` command was used to simulate a **ping sweep**—a basic reconnaissance technique to discover if a host is online.

`ping 192.168.0.194`

This continuously sends **ICMP Echo Requests** to the Ubuntu server.

![ICMP Ping flood from Kali Linux](images/screenshot254.png)

### 4. Detection & Analysis
Simultaneously, on the **Ubuntu Server** (`192.168.0.194`), Snort detected and logged this activity in real-time.

> **Explanation of Alerts:**
> The Snort console instantly displayed alerts for each ICMP packet. It correctly identified the incoming "ICMP Ping" (Type 8) from the attacker and the outgoing "ICMP Echo Reply" (Type 0) from the server. Snort rules flagged this as a "Classification: Information Leak" because the reply confirms to the attacker that the host is alive.

![Snort detecting and logging ICMP alerts](images/screenshot254.png)

---

## 📘 Example Snort Rule

While this lab used the built-in rules, a custom rule to detect a simple ping could be written like this:

``c
// This rule alerts on any ICMP Echo Request (itype:8)
// coming from any IP address to the protected network ($HOME_NET).

alert icmp any any -> $HOME_NET any ( \
    msg:"ICMP Ping Detected (Custom Rule)"; \
    itype:8; \
    classtype:information-leak; \
    sid:1000001; \
    rev:1; \
)

├── /images
│   ├── screenshot250.png   # Attacker VM (Kali)
│   └── screenshot254.png   # Sensor VM (Snort)
│
├── /configs
│   ├── snort.conf          # Snort configuration file
│   └── custom.rules        # Custom rule file
│
└── README.md               # This file




---

# ✅ Final Step  
Place your screenshots inside:
<img width="3840" height="2160" alt="Screenshot (254)" src="https://github.com/user-attachments/assets/3d3322fc-7bf7-42d2-b027-0a624fe4249c" />

