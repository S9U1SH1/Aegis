# Aegis – Windows Security Monitoring Agent

An open-source Windows security monitoring system that provides real-time
visibility into endpoint security events through a centralized web-based dashboard.

## Overview

Cyber threats targeting Windows systems continue to increase in frequency
and sophistication. Many existing security monitoring solutions are either
enterprise-focused, expensive, or overly complex for small and medium-sized
environments.

This project introduces a lightweight, open-source Windows security monitoring
agent that collects critical security events and securely transmits them to a
centralized web-based dashboard for analysis and visualization.

## Objectives

- Monitor Windows Firewall and Antivirus status
- Detect suspicious processes and injected binaries
- Track failed login attempts
- Monitor critical Windows Registry modifications
- Identify outbound network connections and open ports
- Provide a centralized dashboard for visualization and reporting

## System Architecture

The system consists of three main components:

1. **Windows Security Agent**
   - Runs in the background on Windows endpoints
   - Collects security-related data at optimized intervals

2. **Centralized Server**
   - Receives encrypted data from agents
   - Stores events in a relational database

3. **Web-Based Dashboard**
   - Provides real-time visibility
   - Displays alerts, logs, and reports
  
## Login Page
This is the secure gateway for authorized personnel to access the monitoring data.

<img width="1259" height="693" alt="image" src="https://github.com/user-attachments/assets/499b1a65-2cc7-40cc-9d8c-fcb318f911e2" />

## Security Dashboard
The central interface for viewing system-wide logs, alerts, and security trends.
<img width="1403" height="526" alt="image" src="https://github.com/user-attachments/assets/6c7f9950-baa8-4dee-aa5a-8900c7915489" />
<img width="1401" height="418" alt="image" src="https://github.com/user-attachments/assets/27612e09-8fa7-4669-a285-9dee852e82df" />

## 🚀 Features

Aegis provides a robust suite of monitoring tools designed to offer full visibility into Windows endpoint security.

### 🛡️ Core Security Monitoring
* **Antivirus Health Monitoring:** Verifies if antivirus software is installed, checks if real-time protection is active, and ensures malware definition databases are up to date.
* **Firewall Status Verification:** Periodically monitors the state of Windows Firewall across Domain, Private, and Public profiles to detect misconfigurations.
* **Registry Integrity Monitoring:** Inspects critical registry keys (Secure Boot, UAC, LSASS) to detect unauthorized changes indicating malware persistence or privilege escalation.
* **Failed Login Tracking:** Analyzes Windows Security Event Logs (Event ID 4625) to detect and report failed local or remote authentication attempts.
* **Binary Trust Verification:** Evaluates the digital signatures of running executables using Microsoft’s Sigcheck to identify untrusted or suspicious binaries.
* **Suspicious Process Detection:** Analyzes process creation events and parent-child relationships (e.g., `explorer.exe` spawning `cmd.exe`) to flag potential exploits.

### 🌐 Network & Process Oversight
* **Outbound Connection Tracking:** Monitors active TCP and UDP connections to identify suspicious external communication patterns.
* **Open Ports Scanning:** Identifies active network services and listening ports to flag unauthorized service exposure.

### 📊 Management & Security Infrastructure
* **Web-Based Dashboard:** A central GUI for administrators to visualize aggregated data, inspect real-time logs, and manage alerts.
* **Secure Data Transmission:** All logs are transmitted to the server via encrypted HTTPS/TLS protocols to ensure confidentiality and integrity.
* **Role-Based Access Control:** Implements user authentication to differentiate between regular users and administrators.
* **Automated Setup & Persistence:** Includes a dedicated setup module that configures the environment and schedules the agent to run automatically with high privileges.
* **Customizable Security Reports:** Allows for the generation of filtered reports based on user, time frame, and security metrics.
