# Aegis – Windows Security Monitoring Agent

**Live Dashboard:** [https://aegis-security-solutions.com/](https://aegis-security-solutions.com/)

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

## Aegis Agent Dashboard
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

## 📦 Installation & Setup

Aegis is designed for a streamlined deployment. The process involves downloading the core package, running the setup with administrative rights, and initializing your secure credentials.

### 1. Prerequisites
* **Operating System:** Microsoft Windows 10 or above.
* **Privileges:** Administrator rights are required to run the setup and to allow the agent to monitor protected system registries and logs.
* **Dependencies:** The setup script automatically manages the deployment of `Sigcheck64.exe` for binary verification.

### 2. Installation Steps
1. **Download the Package:** Click the "Download Windows Installer" button on the dashboard. This will download a package containing the `setup.exe` and necessary project files.
2. **Run Setup as Administrator:** Open the downloaded folder, right-click `setup.exe`, and select **"Run as administrator"**. This is essential for the installer to create the required system directories.
3. **Automated Environment Preparation:** The installer will automatically:
    * Create the permanent application directory at `C:\ProgramData\Aegis`.
    * Initialize configuration files, event log checkpoints, and cryptographic keys.
    * Relocate the agent executable and Sigcheck to the trusted application path.
4. **Configure Your Credentials:** When prompted by the setup window, enter your **Email** and **Password**. These credentials are encrypted and stored locally to securely authenticate your device with the central server.

### 3. Background Persistence
Once the setup reports "Setup complete," no further manual action is required:
* **Task Scheduler:** The installer creates a Windows Scheduled Task to launch the agent automatically every time a user logs on.
* **Highest Privileges:** The agent is configured to run with the highest privileges to ensure it can monitor all security subsystems without interruption.
* **Multi-threaded Execution:** The agent operates silently in the background, using separate threads to monitor different security components (Antivirus, Firewall, Registry, etc.) simultaneously.
