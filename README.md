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
  
##Login Page
This is the secure gateway for authorized personnel to access the monitoring data.

<img width="1259" height="693" alt="image" src="https://github.com/user-attachments/assets/499b1a65-2cc7-40cc-9d8c-fcb318f911e2" />

##Security Dashboard
The central interface for viewing system-wide logs, alerts, and security trends.
<img width="1403" height="526" alt="image" src="https://github.com/user-attachments/assets/6c7f9950-baa8-4dee-aa5a-8900c7915489" />
<img width="1401" height="418" alt="image" src="https://github.com/user-attachments/assets/27612e09-8fa7-4669-a285-9dee852e82df" />
