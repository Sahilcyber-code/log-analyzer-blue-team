# 🔐 Log Analyzer – Mini SIEM Simulation

A Python-based mini SIEM (Security Information and Event Management) tool that analyzes SSH and Apache logs to detect suspicious activities such as brute-force attacks and web scanning behavior.

---

## 🚀 Project Overview

This tool parses real-world log formats and applies basic threat detection logic.

It demonstrates:
- Log parsing
- Regex pattern detection
- Time-window brute force detection
- Basic alerting system
- IP-based attack analysis

---

## 🛠 Features

### 🔐 SSH Log Analysis
- Detects failed login attempts
- Detects brute-force attempts (≥ 5 failures within 60 seconds)
- Detects suspicious successful login after repeated failures
- Displays summary of failed/successful attempts per IP

### 🌐 Apache Log Analysis
- Detects suspicious path scanning (e.g., `/wp-login.php`, `/.env`, `/phpmyadmin`)
- Detects high 4xx error activity
- Displays request statistics per IP

---

## 📂 Project Structure

log-analyzer-blue-team/
│
├── analyzer.py
├── README.md
│
└── samples/
├── ssh_auth.log
└── apache_access.log


---

## ▶️ How To Run

### SSH Log Analysis
```bash
python analyzer.py ssh samples/ssh_auth.log
Apache Log Analysis
python analyzer.py apache samples/apache_access.log
📌 Sample Output
[ALERT] Possible brute force from 192.168.1.5 (>= 5 failures in 60s)
[ALERT] Suspicious success after many failures from 192.168.1.5 (fails=5)

--- SSH Summary ---
192.168.1.5   failed=5 success=1

Detection Logic
Brute Force Detection
Stores failed login timestamps per IP
Maintains a rolling 60-second window
If ≥ 5 failures occur within that window → triggers alert
Web Scanning Detection
Checks requests against common attacker paths:
/.env
/wp-login.php
/xmlrpc.php
/phpmyadmin
/wp-admin
Tracks high 4xx responses per IP

💻 Technologies Used

Python 3
Regular Expressions (regex)
datetime module
collections (defaultdict, deque)
CLI-based execution