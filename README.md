# 🔍 Python Network Scanner

[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-success)]()

A Python-based **network scanner** for penetration testers and network administrators.  
Features include **host discovery**, **port scanning**, **banner grabbing**, **OS detection**,  
**MAC vendor identification**, and **Metasploitable OS detection**.

---

## ✅ Features
✔ Discover active hosts in a network (ARP Scan)  
✔ Identify open ports (default or custom)  
✔ Grab service banners from open ports  
✔ Detect OS (Linux/Unix/Windows) via ICMP TTL  
✔ Show MAC address vendor (VMware, VirtualBox, etc.)  
✔ Detect **Metasploitable OS signatures**  

---

## ⚠ Requirements
- **Python 3.x**
- Root privileges (for ARP scan)
- Dependencies:
  - `scapy`
  - `python-nmap` (optional for advanced detection)

---

## ✅ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Alleybo33/network-scanner.git
cd network-scanner


