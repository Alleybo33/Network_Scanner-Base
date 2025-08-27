#!/usr/bin/env python3
import argparse
import socket
import os
import sys
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1

#--------------Host Discovery--------------------

def scan_network(ip_range):
        #Create ARP request
        try:
                arp = ARP(pdst=ip_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp

                result = srp(packet, timeout=3, verbose=0)[0]

                clients = []
                for sent, received in result:
                        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

                return clients
        except Exception as e:
                print(f"[!] Error during network scan: {e}")
                return []


#---------------Port Scanning--------------------------

def scan_ports(ip, ports=[21, 22, 80, 443, 8080]):
        open_ports = []
        for port in ports:
                try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                                open_ports.append(port)
                        sock.close()
                except Exception as e:
                        print(f"[!] Error scanning port {port} on {ip}: {e}")
        return open_ports


#-------------Banner Grabbing------------------------

def grab_banner(ip, port):
        try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect((ip, port))
                banner = sock.recv(1024)
                try:
                        banner = banner.decode().strip()
                except UnicodeDecodeError:
                        banner = str(banner)
                sock.close()
                return banner
        except Exception:
                return None


#------------------OS Detection-------------------------

def detect_os(ip):
        try:
                pkt = IP(dst=ip)/ICMP()
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp:
                        ttl = resp.ttl
                        if ttl <= 64:
                                return "Linux/Unix"
                        elif ttl <= 128:
                                return "Windows"
                return "Unknown"
        except Exception:
                return "Unknown"

# ------------------- Main ------------------------------
def main():
        #Chek for root privileges
        if os.geteuid() != 0:
                print("[!] Please run this script as root.")
        parser = argparse.ArgumentParser(description="Python Network Scanner")
        parser.add_argument("-t", "--target", required=True, help="Target IP range (e.g., 192.168.1.0/24)")
        parser.add_argument("-p", "--ports", help="Comma-separated ports (default: 21,22,80,443,8080)", default="21,22,80,443,8080")
        args = parser.parse_args()

        ip_range = args.target
        ports = [int(p) for p in args.ports.split(",")]

        print("[*] Scanning network for active hosts......")
        devices = scan_network(ip_range)

        if not devices:
                print("[-] No active hosts found.")
                return

        print("\nActive devices found:")
        print("-----------------------------------")
        for device in devices:
                print(f"IP: {device['ip']} | MAC: {device['mac']}")
        print("-----------------------------------\n")

        for device in devices: 
                ip = device['ip']
                print(f"[+] Scanning {ip}....")
                os_guess = detect_os(ip)
                open_ports = scan_ports(ip, ports)

                print(f"    OS  Guess: {os_guess}")
                print(f"    Open Ports: {open_ports}")
        for port in open_ports:
                banner = grab_banner(ip, port)
                if banner:
                        print(f"       Port {port} Banner: {banner}")
        print("-------------------------------------------")

if __name__ == "__main__":
	main()
''