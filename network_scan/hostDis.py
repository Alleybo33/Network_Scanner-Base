from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
	#Create ARP request
	arp = ARP(pdst=ip_range)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether / arp

	result = srp(packet, timeout=3, verbose=0)[0]

	clients = []
	for sent, received in result:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc})

	return clients


#Usage:
ip_range = input("Enter ip range to scan(192.168.1.0/24): ")
devices = scan_network(ip_range)

print("Active devices in the network:")
for deivce in devices:.
	print(f"IP: {device['ip']}, MAC: {device['mac']}")
