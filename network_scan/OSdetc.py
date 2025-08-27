from scapy.all import IP, ICMP, sr1

def detect_os(ip):
	pkt = IP(dst=ip)/ICMP()
	resp = sr1(pkt, timeout=1, verbose=o)
	if resp:
		ttl = resp.ttl
		if ttl <= 64:
			return "Linux/Unix"
		elif ttl <= 128:
			return "Windows"
	return "Unknown"

for device in devices:
	os_guess = detect_os(device['ip'])
	print(f"IP: {device['ip']} | OS: {os_guess}")

