import socket

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
		except:
			pass
	return open_ports

for device in devices:
	open_ports = scan_ports(deivices['ip'])
	print(f"IP: {device['ip']} | open Ports: {open_ports}")
