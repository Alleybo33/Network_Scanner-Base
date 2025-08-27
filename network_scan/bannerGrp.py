def grab_banner(ip, port):
	try:
		sock = socket.socket()
		sock.settimeout(1)
		sock.connect((ip, port))
		banner = sock.recv(1024).decode().strip()
		sock.close()
		return banner
	except:
		return None

for device in devices:
    open_ports = scan_ports(device['ip'])
    print(f"IP: {device['ip']} | Open Ports: {open_ports}")
    for port in open_ports:
        banner = grab_banner(device['ip'], port)
        if banner:
            print(f"  Port {port} Banner: {banner}")